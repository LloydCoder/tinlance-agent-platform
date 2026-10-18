-- P8 recovery test: an expired lease must stay charged until reconciled.
begin;

insert into platform.tenants(tenant_id, name)
values ('00000000-0000-0000-0000-000000000091', 'p8-recovery-tenant');

insert into platform.agents(
    agent_id, tenant_id, agent_type, version, owner_subject_id,
    policy_profile, trust_level, environment
) values (
    '10000000-0000-0000-0000-000000000091',
    '00000000-0000-0000-0000-000000000091',
    'quota-recovery', '1.0.0', 'p8-recovery-owner', 'default', 'standard', 'test'
);

insert into platform.tasks(
    task_id, tenant_id, agent_id, agent_version, requester_subject_id, status, objective
) values (
    '20000000-0000-0000-0000-000000000091',
    '00000000-0000-0000-0000-000000000091',
    '10000000-0000-0000-0000-000000000091',
    '1.0.0', 'p8-recovery-owner', 'queued', 'quota reservation recovery'
);

insert into platform.runs(run_id, tenant_id, task_id, status)
values (
    '30000000-0000-0000-0000-000000000091',
    '00000000-0000-0000-0000-000000000091',
    '20000000-0000-0000-0000-000000000091', 'created'
);

insert into platform.tenant_budget_limits(
    tenant_id, max_concurrency, max_tool_calls, max_token_units, max_cost_units
) values (
    '00000000-0000-0000-0000-000000000091', 1, 10, 1000, 100
);

select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000091', true);

do $$
declare
    v_reservation_id uuid := '50000000-0000-0000-0000-000000000091';
    v_second_id uuid := '60000000-0000-0000-0000-000000000091';
    lease_expiry timestamptz;
    first_lease_expiry timestamptz;
    recovery_count integer;
begin
    perform platform.reserve_quota(
        v_reservation_id,
        '00000000-0000-0000-0000-000000000091',
        null,
        '10000000-0000-0000-0000-000000000091',
        '30000000-0000-0000-0000-000000000091',
        'read', 'resource:recovery', 'p8-recovery-idempotency-001', 1, 1, 10, 1.0
    );

    lease_expiry := platform.renew_quota_reservation(
        '00000000-0000-0000-0000-000000000091', v_reservation_id, 600
    );
    if lease_expiry <= clock_timestamp() then
        raise exception 'renewal did not extend the reservation lease';
    end if;
    first_lease_expiry := lease_expiry;

    lease_expiry := platform.renew_quota_reservation(
        '00000000-0000-0000-0000-000000000091', v_reservation_id, 900
    );
    if lease_expiry <= first_lease_expiry then
        raise exception 'second renewal did not advance the wall-clock lease';
    end if;
    if (
        select count(*) from platform.quota_ledger
        where tenant_id = '00000000-0000-0000-0000-000000000091'
          and reservation_id = v_reservation_id
          and event_type = 'lease_renewed'
    ) <> 2 then
        raise exception 'lease renewals were not individually audited';
    end if;

    update platform.quota_reservations
       set lease_expires_at = now() - interval '1 second'
     where tenant_id = '00000000-0000-0000-0000-000000000091'
       and quota_reservations.reservation_id = v_reservation_id;

    begin
        perform platform.release_quota(
            '00000000-0000-0000-0000-000000000091',
            v_reservation_id,
            'cancelled-before-side-effect',
            '{}'::jsonb
        );
        raise exception 'expired reservation was released before reconciliation';
    exception when sqlstate '55000' then
        null;
    end;

    recovery_count := platform.request_expired_quota_reconciliation(
        '00000000-0000-0000-0000-000000000091', 10
    );
    if recovery_count <> 1 then
        raise exception 'expected one expired reservation to require reconciliation';
    end if;

    if not exists (
        select 1 from platform.quota_reservations
        where tenant_id = '00000000-0000-0000-0000-000000000091'
          and quota_reservations.reservation_id = v_reservation_id
          and state = 'reserved'
          and recovery_attempts = 1
          and recovery_requested_at is not null
    ) then
        raise exception 'expired reservation was silently refunded or not marked';
    end if;

    if not exists (
        select 1 from platform.quota_ledger
        where tenant_id = '00000000-0000-0000-0000-000000000091'
          and quota_ledger.reservation_id = v_reservation_id
          and event_type = 'recovery_requested'
    ) then
        raise exception 'recovery request is missing its audit ledger fact';
    end if;

    recovery_count := platform.request_expired_quota_reconciliation(
        '00000000-0000-0000-0000-000000000091', 10
    );
    if recovery_count <> 0 then
        raise exception 'recovery request was not idempotent';
    end if;

    begin
        perform platform.renew_quota_reservation(
            '00000000-0000-0000-0000-000000000091', v_reservation_id, 600
        );
        raise exception 'expired reservation was renewed without reconciliation';
    exception when object_not_in_prerequisite_state then
        null;
    end;

    begin
        perform platform.reserve_quota(
            '60000000-0000-0000-0000-000000000091',
            '00000000-0000-0000-0000-000000000091',
            null,
            '10000000-0000-0000-0000-000000000091',
            '30000000-0000-0000-0000-000000000091',
            'read', 'resource:another', 'p8-recovery-idempotency-002', 1, 1, 10, 1.0
        );
    exception when sqlstate 'P0001' then
        -- The quota denial is expected; the exception block isolates it from
        -- the assertion below so a successful reservation cannot be swallowed.
        null;
    end;
    if exists (
        select 1 from platform.quota_reservations
        where tenant_id = '00000000-0000-0000-0000-000000000091'
          and idempotency_key = 'p8-recovery-idempotency-002'
    ) then
        raise exception 'expired reservation stopped counting against concurrency';
    end if;

    begin
        perform platform.release_quota(
            '00000000-0000-0000-0000-000000000091',
            v_reservation_id,
            'lease-expired',
            '{"measurement_ref":"recovery:review"}'::jsonb
        );
        raise exception 'recovery-requested reservation was released' using errcode = 'P8R02';
    exception when sqlstate '55000' then
        null;
    end;

    if platform.settle_quota(
        '00000000-0000-0000-0000-000000000091',
        v_reservation_id, 1, 10, 1.0,
        '{"provider":"recovery-test","measurement_ref":"usage:recovered-091"}'::jsonb
    ) not in ('settled', 'overrun') then
        raise exception 'reconciliation could not settle measured usage';
    end if;

    perform platform.reserve_quota(
        v_second_id,
        '00000000-0000-0000-0000-000000000091',
        null,
        '10000000-0000-0000-0000-000000000091',
        '30000000-0000-0000-0000-000000000091',
        'read', 'resource:recovery-two', 'p8-recovery-idempotency-003', 1, 1, 10, 1.0
    );
    update platform.quota_reservations
       set lease_expires_at = now() - interval '1 second'
     where tenant_id = '00000000-0000-0000-0000-000000000091'
       and quota_reservations.reservation_id = v_second_id;
    if platform.request_expired_quota_reconciliation(
        '00000000-0000-0000-0000-000000000091', 10
    ) <> 1 then
        raise exception 'second expired reservation did not enter reconciliation';
    end if;

    begin
        perform platform.release_quota(
            '00000000-0000-0000-0000-000000000091',
            v_second_id,
            'cancelled-before-side-effect',
            '{"measurement_ref":"recovery:review-002","source_event_id":"recovery-review-002"}'::jsonb
        );
        raise exception 'recovery reservation was released without explicit no-side-effect confirmation';
    exception when object_not_in_prerequisite_state then
        null;
    end;

    if platform.release_quota(
        '00000000-0000-0000-0000-000000000091',
        v_second_id,
        'confirmed-no-side-effect',
        '{"measurement_ref":"recovery:review-002","source_event_id":"recovery-review-002"}'::jsonb
    ) is not true then
        raise exception 'explicit no-side-effect reconciliation did not release reservation';
    end if;
    if not exists (
        select 1 from platform.quota_reservations
        where tenant_id = '00000000-0000-0000-0000-000000000091'
          and reservation_id = v_second_id
          and state = 'released'
          and recovery_resolution = 'confirmed-no-side-effect'
          and recovery_evidence_ref = 'recovery:review-002'
          and recovery_resolved_at is not null
    ) then
        raise exception 'recovery resolution was not durably recorded';
    end if;
    if platform.release_quota(
        '00000000-0000-0000-0000-000000000091',
        v_second_id,
        'confirmed-no-side-effect',
        '{"measurement_ref":"recovery:review-002","source_event_id":"recovery-review-002"}'::jsonb
    ) is not false then
        raise exception 'reconciled release replay was not idempotent';
    end if;
end
$$;

rollback;
