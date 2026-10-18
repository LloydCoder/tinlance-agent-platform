-- P8 recovery hardening: expired leases are flagged for reconciliation, never
-- silently refunded. A crashed worker may have completed a consequential side effect.
alter table platform.quota_reservations
    add column if not exists lease_expires_at timestamptz not null default (clock_timestamp() + interval '15 minutes'),
    add column if not exists recovery_requested_at timestamptz,
    add column if not exists recovery_attempts integer not null default 0
        check (recovery_attempts >= 0),
    add column if not exists recovery_resolution text
        check (recovery_resolution is null or recovery_resolution = 'confirmed-no-side-effect'),
    add column if not exists recovery_evidence_ref text,
    add column if not exists recovery_resolved_at timestamptz;

create index if not exists idx_quota_reservations_expiry
    on platform.quota_reservations(tenant_id, lease_expires_at)
    where state = 'reserved' and recovery_requested_at is null;

alter table platform.quota_ledger
    drop constraint if exists quota_ledger_event_type_check;
alter table platform.quota_ledger
    add constraint quota_ledger_event_type_check
    check (event_type in (
        'reserved', 'settled', 'released', 'overrun', 'recovery_requested', 'lease_renewed'
    ));

alter table platform.quota_ledger
    drop constraint if exists quota_ledger_tenant_id_reservation_id_event_type_key;
create unique index if not exists quota_ledger_single_transition_event
    on platform.quota_ledger(tenant_id, reservation_id, event_type)
    where event_type <> 'lease_renewed';

create or replace function platform.renew_quota_reservation(
    p_tenant_id uuid,
    p_reservation_id uuid,
    p_lease_seconds integer default 900
) returns timestamptz
language plpgsql
security invoker
set search_path = pg_catalog, platform
as $$
declare
    reservation platform.quota_reservations%rowtype;
    new_expiry timestamptz;
begin
    if platform.current_tenant_id() is distinct from p_tenant_id then
        raise exception 'tenant scope mismatch' using errcode = '42501';
    end if;
    if p_lease_seconds is null or p_lease_seconds < 60 or p_lease_seconds > 3600 then
        raise exception 'lease duration must be between 60 and 3600 seconds' using errcode = '22023';
    end if;

    select * into reservation
      from platform.quota_reservations
     where tenant_id = p_tenant_id and reservation_id = p_reservation_id
     for update;
    if not found then
        raise exception 'reservation not found' using errcode = 'P0002';
    end if;
    if reservation.state <> 'reserved'
       or reservation.lease_expires_at <= clock_timestamp()
       or reservation.recovery_requested_at is not null then
        raise exception 'reservation is expired or requires reconciliation' using errcode = '55000';
    end if;

    new_expiry := clock_timestamp() + make_interval(secs => p_lease_seconds);
    update platform.quota_reservations
       set lease_expires_at = new_expiry
     where tenant_id = p_tenant_id and reservation_id = p_reservation_id;
    insert into platform.quota_ledger(
        ledger_id, tenant_id, organization_id, reservation_id, run_id, event_type,
        tool_calls, token_units, cost_units, idempotency_key, evidence
    ) values (
        gen_random_uuid(), reservation.tenant_id, reservation.organization_id,
        reservation.reservation_id, reservation.run_id, 'lease_renewed',
        0, 0, 0, reservation.idempotency_key,
        jsonb_build_object(
            'lease_expires_at',
            to_char(new_expiry at time zone 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
            'source_event_id', reservation.idempotency_key
        )
    );
    return new_expiry;
end;
$$;

-- Once recovery is requested, a reservation cannot be released/refunded.
-- Reconciliation must settle observed usage (including zero only with evidence).
create or replace function platform.reject_quota_release_after_recovery()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog, platform
as $$
begin
    if old.recovery_requested_at is not null and new.state = 'released' and not (
        new.recovery_resolution = 'confirmed-no-side-effect'
        and new.recovery_evidence_ref is not null
        and new.recovery_resolved_at is not null
    ) then
        raise exception 'reservation requires explicit no-side-effect reconciliation before release'
            using errcode = '55000';
    end if;
    return new;
end;
$$;

drop trigger if exists quota_reservation_recovery_no_release on platform.quota_reservations;
create trigger quota_reservation_recovery_no_release
before update of state on platform.quota_reservations
for each row execute function platform.reject_quota_release_after_recovery();

-- A lease expiry is a reconciliation signal, not a refund. The reservation
-- remains reserved and continues consuming its quota until settle/release is
-- resolved with evidence. SKIP LOCKED allows multiple tenant-scoped sweepers.
create or replace function platform.request_expired_quota_reconciliation(
    p_tenant_id uuid,
    p_limit integer default 100
) returns integer
language plpgsql
security invoker
set search_path = pg_catalog, platform
as $$
declare
    requested_count integer;
begin
    if platform.current_tenant_id() is distinct from p_tenant_id then
        raise exception 'tenant scope mismatch' using errcode = '42501';
    end if;
    if p_limit is null or p_limit < 1 or p_limit > 1000 then
        raise exception 'reconciliation batch limit must be between 1 and 1000' using errcode = '22023';
    end if;

    with expired as (
        select q.reservation_id
          from platform.quota_reservations q
         where q.tenant_id = p_tenant_id
           and q.state = 'reserved'
           and q.lease_expires_at <= clock_timestamp()
           and q.recovery_requested_at is null
         order by q.lease_expires_at, q.reservation_id
         limit p_limit
         for update skip locked
    ), marked as (
        update platform.quota_reservations q
           set recovery_requested_at = clock_timestamp(),
               recovery_attempts = q.recovery_attempts + 1
          from expired e
         where q.tenant_id = p_tenant_id
           and q.reservation_id = e.reservation_id
        returning q.*
    )
    insert into platform.quota_ledger(
        ledger_id, tenant_id, organization_id, reservation_id, run_id, event_type,
        tool_calls, token_units, cost_units, idempotency_key, evidence
    )
    select gen_random_uuid(), m.tenant_id, m.organization_id, m.reservation_id, m.run_id,
           'recovery_requested', 0, 0, 0, m.idempotency_key,
           jsonb_build_object(
               'cancellation_reason', 'lease-expired',
               'source_event_id', m.idempotency_key
           )
      from marked m;

    get diagnostics requested_count = row_count;
    return requested_count;
end;
$$;

revoke all on function platform.renew_quota_reservation(uuid, uuid, integer) from public;
revoke all on function platform.request_expired_quota_reconciliation(uuid, integer) from public;

-- Recovery-requested reservations can only be released when the Platform
-- reconciler explicitly attests that no consequential side effect occurred.
create or replace function platform.release_quota(
    p_tenant_id uuid,
    p_reservation_id uuid,
    p_reason text,
    p_evidence jsonb default '{}'::jsonb
) returns boolean
language plpgsql
security invoker
set search_path = pg_catalog, platform
as $$
declare
    reservation platform.quota_reservations%rowtype;
    prior_release platform.quota_ledger%rowtype;
    expected_evidence jsonb;
begin
    if platform.current_tenant_id() is distinct from p_tenant_id then
        raise exception 'tenant scope mismatch' using errcode = '42501';
    end if;
    if p_reason is null or p_reason !~ '^[a-z0-9][a-z0-9._:-]{0,127}$'
       or not platform.quota_evidence_is_safe(p_evidence) then
        raise exception 'release reason or evidence is invalid' using errcode = '22023';
    end if;
    perform 1 from platform.tenant_budget_limits
     where tenant_id = p_tenant_id for update;
    if not found then
        raise exception 'tenant budget limits are not configured' using errcode = 'P0002';
    end if;
    select * into reservation from platform.quota_reservations
     where tenant_id = p_tenant_id and reservation_id = p_reservation_id for update;
    if not found then
        raise exception 'reservation not found' using errcode = 'P0002';
    end if;
    if reservation.state = 'released' then
        select * into prior_release from platform.quota_ledger
         where tenant_id = p_tenant_id and reservation_id = p_reservation_id
           and event_type = 'released';
        expected_evidence := coalesce(p_evidence, '{}'::jsonb)
            || jsonb_build_object('cancellation_reason', p_reason);
        if found and prior_release.evidence = expected_evidence then
            return false;
        end if;
        raise exception 'conflicting duplicate release' using errcode = '23505';
    end if;
    if reservation.state <> 'reserved' then
        raise exception 'settled reservation cannot be released' using errcode = '55000';
    end if;
    if reservation.lease_expires_at <= clock_timestamp()
       and reservation.recovery_requested_at is null then
        raise exception 'expired reservation must enter reconciliation before release'
            using errcode = '55000';
    end if;
    if reservation.recovery_requested_at is not null and (
        p_reason <> 'confirmed-no-side-effect'
        or not (p_evidence ? 'measurement_ref')
        or not (p_evidence ? 'source_event_id')
    ) then
        raise exception 'recovery-requested reservation requires explicit no-side-effect evidence'
            using errcode = '55000';
    end if;
    if reservation.recovery_requested_at is not null then
        update platform.quota_reservations
           set recovery_resolution = 'confirmed-no-side-effect',
               recovery_evidence_ref = p_evidence->>'measurement_ref',
               recovery_resolved_at = clock_timestamp()
         where tenant_id = p_tenant_id and reservation_id = p_reservation_id;
    end if;
    update platform.quota_reservations
       set state = 'released', released_at = clock_timestamp()
     where tenant_id = p_tenant_id and reservation_id = p_reservation_id;
    insert into platform.quota_ledger (
        ledger_id, tenant_id, organization_id, reservation_id, run_id, event_type,
        tool_calls, token_units, cost_units, idempotency_key, evidence
    ) values (
        gen_random_uuid(), p_tenant_id, reservation.organization_id, p_reservation_id, reservation.run_id,
        'released', 0, 0, 0, reservation.idempotency_key,
        coalesce(p_evidence, '{}'::jsonb) || jsonb_build_object('cancellation_reason', p_reason)
    );
    return true;
end;
$$;

