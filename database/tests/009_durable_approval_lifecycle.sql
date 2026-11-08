-- Durable approval lifecycle: tenant isolation, bound decisions, one-time
-- consumption, expiry, append-only audit and concurrent-consumer serialization.
create extension if not exists dblink;

do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'approval_test_app') then
        create role approval_test_app nologin nosuperuser nobypassrls;
    end if;
end
$$;
grant platform_approval_client to approval_test_app;

begin;
insert into platform.tenants(tenant_id, name) values
('00000000-0000-0000-0000-000000000091', 'approval-tenant-a'),
('00000000-0000-0000-0000-000000000092', 'approval-tenant-b');

set role approval_test_app;
select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000091', true);

do $$
declare
    approval_id uuid;
    expiry_id uuid;
    race_id uuid;
    fingerprint text := repeat('a', 64);
    consumed boolean;
begin
    approval_id := platform.request_approval(
        '00000000-0000-0000-0000-000000000091',
        '50000000-0000-0000-0000-000000000091',
        '40000000-0000-0000-0000-000000000091',
        'invoice.refund',
        'invoice:123',
        'refund requested by account owner',
        'requester-a',
        '{}'::jsonb,
        clock_timestamp() + interval '10 minutes',
        fingerprint,
        null
    );

    if approval_id <> '50000000-0000-0000-0000-000000000091' then
        raise exception 'approval request returned an unexpected ID';
    end if;
    if (select a.status from platform.approvals a where a.approval_id = approval_id) <> 'pending' then
        raise exception 'new approval is not pending';
    end if;

    begin
        perform platform.decide_approval(
            '00000000-0000-0000-0000-000000000091',
            approval_id,
            true,
            'requester-a',
            fingerprint
        );
        raise exception 'requester was allowed to approve their own request';
    exception when insufficient_privilege then
        null;
    end;

    begin
        perform platform.decide_approval(
            '00000000-0000-0000-0000-000000000091',
            approval_id,
            true,
            'approver-b',
            repeat('b', 64)
        );
        raise exception 'approval accepted a mismatched intent fingerprint';
    exception when insufficient_privilege then
        null;
    end;

    if platform.decide_approval(
        '00000000-0000-0000-0000-000000000091',
        approval_id,
        true,
        'approver-b',
        fingerprint
    ) <> 'approved' then
        raise exception 'approval did not transition to approved';
    end if;

    begin
        perform platform.consume_approval(
            '00000000-0000-0000-0000-000000000091',
            approval_id,
            '40000000-0000-0000-0000-000000000091',
            'invoice.refund',
            'invoice:other',
            fingerprint
        );
        raise exception 'approval accepted a different resource';
    exception when insufficient_privilege then
        null;
    end;

    consumed := platform.consume_approval(
        '00000000-0000-0000-0000-000000000091',
        approval_id,
        '40000000-0000-0000-0000-000000000091',
        'invoice.refund',
        'invoice:123',
        fingerprint
    );
    if consumed is not true then
        raise exception 'approved intent was not consumed';
    end if;

    consumed := platform.consume_approval(
        '00000000-0000-0000-0000-000000000091',
        approval_id,
        '40000000-0000-0000-0000-000000000091',
        'invoice.refund',
        'invoice:123',
        fingerprint
    );
    if consumed is not false then
        raise exception 'consumed approval was reusable';
    end if;

    if (select status from platform.approvals where approval_id = approval_id) <> 'consumed' then
        raise exception 'approval status was not persisted as consumed';
    end if;
    if (select count(*) from platform.approval_events where approval_id = approval_id) <> 3 then
        raise exception 'approval lifecycle audit did not record request, decision and consumption';
    end if;

    expiry_id := platform.request_approval(
        '00000000-0000-0000-0000-000000000091',
        '50000000-0000-0000-0000-000000000092',
        '40000000-0000-0000-0000-000000000092',
        'invoice.refund',
        'invoice:expired',
        'short-lived approval',
        'requester-a',
        '{}'::jsonb,
        clock_timestamp() + interval '100 milliseconds',
        fingerprint,
        null
    );
    perform pg_sleep(0.2);
    if platform.expire_approval_if_due(
        '00000000-0000-0000-0000-000000000091', expiry_id
    ) is not true then
        raise exception 'expired approval was not transitioned';
    end if;
    if (select a.status from platform.approvals a where a.approval_id = expiry_id) <> 'expired' then
        raise exception 'expired approval status was not persisted';
    end if;
    if platform.consume_approval(
        '00000000-0000-0000-0000-000000000091',
        expiry_id,
        '40000000-0000-0000-0000-000000000092',
        'invoice.refund',
        'invoice:expired',
        fingerprint
    ) is not false then
        raise exception 'expired approval was consumed';
    end if;

    race_id := platform.request_approval(
        '00000000-0000-0000-0000-000000000091',
        '50000000-0000-0000-0000-000000000093',
        '40000000-0000-0000-0000-000000000093',
        'invoice.refund',
        'invoice:concurrent',
        'concurrent one-shot approval',
        'requester-a',
        '{}'::jsonb,
        clock_timestamp() + interval '10 minutes',
        fingerprint,
        null
    );
    perform platform.decide_approval(
        '00000000-0000-0000-0000-000000000091',
        race_id,
        true,
        'approver-b',
        fingerprint
    );
end
$$;

-- The runtime role cannot mutate approval state or its append-only audit directly.
do $$
begin
    begin
        update platform.approvals
           set status = 'approved'
         where approval_id = '50000000-0000-0000-0000-000000000093';
        raise exception 'application role directly updated approval state';
    exception when insufficient_privilege then
        null;
    end;

    begin
        update platform.approval_events
           set actor_subject_id = 'tampered'
         where approval_id = '50000000-0000-0000-0000-000000000093';
        raise exception 'application role mutated approval event history';
    exception when insufficient_privilege then
        null;
    end;

    begin
        delete from platform.approval_events
         where approval_id = '50000000-0000-0000-0000-000000000093';
        raise exception 'application role deleted approval event history';
    exception when insufficient_privilege then
        null;
    end;

    begin
        truncate platform.approval_events;
        raise exception 'application role truncated approval event history';
    exception when insufficient_privilege then
        null;
    end;
end
$$;

-- Tenant B cannot observe tenant A approvals and cannot consume one.
select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000092', true);
do $$
begin
    if exists (
        select 1 from platform.approvals
        where approval_id = '50000000-0000-0000-0000-000000000093'
    ) then
        raise exception 'approval RLS exposed another tenant approval';
    end if;

    begin
        perform platform.consume_approval(
            '00000000-0000-0000-0000-000000000091',
            '50000000-0000-0000-0000-000000000093',
            '40000000-0000-0000-0000-000000000093',
            'invoice.refund',
            'invoice:concurrent',
            repeat('a', 64)
        );
        raise exception 'cross-tenant approval consumption was accepted';
    exception when insufficient_privilege then
        null;
    end;
end
$$;

reset role;
commit;

-- Two independent sessions race to consume the same approved approval.
select dblink_connect(
    'approval_race_one',
    'dbname=postgres user=postgres password=postgres host=127.0.0.1'
);
select dblink_connect(
    'approval_race_two',
    'dbname=postgres user=postgres password=postgres host=127.0.0.1'
);

select dblink_send_query(
    'approval_race_one',
    $query$
        with setup as materialized (
            select set_config('role', 'approval_test_app', false),
                   set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000091', false),
                   pg_sleep(0.2)
        )
        select platform.consume_approval(
            '00000000-0000-0000-0000-000000000091',
            '50000000-0000-0000-0000-000000000093',
            '40000000-0000-0000-0000-000000000093',
            'invoice.refund',
            'invoice:concurrent',
            repeat('a', 64)
        ) from setup
    $query$
);

select dblink_send_query(
    'approval_race_two',
    $query$
        with setup as materialized (
            select set_config('role', 'approval_test_app', false),
                   set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000091', false),
                   pg_sleep(0.2)
        )
        select platform.consume_approval(
            '00000000-0000-0000-0000-000000000091',
            '50000000-0000-0000-0000-000000000093',
            '40000000-0000-0000-0000-000000000093',
            'invoice.refund',
            'invoice:concurrent',
            repeat('a', 64)
        ) from setup
    $query$
);

create temporary table approval_consume_results(consumed boolean);
insert into approval_consume_results
select consumed from dblink_get_result('approval_race_one', false) as result(consumed boolean);
insert into approval_consume_results
select consumed from dblink_get_result('approval_race_two', false) as result(consumed boolean);
select * from dblink_get_result('approval_race_one', false) as result(consumed boolean);
select * from dblink_get_result('approval_race_two', false) as result(consumed boolean);

do $$
begin
    if (select count(*) from approval_consume_results where consumed is true) <> 1
       or (select count(*) from approval_consume_results where consumed is false) <> 1 then
        raise exception 'concurrent approval consumption was not one-shot';
    end if;
    if (
        select count(*) from platform.approval_events
        where approval_id = '50000000-0000-0000-0000-000000000093'
          and event_type = 'consumed'
    ) <> 1 then
        raise exception 'concurrent consumers wrote more than one consumed audit event';
    end if;
end
$$;

select dblink_disconnect('approval_race_one');
select dblink_disconnect('approval_race_two');
