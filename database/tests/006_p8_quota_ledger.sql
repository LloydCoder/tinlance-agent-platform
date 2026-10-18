begin;

create role p8_quota_test_app nologin;
grant usage on schema platform to p8_quota_test_app;
grant select, insert, update, delete on all tables in schema platform to p8_quota_test_app;
grant truncate on platform.quota_ledger to p8_quota_test_app;
grant execute on function platform.reserve_quota(uuid, uuid, uuid, uuid, uuid, text, text, text, integer, bigint, bigint, numeric) to p8_quota_test_app;
grant execute on function platform.settle_quota(uuid, uuid, bigint, bigint, numeric, jsonb) to p8_quota_test_app;
grant execute on function platform.release_quota(uuid, uuid, text, jsonb) to p8_quota_test_app;

insert into platform.tenants(tenant_id, name)
values ('00000000-0000-0000-0000-000000000071', 'p8-quota-tenant');

insert into platform.agents(
    agent_id, tenant_id, agent_type, version, owner_subject_id,
    policy_profile, trust_level, environment
) values (
    '10000000-0000-0000-0000-000000000071',
    '00000000-0000-0000-0000-000000000071',
    'quota-test', '1.0.0', 'p8-owner', 'default', 'standard', 'test'
);

insert into platform.tasks(
    task_id, tenant_id, agent_id, agent_version, requester_subject_id, status, objective
) values (
    '20000000-0000-0000-0000-000000000071',
    '00000000-0000-0000-0000-000000000071',
    '10000000-0000-0000-0000-000000000071',
    '1.0.0', 'p8-owner', 'queued', 'quota ledger test'
);

insert into platform.runs(run_id, tenant_id, task_id, status)
values (
    '30000000-0000-0000-0000-000000000071',
    '00000000-0000-0000-0000-000000000071',
    '20000000-0000-0000-0000-000000000071', 'created'
);

insert into platform.organizations(organization_id, tenant_id, name)
values (
    '40000000-0000-0000-0000-000000000071',
    '00000000-0000-0000-0000-000000000071', 'p8-test-org'
);

insert into platform.tenant_budget_limits(
    tenant_id, max_concurrency, max_tool_calls, max_token_units, max_cost_units
) values (
    '00000000-0000-0000-0000-000000000071', 3, 100, 1000, 100
);

insert into platform.organization_budget_limits(
    tenant_id, organization_id, max_concurrency, max_tool_calls, max_token_units, max_cost_units
) values (
    '00000000-0000-0000-0000-000000000071',
    '40000000-0000-0000-0000-000000000071', 3, 100, 1000, 100
);

set role p8_quota_test_app;
select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000071', true);

do $$
declare
    first_id uuid := '50000000-0000-0000-0000-000000000071';
    second_id uuid := '60000000-0000-0000-0000-000000000071';
    replay_id uuid;
    released boolean;
    settled text;
begin
    replay_id := platform.reserve_quota(
        first_id,
        '00000000-0000-0000-0000-000000000071',
        '40000000-0000-0000-0000-000000000071',
        '10000000-0000-0000-0000-000000000071',
        '30000000-0000-0000-0000-000000000071',
        'read', 'resource:one', 'p8-idempotency-key-0001', 1, 1, 10, 1.0
    );
    if replay_id <> first_id then
        raise exception 'first reservation returned an unexpected ID';
    end if;

    replay_id := platform.reserve_quota(
        second_id,
        '00000000-0000-0000-0000-000000000071',
        '40000000-0000-0000-0000-000000000071',
        '10000000-0000-0000-0000-000000000071',
        '30000000-0000-0000-0000-000000000071',
        'read', 'resource:one', 'p8-idempotency-key-0001', 1, 1, 10, 1.0
    );
    if replay_id <> first_id then
        raise exception 'identical reservation retry was not idempotent';
    end if;

    settled := platform.settle_quota(
        '00000000-0000-0000-0000-000000000071', first_id, 1, 10, 1.0,
        '{"provider":"unit-test","measurement_ref":"usage:p8-test"}'::jsonb
    );
    if settled <> 'settled' then
        raise exception 'expected settled, got %', settled;
    end if;

    settled := platform.settle_quota(
        '00000000-0000-0000-0000-000000000071', first_id, 1, 10, 1.0,
        '{"provider":"unit-test","measurement_ref":"usage:p8-test"}'::jsonb
    );
    if settled <> 'already_settled' then
        raise exception 'settlement retry was not idempotent';
    end if;

    replay_id := platform.reserve_quota(
        first_id,
        '00000000-0000-0000-0000-000000000071',
        '40000000-0000-0000-0000-000000000071',
        '10000000-0000-0000-0000-000000000071',
        '30000000-0000-0000-0000-000000000071',
        'read', 'resource:one', 'p8-idempotency-key-0001', 1, 1, 10, 1.0
    );
    if replay_id <> first_id then
        raise exception 'retry after settlement created a different reservation';
    end if;

    perform platform.reserve_quota(
        second_id,
        '00000000-0000-0000-0000-000000000071',
        '40000000-0000-0000-0000-000000000071',
        '10000000-0000-0000-0000-000000000071',
        '30000000-0000-0000-0000-000000000071',
        'read', 'resource:two', 'p8-idempotency-key-0002', 1, 1, 10, 1.0
    );

    released := platform.release_quota(
        '00000000-0000-0000-0000-000000000071', second_id,
        'cancelled-before-side-effect', '{"cancellation_reason":"test"}'::jsonb
    );
    if released is not true then
        raise exception 'first release did not report a state transition';
    end if;

    released := platform.release_quota(
        '00000000-0000-0000-0000-000000000071', second_id,
        'cancelled-before-side-effect', '{"cancellation_reason":"test"}'::jsonb
    );
    if released is not false then
        raise exception 'duplicate release was not idempotent';
    end if;

    if (select count(*) from platform.quota_ledger where tenant_id = '00000000-0000-0000-0000-000000000071') <> 4 then
        raise exception 'expected exactly four append-only ledger facts';
    end if;
    if (select used_tool_calls from platform.tenant_budget_limits where tenant_id = '00000000-0000-0000-0000-000000000071') <> 1 then
        raise exception 'settlement usage was not accounted exactly once';
    end if;

    begin
        update platform.quota_ledger
           set cost_units = 999
         where tenant_id = '00000000-0000-0000-0000-000000000071';
        raise exception 'append-only ledger allowed an update';
    exception when insufficient_privilege then
        null;
    end;

    begin
        delete from platform.quota_ledger
         where tenant_id = '00000000-0000-0000-0000-000000000071';
        raise exception 'append-only ledger allowed a delete';
    exception when insufficient_privilege then
        null;
    end;

    begin
        truncate platform.quota_ledger;
        raise exception 'append-only ledger allowed truncation';
    exception when insufficient_privilege then
        null;
    end;
end;
$$;

rollback;
