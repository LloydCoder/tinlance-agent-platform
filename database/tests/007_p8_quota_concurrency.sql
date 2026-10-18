-- Real concurrent PostgreSQL admission test for P8.
-- This file runs in the isolated CI database after migrations and earlier SQL tests.
create extension if not exists dblink;

insert into platform.tenants(tenant_id, name)
values ('00000000-0000-0000-0000-000000000081', 'p8-race-tenant');

insert into platform.agents(
    agent_id, tenant_id, agent_type, version, owner_subject_id,
    policy_profile, trust_level, environment
) values (
    '10000000-0000-0000-0000-000000000081',
    '00000000-0000-0000-0000-000000000081',
    'quota-race', '1.0.0', 'p8-race-owner', 'default', 'standard', 'test'
);

insert into platform.tasks(
    task_id, tenant_id, agent_id, agent_version, requester_subject_id, status, objective
) values (
    '20000000-0000-0000-0000-000000000081',
    '00000000-0000-0000-0000-000000000081',
    '10000000-0000-0000-0000-000000000081',
    '1.0.0', 'p8-race-owner', 'queued', 'concurrent quota admission'
);

insert into platform.runs(run_id, tenant_id, task_id, status)
values (
    '30000000-0000-0000-0000-000000000081',
    '00000000-0000-0000-0000-000000000081',
    '20000000-0000-0000-0000-000000000081', 'created'
);

insert into platform.tenant_budget_limits(
    tenant_id, max_concurrency, max_tool_calls, max_token_units, max_cost_units
) values (
    '00000000-0000-0000-0000-000000000081', 1, 10, 1000, 100
);

select dblink_connect(
    'p8_race_one',
    'dbname=postgres user=postgres password=postgres host=127.0.0.1'
);
select dblink_connect(
    'p8_race_two',
    'dbname=postgres user=postgres password=postgres host=127.0.0.1'
);

select dblink_send_query(
    'p8_race_one',
    $query$
        with tenant_context as materialized (
            select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000081', false)
        ), delay as materialized (
            select pg_sleep(0.25) from tenant_context
        )
        select platform.reserve_quota(
            '50000000-0000-0000-0000-000000000081',
            '00000000-0000-0000-0000-000000000081',
            null,
            '10000000-0000-0000-0000-000000000081',
            '30000000-0000-0000-0000-000000000081',
            'read', 'resource:race-one', 'p8-race-idempotency-0001', 1, 1, 10, 1.0
        ) from delay
    $query$
);

select dblink_send_query(
    'p8_race_two',
    $query$
        with tenant_context as materialized (
            select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000081', false)
        ), delay as materialized (
            select pg_sleep(0.25) from tenant_context
        )
        select platform.reserve_quota(
            '60000000-0000-0000-0000-000000000081',
            '00000000-0000-0000-0000-000000000081',
            null,
            '10000000-0000-0000-0000-000000000081',
            '30000000-0000-0000-0000-000000000081',
            'read', 'resource:race-two', 'p8-race-idempotency-0002', 1, 1, 10, 1.0
        ) from delay
    $query$
);

create temporary table p8_race_results(reservation_id uuid);
insert into p8_race_results
select reservation_id from dblink_get_result('p8_race_one', false) as result(reservation_id uuid);
insert into p8_race_results
select reservation_id from dblink_get_result('p8_race_two', false) as result(reservation_id uuid);

-- Drain each asynchronous connection after the first result set.
select * from dblink_get_result('p8_race_one', false) as result(reservation_id uuid);
select * from dblink_get_result('p8_race_two', false) as result(reservation_id uuid);

do $$
begin
    if (select count(*) from p8_race_results) <> 1 then
        raise exception 'concurrent admission must admit exactly one reservation';
    end if;
    if (
        select count(*) from platform.quota_reservations
        where tenant_id = '00000000-0000-0000-0000-000000000081'
          and state = 'reserved'
    ) <> 1 then
        raise exception 'concurrent admission oversubscribed tenant concurrency';
    end if;
end
$$;

select dblink_disconnect('p8_race_one');
select dblink_disconnect('p8_race_two');
