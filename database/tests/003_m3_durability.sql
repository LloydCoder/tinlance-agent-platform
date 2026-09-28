begin;
create role m3_app nologin;
grant usage on schema platform to m3_app;
grant select, insert, update, delete on all tables in schema platform to m3_app;
insert into platform.tenants (tenant_id, name) values
('00000000-0000-0000-0000-000000000001', 'tenant-a'),
('00000000-0000-0000-0000-000000000002', 'tenant-b');
insert into platform.agents (
    agent_id, tenant_id, agent_type, version, owner_subject_id,
    policy_profile, trust_level, environment
) values (
    '10000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    'research', '1.0.0', 'owner-a', 'default', 'standard', 'test'
);
insert into platform.tasks (
    task_id, tenant_id, agent_id, agent_version, requester_subject_id, status, objective
) values (
    '30000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    '10000000-0000-0000-0000-000000000001', '1.0.0', 'owner-a', 'queued', 'durability test'
);
insert into platform.runs (run_id, tenant_id, task_id)
values (
    '40000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',
    '30000000-0000-0000-0000-000000000001'
);
set role m3_app;
select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000001', true);
insert into platform.idempotency_keys (tenant_id, idempotency_key, run_id)
values ('00000000-0000-0000-0000-000000000001', 'm3-key', '40000000-0000-0000-0000-000000000001');
select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000002', true);
do $$
begin
    if exists (
        select 1 from platform.idempotency_keys
        where tenant_id = '00000000-0000-0000-0000-000000000001'
    ) then
        raise exception 'idempotency cross-tenant visibility detected';
    end if;
end
$$;
rollback;
