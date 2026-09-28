begin;
set role platform_app;
select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000001', true);

insert into platform.tasks (task_id, tenant_id, agent_id, objective)
select '30000000-0000-0000-0000-000000000001', tenant_id,
       '10000000-0000-0000-0000-000000000001', 'durability test'
from platform.tenants
where tenant_id = '00000000-0000-0000-0000-000000000001';
insert into platform.runs (run_id, tenant_id, task_id)
values ('40000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', '30000000-0000-0000-0000-000000000001');
insert into platform.idempotency_keys (tenant_id, idempotency_key, run_id)
values ('00000000-0000-0000-0000-000000000001', 'm3-key', '40000000-0000-0000-0000-000000000001');

select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000002', true);
do $$
begin
    if exists (select 1 from platform.idempotency_keys where tenant_id = '00000000-0000-0000-0000-000000000001') then
        raise exception 'idempotency cross-tenant visibility detected';
    end if;
end
$$;
rollback;
