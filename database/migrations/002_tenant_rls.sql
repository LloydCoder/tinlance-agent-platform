create or replace function platform.current_tenant_id()
returns uuid
language sql
stable
as $$
    select nullif(current_setting('platform.tenant_id', true), '')::uuid
$$;

alter table platform.tenants enable row level security;
alter table platform.tenants force row level security;
alter table platform.agents enable row level security;
alter table platform.agents force row level security;
alter table platform.tasks enable row level security;
alter table platform.tasks force row level security;

create policy tenants_tenant_isolation on platform.tenants
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy agents_tenant_isolation on platform.agents
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy tasks_tenant_isolation on platform.tasks
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
