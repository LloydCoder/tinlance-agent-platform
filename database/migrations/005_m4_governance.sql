create table if not exists platform.capability_grants (
    grant_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    agent_id uuid not null references platform.agents(agent_id),
    capability text not null,
    resource text not null,
    expires_at timestamptz,
    created_at timestamptz not null default now(),
    unique (tenant_id, agent_id, capability, resource)
);
create table if not exists platform.emergency_stops (
    tenant_id uuid primary key references platform.tenants(tenant_id),
    stopped_at timestamptz not null default now(),
    reason text not null
);
alter table platform.capability_grants enable row level security;
alter table platform.capability_grants force row level security;
alter table platform.emergency_stops enable row level security;
alter table platform.emergency_stops force row level security;
create policy capability_grants_tenant_isolation on platform.capability_grants
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy emergency_stops_tenant_isolation on platform.emergency_stops
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
