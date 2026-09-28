create table if not exists platform.memory_entries (
    memory_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    content text not null,
    classification text not null check (classification in ('public','internal','sensitive')),
    created_at timestamptz not null default now()
);
alter table platform.memory_entries enable row level security;
alter table platform.memory_entries force row level security;
create policy memory_tenant_isolation on platform.memory_entries
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
