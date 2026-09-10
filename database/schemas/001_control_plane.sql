-- M0 control-plane relational baseline.
-- Tenant-owned tables are intentionally small at M0; later migrations expand the model.
-- RLS policies are added with the first production persistence implementation and must be
-- validated with both application authorization tests and database-level isolation tests.

create schema if not exists platform;

create table if not exists platform.tenants (
    tenant_id uuid primary key,
    name text not null,
    status text not null default 'active',
    created_at timestamptz not null default now()
);

create table if not exists platform.agents (
    agent_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    agent_type text not null,
    version text not null,
    owner_subject_id text not null,
    policy_profile text not null,
    trust_level text not null,
    environment text not null,
    lifecycle_state text not null default 'registered',
    created_at timestamptz not null default now(),
    unique (tenant_id, agent_id, version)
);

create table if not exists platform.tasks (
    task_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    agent_id uuid not null,
    agent_version text not null,
    requester_subject_id text not null,
    status text not null,
    objective text not null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists idx_agents_tenant on platform.agents (tenant_id);
create index if not exists idx_tasks_tenant on platform.tasks (tenant_id);
create index if not exists idx_tasks_agent on platform.tasks (tenant_id, agent_id);
