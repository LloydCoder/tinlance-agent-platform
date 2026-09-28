-- Enterprise integrity: cross-tenant foreign keys, append-only evidence/audit, delegation and domain registration.

alter table platform.tasks add constraint uq_tasks_tenant_task unique (tenant_id, task_id);
alter table platform.runs drop constraint if exists runs_task_id_fkey;
alter table platform.runs add constraint fk_runs_tenant_task
    foreign key (tenant_id, task_id) references platform.tasks(tenant_id, task_id);
alter table platform.runs add constraint uq_runs_tenant_run unique (tenant_id, run_id);

alter table platform.approvals drop constraint if exists approvals_run_id_fkey;
alter table platform.approvals add constraint fk_approvals_tenant_run
    foreign key (tenant_id, run_id) references platform.runs(tenant_id, run_id);
alter table platform.run_budgets drop constraint if exists run_budgets_run_id_fkey;
alter table platform.run_budgets add constraint fk_budgets_tenant_run
    foreign key (tenant_id, run_id) references platform.runs(tenant_id, run_id);

alter table platform.capability_grants drop constraint if exists capability_grants_agent_id_fkey;
alter table platform.capability_grants add constraint fk_grants_tenant_agent
    foreign key (tenant_id, agent_id) references platform.agents(tenant_id, agent_id);

alter table platform.events add constraint uq_events_tenant_event unique (tenant_id, event_id);
alter table platform.events drop constraint if exists events_run_id_fkey;
alter table platform.events add constraint fk_events_tenant_run
    foreign key (tenant_id, run_id) references platform.runs(tenant_id, run_id);
alter table platform.outbox drop constraint if exists outbox_event_id_fkey;
alter table platform.outbox add constraint fk_outbox_tenant_event
    foreign key (tenant_id, event_id) references platform.events(tenant_id, event_id);

create table if not exists platform.evidence (
    evidence_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    run_id uuid not null,
    sequence bigint not null check (sequence > 0),
    content_hash text not null,
    content text not null,
    classification text not null,
    created_at timestamptz not null default now(),
    unique (tenant_id, run_id, sequence),
    foreign key (tenant_id, run_id) references platform.runs(tenant_id, run_id)
);

create table if not exists platform.trajectory_events (
    event_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    run_id uuid not null,
    sequence bigint not null check (sequence > 0),
    event_type text not null,
    payload text not null,
    previous_hash text not null,
    event_hash text not null,
    created_at timestamptz not null default now(),
    unique (tenant_id, run_id, sequence),
    foreign key (tenant_id, run_id) references platform.runs(tenant_id, run_id)
);

create table if not exists platform.audit_records (
    record_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    run_id uuid,
    actor_id text not null,
    actor_type text not null,
    action text not null,
    resource text not null,
    policy_id text not null,
    policy_version text not null,
    decision text not null,
    result text not null,
    occurred_at timestamptz not null default now(),
    foreign key (tenant_id, run_id) references platform.runs(tenant_id, run_id)
);

create table if not exists platform.delegations (
    delegation_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    parent_agent_id uuid not null,
    child_agent_id uuid not null,
    capabilities text[] not null,
    active boolean not null default true,
    created_at timestamptz not null default now(),
    foreign key (tenant_id, parent_agent_id) references platform.agents(tenant_id, agent_id),
    foreign key (tenant_id, child_agent_id) references platform.agents(tenant_id, agent_id)
);

create table if not exists platform.domain_registrations (
    registration_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    domain text not null,
    name text not null,
    version text not null,
    definition_hash text not null,
    created_at timestamptz not null default now(),
    unique (tenant_id, domain, name, version)
);

create table if not exists platform.evaluation_runs (
    evaluation_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    suite text not null,
    passed boolean not null,
    safety_critical boolean not null default false,
    result jsonb not null,
    created_at timestamptz not null default now()
);

create table if not exists platform.observability_events (
    event_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    run_id uuid,
    signal_type text not null,
    name text not null,
    attributes jsonb not null default '{}'::jsonb,
    occurred_at timestamptz not null default now(),
    foreign key (tenant_id, run_id) references platform.runs(tenant_id, run_id)
);

alter table platform.evidence enable row level security;
alter table platform.evidence force row level security;
alter table platform.trajectory_events enable row level security;
alter table platform.trajectory_events force row level security;
alter table platform.audit_records enable row level security;
alter table platform.audit_records force row level security;
alter table platform.delegations enable row level security;
alter table platform.delegations force row level security;
alter table platform.domain_registrations enable row level security;
alter table platform.domain_registrations force row level security;
alter table platform.evaluation_runs enable row level security;
alter table platform.evaluation_runs force row level security;
alter table platform.observability_events enable row level security;
alter table platform.observability_events force row level security;

create policy evidence_tenant_isolation on platform.evidence
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy trajectory_tenant_isolation on platform.trajectory_events
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy audit_tenant_isolation on platform.audit_records
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy delegation_tenant_isolation on platform.delegations
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy domain_registration_tenant_isolation on platform.domain_registrations
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy evaluation_tenant_isolation on platform.evaluation_runs
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy observability_tenant_isolation on platform.observability_events
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());

create index if not exists idx_evidence_tenant_run_sequence on platform.evidence(tenant_id, run_id, sequence);
create index if not exists idx_trajectory_tenant_run_sequence on platform.trajectory_events(tenant_id, run_id, sequence);
create index if not exists idx_audit_tenant_time on platform.audit_records(tenant_id, occurred_at);
create index if not exists idx_observability_tenant_time on platform.observability_events(tenant_id, occurred_at);
