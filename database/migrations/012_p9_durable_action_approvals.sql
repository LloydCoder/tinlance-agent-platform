-- Durable approval authority for high-risk operations that are not backed by a Platform run row.
create table if not exists platform.action_approvals (
    approval_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    run_id uuid not null,
    action text not null check (length(action) between 1 and 256),
    resource text not null check (length(resource) between 1 and 2048),
    reason text not null check (length(reason) between 1 and 4096),
    requested_by text not null check (length(requested_by) between 1 and 512),
    status text not null check (
        status in ('pending', 'approved', 'rejected', 'expired', 'cancelled', 'consumed')
    ),
    metadata jsonb not null default '{}'::jsonb check (jsonb_typeof(metadata) = 'object'),
    expires_at timestamptz,
    intent_fingerprint text check (
        intent_fingerprint is null or intent_fingerprint ~ '^[0-9a-f]{64}$'
    ),
    approved_by text,
    consumed_at timestamptz,
    created_at timestamptz not null default now(),
    decided_at timestamptz,
    unique (tenant_id, approval_id),
    check (status not in ('approved', 'consumed') or approved_by is not null),
    check (status not in ('pending', 'rejected', 'cancelled') or approved_by is null),
    check ((status = 'consumed') = (consumed_at is not null)),
    check (
        (status in ('pending')) = (decided_at is null)
    )
);

create index if not exists idx_action_approvals_tenant_status
    on platform.action_approvals (tenant_id, status, created_at);
create index if not exists idx_action_approvals_tenant_run
    on platform.action_approvals (tenant_id, run_id, created_at);
create index if not exists idx_action_approvals_expiry
    on platform.action_approvals (tenant_id, expires_at)
    where status in ('pending', 'approved');

alter table platform.action_approvals enable row level security;
alter table platform.action_approvals force row level security;
create policy action_approvals_tenant_isolation on platform.action_approvals
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());

create table if not exists platform.action_approval_events (
    event_id uuid primary key,
    tenant_id uuid not null,
    approval_id uuid not null,
    event_type text not null check (
        event_type in ('requested', 'approved', 'rejected', 'expired', 'cancelled', 'consumed')
    ),
    actor_subject_id text,
    intent_fingerprint text check (
        intent_fingerprint is null or intent_fingerprint ~ '^[0-9a-f]{64}$'
    ),
    occurred_at timestamptz not null default now(),
    foreign key (tenant_id, approval_id)
        references platform.action_approvals (tenant_id, approval_id)
);

create index if not exists idx_action_approval_events_tenant_approval
    on platform.action_approval_events (tenant_id, approval_id, occurred_at);

alter table platform.action_approval_events enable row level security;
alter table platform.action_approval_events force row level security;
create policy action_approval_events_tenant_isolation on platform.action_approval_events
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());

revoke update, delete on platform.action_approval_events from public;
