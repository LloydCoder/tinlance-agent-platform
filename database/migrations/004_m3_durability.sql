create table if not exists platform.idempotency_keys (
    tenant_id uuid not null references platform.tenants(tenant_id),
    idempotency_key text not null,
    run_id uuid not null references platform.runs(run_id),
    created_at timestamptz not null default now(),
    primary key (tenant_id, idempotency_key)
);

create table if not exists platform.events (
    event_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    run_id uuid not null references platform.runs(run_id),
    event_type text not null,
    payload jsonb not null,
    sequence bigint not null check (sequence > 0),
    occurred_at timestamptz not null default now(),
    unique (tenant_id, run_id, sequence)
);

create table if not exists platform.outbox (
    outbox_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    event_id uuid not null unique references platform.events(event_id),
    available_at timestamptz not null default now(),
    published_at timestamptz,
    attempts integer not null default 0 check (attempts >= 0),
    last_error text
);

alter table platform.idempotency_keys enable row level security;
alter table platform.idempotency_keys force row level security;
alter table platform.events enable row level security;
alter table platform.events force row level security;
alter table platform.outbox enable row level security;
alter table platform.outbox force row level security;

create policy idempotency_tenant_isolation on platform.idempotency_keys
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy events_tenant_isolation on platform.events
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy outbox_tenant_isolation on platform.outbox
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());

create index if not exists idx_events_tenant_run_sequence
    on platform.events(tenant_id, run_id, sequence);
create index if not exists idx_outbox_pending
    on platform.outbox(available_at, outbox_id)
    where published_at is null;
