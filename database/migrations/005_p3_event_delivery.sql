-- P3: canonical event lineage, expiring publisher leases, and idempotent consumer inbox.
-- This migration adds schema support only; callers must write domain state, event, and outbox
-- rows in one database transaction. External publication is at-least-once, never exactly-once.

alter table platform.events
    add column if not exists source text not null default 'urn:tinlance:agent-platform',
    add column if not exists correlation_id text,
    add column if not exists causation_id text,
    add column if not exists trace_id char(32),
    add column if not exists span_id char(16),
    add column if not exists schema_uri text,
    add column if not exists data_classification text not null default 'internal'
        check (data_classification in ('public', 'internal', 'confidential', 'restricted'));

create unique index if not exists uq_events_source_event_id
    on platform.events(source, event_id);

alter table platform.outbox
    add column if not exists lease_token uuid,
    add column if not exists lease_expires_at timestamptz,
    add column if not exists ordering_key text,
    add column if not exists last_error_code text;

alter table platform.outbox
    drop constraint if exists outbox_lease_pair_check;
alter table platform.outbox
    add constraint outbox_lease_pair_check
    check ((lease_token is null and lease_expires_at is null)
        or (lease_token is not null and lease_expires_at is not null));

create index if not exists idx_outbox_available_lease
    on platform.outbox(available_at, lease_expires_at, outbox_id)
    where published_at is null;

create table if not exists platform.inbox (
    tenant_id uuid not null references platform.tenants(tenant_id),
    event_source text not null,
    event_id text not null,
    consumer_id text not null,
    payload_digest char(64) not null,
    processed_at timestamptz not null default now(),
    primary key (tenant_id, event_source, event_id, consumer_id),
    check (length(trim(event_source)) > 0),
    check (length(trim(event_id)) > 0),
    check (length(trim(consumer_id)) > 0),
    check (payload_digest ~ '^[0-9a-f]{64}$')
);

alter table platform.inbox enable row level security;
alter table platform.inbox force row level security;
drop policy if exists inbox_tenant_isolation on platform.inbox;
create policy inbox_tenant_isolation on platform.inbox
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());

create index if not exists idx_inbox_processed_at
    on platform.inbox(tenant_id, processed_at);
