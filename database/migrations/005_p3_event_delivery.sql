-- P3: canonical event lineage, durable outbox leases, and idempotent consumer inbox.
-- Producers must commit domain state, event, and outbox rows in one transaction.
-- Consumers must commit the inbox receipt and business effect in one transaction.
-- Delivery is at-least-once; this migration does not claim exactly-once side effects.

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

-- Existing events predate P3 trace propagation. Backfill stable synthetic trace IDs
-- and correlation IDs rather than losing legacy rows; these IDs are observability only.
update platform.events
   set trace_id = md5(event_id::text)
 where trace_id is null;
update platform.events
   set correlation_id = coalesce(run_id::text, event_id::text)
 where correlation_id is null;
alter table platform.events alter column trace_id set not null;
alter table platform.events alter column correlation_id set not null;

alter table platform.events drop constraint if exists events_source_nonempty_check;
alter table platform.events add constraint events_source_nonempty_check
    check (length(trim(source)) > 0);
alter table platform.events drop constraint if exists events_trace_id_check;
alter table platform.events add constraint events_trace_id_check
    check (trace_id is null or (
        trace_id ~ '^[0-9a-f]{32}$' and trace_id <> repeat('0', 32)
    ));
alter table platform.events drop constraint if exists events_span_id_check;
alter table platform.events add constraint events_span_id_check
    check (span_id is null or (
        span_id ~ '^[0-9a-f]{16}$' and span_id <> repeat('0', 16)
    ));
alter table platform.events drop constraint if exists events_correlation_id_check;
alter table platform.events add constraint events_correlation_id_check
    check (correlation_id is null or length(trim(correlation_id)) > 0);

alter table platform.outbox
    add column if not exists lease_token uuid,
    add column if not exists lease_expires_at timestamptz,
    add column if not exists ordering_key text,
    add column if not exists last_error_code text,
    add column if not exists max_attempts integer not null default 10
        check (max_attempts between 1 and 100),
    add column if not exists dead_lettered_at timestamptz;

alter table platform.outbox
    drop constraint if exists outbox_lease_pair_check;
alter table platform.outbox
    add constraint outbox_lease_pair_check
    check ((lease_token is null and lease_expires_at is null)
        or (lease_token is not null and lease_expires_at is not null));

create index if not exists idx_outbox_available_lease
    on platform.outbox(available_at, lease_expires_at, outbox_id)
    where published_at is null and dead_lettered_at is null;

create table if not exists platform.inbox (
    tenant_id uuid not null references platform.tenants(tenant_id),
    event_source text not null,
    event_id text not null,
    consumer_id text not null,
    payload_digest char(64) not null,
    processed_at timestamptz not null default clock_timestamp(),
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

-- These functions execute as the caller, retain RLS, and do not elevate authority.
create or replace function platform.claim_outbox_batch(
    p_limit integer default 100,
    p_lease_seconds integer default 30
) returns setof platform.outbox
language plpgsql
set search_path = pg_catalog, platform
as $$
begin
    if p_limit is null or p_limit < 1 or p_limit > 1000 then
        raise exception 'outbox claim limit must be between 1 and 1000';
    end if;
    if p_lease_seconds is null or p_lease_seconds < 1 or p_lease_seconds > 3600 then
        raise exception 'outbox lease must be between 1 and 3600 seconds';
    end if;
    return query
    with candidates as (
        select o.outbox_id
        from platform.outbox o
        where o.tenant_id = platform.current_tenant_id()
          and o.published_at is null
          and o.dead_lettered_at is null
          and o.available_at <= clock_timestamp()
          and (o.lease_expires_at is null or o.lease_expires_at <= clock_timestamp())
        order by o.available_at, o.outbox_id
        for update skip locked
        limit p_limit
    )
    update platform.outbox o
       set lease_token = gen_random_uuid(),
           lease_expires_at = clock_timestamp() + make_interval(secs => p_lease_seconds),
           attempts = o.attempts + 1
      from candidates c
     where o.outbox_id = c.outbox_id
    returning o.*;
end;
$$;

create or replace function platform.ack_outbox(
    p_outbox_id uuid,
    p_lease_token uuid
) returns boolean
language plpgsql
set search_path = pg_catalog, platform
as $$
declare
    affected integer;
begin
    update platform.outbox
       set published_at = clock_timestamp(), lease_token = null, lease_expires_at = null
     where outbox_id = p_outbox_id
       and tenant_id = platform.current_tenant_id()
       and lease_token = p_lease_token
       and lease_expires_at > clock_timestamp()
       and published_at is null
       and dead_lettered_at is null;
    get diagnostics affected = row_count;
    return affected = 1;
end;
$$;

create or replace function platform.release_outbox(
    p_outbox_id uuid,
    p_lease_token uuid,
    p_error_code text,
    p_retry_base_seconds integer default 1
) returns boolean
language plpgsql
set search_path = pg_catalog, platform
as $$
declare
    affected integer;
begin
    if p_error_code is null or p_error_code !~ '^[A-Za-z0-9_.-]{1,128}$' then
        raise exception 'error code must be a non-sensitive stable identifier';
    end if;
    if p_retry_base_seconds is null
       or p_retry_base_seconds < 0
       or p_retry_base_seconds > 3600 then
        raise exception 'retry base must be between 0 and 3600 seconds';
    end if;
    update platform.outbox
       set dead_lettered_at = case when attempts >= max_attempts then clock_timestamp() else null end,
           available_at = case when attempts >= max_attempts
                               then available_at
                               else clock_timestamp() + (
                                   least(
                                       86400::double precision,
                                       p_retry_base_seconds::double precision
                                           * power(
                                               2.0::double precision,
                                               greatest(attempts - 1, 0)::double precision
                                           )
                                           * (0.5 + random() * 0.5)
                                   ) * interval '1 second'
                               ) end,
           last_error_code = p_error_code,
           lease_token = null,
           lease_expires_at = null
     where outbox_id = p_outbox_id
       and tenant_id = platform.current_tenant_id()
       and lease_token = p_lease_token
       and lease_expires_at > clock_timestamp()
       and published_at is null
       and dead_lettered_at is null;
    get diagnostics affected = row_count;
    return affected = 1;
end;
$$;

create or replace function platform.record_inbox_once(
    p_event_source text,
    p_event_id text,
    p_consumer_id text,
    p_payload_digest text
) returns boolean
language plpgsql
set search_path = pg_catalog, platform
as $$
declare
    affected integer;
    existing_digest char(64);
begin
    if p_event_source is null or length(trim(p_event_source)) = 0
       or p_event_id is null or length(trim(p_event_id)) = 0
       or p_consumer_id is null or length(trim(p_consumer_id)) = 0 then
        raise exception 'event source, event id and consumer id are required';
    end if;
    if p_payload_digest is null or p_payload_digest !~ '^[0-9a-f]{64}$' then
        raise exception 'payload digest must be lowercase SHA-256 hex';
    end if;
    insert into platform.inbox (
        tenant_id, event_source, event_id, consumer_id, payload_digest
    ) values (
        platform.current_tenant_id(), p_event_source, p_event_id, p_consumer_id, p_payload_digest
    ) on conflict (tenant_id, event_source, event_id, consumer_id) do nothing;
    get diagnostics affected = row_count;
    if affected = 1 then
        return true;
    end if;
    select payload_digest into existing_digest
      from platform.inbox
     where tenant_id = platform.current_tenant_id()
       and event_source = p_event_source
       and event_id = p_event_id
       and consumer_id = p_consumer_id;
    if not found then
        raise exception 'inbox duplicate could not be verified';
    end if;
    if existing_digest <> p_payload_digest then
        raise exception 'event identity reused with a different payload digest';
    end if;
    return false;
end;
$$;
