-- Durable tenant-scoped approval lifecycle.
-- Approval run IDs are opaque execution identifiers: they may represent governed
-- MCP/tool executions that do not have a platform.runs row.
alter table platform.approvals
    drop constraint if exists fk_approvals_tenant_run;

alter table platform.approvals
    add column if not exists metadata jsonb not null default '{}'::jsonb,
    add column if not exists expires_at timestamptz,
    add column if not exists intent_fingerprint text,
    add column if not exists approved_by text,
    add column if not exists consumed_at timestamptz,
    add column if not exists trace_context jsonb;

alter table platform.approvals
    drop constraint if exists approvals_status_check;
alter table platform.approvals
    add constraint approvals_status_check
    check (status in ('pending', 'approved', 'rejected', 'expired', 'cancelled', 'consumed'));

alter table platform.approvals
    drop constraint if exists approvals_intent_fingerprint_check;
alter table platform.approvals
    add constraint approvals_intent_fingerprint_check
    check (intent_fingerprint is null or intent_fingerprint ~ '^[0-9a-f]{64}$');

alter table platform.approvals
    drop constraint if exists approvals_metadata_object_check;
alter table platform.approvals
    add constraint approvals_metadata_object_check
    check (
        jsonb_typeof(metadata) = 'object'
        and octet_length(metadata::text) <= 8192
    );

alter table platform.approvals
    drop constraint if exists approvals_trace_context_object_check;
alter table platform.approvals
    add constraint approvals_trace_context_object_check
    check (
        trace_context is null
        or (
            jsonb_typeof(trace_context) = 'object'
            and octet_length(trace_context::text) <= 4096
        )
    );

alter table platform.approvals
    drop constraint if exists approvals_state_consistency_check;
alter table platform.approvals
    add constraint approvals_state_consistency_check
    check (
        (status = 'pending' and decided_at is null and approved_by is null and consumed_at is null)
        or (status in ('approved', 'rejected')
            and decided_at is not null and approved_by is not null and consumed_at is null)
        or (status = 'expired' and decided_at is not null and approved_by is null and consumed_at is null)
        or (status = 'cancelled' and decided_at is not null and consumed_at is null)
        or (status = 'consumed'
            and decided_at is not null and approved_by is not null and consumed_at is not null)
    );

alter table platform.approvals
    drop constraint if exists uq_approvals_tenant_approval;
alter table platform.approvals
    add constraint uq_approvals_tenant_approval unique (tenant_id, approval_id);

create index if not exists idx_approvals_pending_expiry
    on platform.approvals(tenant_id, expires_at, approval_id)
    where status = 'pending' and expires_at is not null;
create index if not exists idx_approvals_tenant_run
    on platform.approvals(tenant_id, run_id, created_at desc);

create table if not exists platform.approval_events (
    event_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    approval_id uuid not null,
    event_type text not null check (
        event_type in ('requested', 'approved', 'rejected', 'expired', 'consumed', 'cancelled')
    ),
    actor_subject_id text not null check (
        length(trim(actor_subject_id)) between 1 and 256
        and actor_subject_id = btrim(actor_subject_id)
        and actor_subject_id !~ '[[:cntrl:]]'
    ),
    intent_fingerprint text check (
        intent_fingerprint is null or intent_fingerprint ~ '^[0-9a-f]{64}$'
    ),
    metadata jsonb not null default '{}'::jsonb check (
        jsonb_typeof(metadata) = 'object' and octet_length(metadata::text) <= 4096
    ),
    occurred_at timestamptz not null default clock_timestamp(),
    foreign key (tenant_id, approval_id)
        references platform.approvals(tenant_id, approval_id)
);

alter table platform.approvals enable row level security;
alter table platform.approvals force row level security;
alter table platform.approval_events enable row level security;
alter table platform.approval_events force row level security;

drop policy if exists approvals_tenant_isolation on platform.approvals;
create policy approvals_tenant_isolation on platform.approvals
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy approval_events_tenant_isolation on platform.approval_events
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());

create index if not exists idx_approval_events_tenant_approval
    on platform.approval_events(tenant_id, approval_id, occurred_at, event_id);

-- The application receives read-only table access. All state transitions are
-- performed by SECURITY DEFINER functions owned by a non-login, non-BYPASSRLS
-- role, so callers cannot directly approve, expire or consume an approval.
do $$
begin
    if not exists (select 1 from pg_roles where rolname = 'platform_approval_executor') then
        create role platform_approval_executor nologin nosuperuser nobypassrls;
    end if;
    if not exists (select 1 from pg_roles where rolname = 'platform_approval_client') then
        create role platform_approval_client nologin nosuperuser nobypassrls;
    end if;
end
$$;

alter role platform_approval_executor nologin nosuperuser nobypassrls;
alter role platform_approval_client nologin nosuperuser nobypassrls;

grant usage on schema platform to platform_approval_executor, platform_approval_client;
grant select on platform.tenants, platform.runs to platform_approval_executor;
grant select, insert, update on platform.approvals to platform_approval_executor;
grant select, insert on platform.approval_events to platform_approval_executor;
grant execute on function platform.current_tenant_id() to platform_approval_executor;
grant select on platform.approvals, platform.approval_events to platform_approval_client;

create or replace function platform.reject_approval_event_mutation()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog, platform
as $$
begin
    raise exception 'approval event history is append-only' using errcode = '42501';
end;
$$;

drop trigger if exists approval_events_append_only on platform.approval_events;
create trigger approval_events_append_only
before update or delete on platform.approval_events
for each row execute function platform.reject_approval_event_mutation();
drop trigger if exists approval_events_no_truncate on platform.approval_events;
create trigger approval_events_no_truncate
before truncate on platform.approval_events
for each statement execute function platform.reject_approval_event_mutation();

revoke update, delete, truncate on platform.approval_events from public;

create or replace function platform.request_approval(
    p_tenant_id uuid,
    p_approval_id uuid,
    p_run_id uuid,
    p_action text,
    p_resource text,
    p_reason text,
    p_requested_by text,
    p_metadata jsonb default '{}'::jsonb,
    p_expires_at timestamptz default null,
    p_intent_fingerprint text default null,
    p_trace_context jsonb default null
) returns uuid
language plpgsql
security definer
set search_path = pg_catalog, platform
as $$
declare
    normalized_metadata jsonb := coalesce(p_metadata, '{}'::jsonb);
begin
    if platform.current_tenant_id() is distinct from p_tenant_id then
        raise exception 'tenant scope mismatch' using errcode = '42501';
    end if;
    if p_approval_id is null or p_run_id is null
       or p_action is null or length(trim(p_action)) not between 1 and 256
       or p_action <> btrim(p_action) or p_action ~ '[[:cntrl:]]'
       or p_resource is null or length(trim(p_resource)) not between 1 and 512
       or p_resource <> btrim(p_resource) or p_resource ~ '[[:cntrl:]]'
       or p_reason is null or length(trim(p_reason)) not between 1 and 1024
       or p_reason <> btrim(p_reason) or p_reason ~ '[[:cntrl:]]'
       or p_requested_by is null or length(trim(p_requested_by)) not between 1 and 256
       or p_requested_by <> btrim(p_requested_by) or p_requested_by ~ '[[:cntrl:]]'
       or (p_expires_at is not null and (
            p_expires_at <= clock_timestamp()
            or p_expires_at > clock_timestamp() + interval '30 days'
       ))
       or (p_intent_fingerprint is not null and p_intent_fingerprint !~ '^[0-9a-f]{64}$')
       or jsonb_typeof(normalized_metadata) <> 'object'
       or octet_length(normalized_metadata::text) > 8192
       or (p_trace_context is not null and (
            jsonb_typeof(p_trace_context) <> 'object'
            or octet_length(p_trace_context::text) > 4096
       )) then
        raise exception 'invalid approval request' using errcode = '22023';
    end if;

    perform 1 from platform.tenants
     where tenant_id = p_tenant_id and status = 'active'
     for share;
    if not found then
        raise exception 'tenant is not active' using errcode = '42501';
    end if;

    insert into platform.approvals (
        approval_id, tenant_id, run_id, action, resource, reason, requested_by,
        status, metadata, expires_at, intent_fingerprint, trace_context
    ) values (
        p_approval_id, p_tenant_id, p_run_id, p_action, p_resource, p_reason, p_requested_by,
        'pending', normalized_metadata, p_expires_at, p_intent_fingerprint, p_trace_context
    );

    insert into platform.approval_events (
        event_id, tenant_id, approval_id, event_type, actor_subject_id,
        intent_fingerprint, metadata
    ) values (
        gen_random_uuid(), p_tenant_id, p_approval_id, 'requested', p_requested_by,
        p_intent_fingerprint, jsonb_build_object('reason', p_reason)
    );
    return p_approval_id;
end;
$$;

create or replace function platform.expire_approval_if_due(
    p_tenant_id uuid,
    p_approval_id uuid
) returns boolean
language plpgsql
security definer
set search_path = pg_catalog, platform
as $$
declare
    current_approval platform.approvals%rowtype;
begin
    if platform.current_tenant_id() is distinct from p_tenant_id then
        raise exception 'tenant scope mismatch' using errcode = '42501';
    end if;
    select * into current_approval
      from platform.approvals
     where tenant_id = p_tenant_id and approval_id = p_approval_id
     for update;
    if not found then
        return false;
    end if;
    if current_approval.status <> 'pending'
       or current_approval.expires_at is null
       or current_approval.expires_at > clock_timestamp() then
        return false;
    end if;

    update platform.approvals
       set status = 'expired',
           decided_at = clock_timestamp()
     where tenant_id = p_tenant_id and approval_id = p_approval_id;
    insert into platform.approval_events (
        event_id, tenant_id, approval_id, event_type, actor_subject_id,
        intent_fingerprint, metadata
    ) values (
        gen_random_uuid(), p_tenant_id, p_approval_id, 'expired', 'system:expiry',
        current_approval.intent_fingerprint, '{}'::jsonb
    );
    return true;
end;
$$;

create or replace function platform.decide_approval(
    p_tenant_id uuid,
    p_approval_id uuid,
    p_approved boolean,
    p_approver_subject_id text,
    p_intent_fingerprint text default null
) returns text
language plpgsql
security definer
set search_path = pg_catalog, platform
as $$
declare
    current_approval platform.approvals%rowtype;
    next_status text;
begin
    if platform.current_tenant_id() is distinct from p_tenant_id then
        raise exception 'tenant scope mismatch' using errcode = '42501';
    end if;
    if p_approved is null
       or p_approver_subject_id is null
       or length(trim(p_approver_subject_id)) not between 1 and 256
       or p_approver_subject_id <> btrim(p_approver_subject_id)
       or p_approver_subject_id ~ '[[:cntrl:]]'
       or (p_intent_fingerprint is not null and p_intent_fingerprint !~ '^[0-9a-f]{64}$') then
        raise exception 'invalid approval decision' using errcode = '22023';
    end if;

    perform platform.expire_approval_if_due(p_tenant_id, p_approval_id);
    select * into current_approval
      from platform.approvals
     where tenant_id = p_tenant_id and approval_id = p_approval_id
     for update;
    if not found then
        raise exception 'approval not found' using errcode = 'P0002';
    end if;
    if current_approval.status = 'expired' then
        return 'expired';
    end if;
    if current_approval.status <> 'pending' then
        raise exception 'approval is no longer pending' using errcode = '55000';
    end if;
    if p_intent_fingerprint is not null
       and current_approval.intent_fingerprint is distinct from p_intent_fingerprint then
        raise exception 'approval intent does not match' using errcode = '42501';
    end if;
    if p_approved and p_approver_subject_id = current_approval.requested_by then
        raise exception 'requester cannot approve the same consequential request' using errcode = '42501';
    end if;

    next_status := case when p_approved then 'approved' else 'rejected' end;
    update platform.approvals
       set status = next_status,
           decided_at = clock_timestamp(),
           approved_by = p_approver_subject_id
     where tenant_id = p_tenant_id and approval_id = p_approval_id;

    insert into platform.approval_events (
        event_id, tenant_id, approval_id, event_type, actor_subject_id,
        intent_fingerprint, metadata
    ) values (
        gen_random_uuid(), p_tenant_id, p_approval_id, next_status,
        p_approver_subject_id, current_approval.intent_fingerprint, '{}'::jsonb
    );
    return next_status;
end;
$$;

create or replace function platform.consume_approval(
    p_tenant_id uuid,
    p_approval_id uuid,
    p_run_id uuid,
    p_action text,
    p_resource text,
    p_intent_fingerprint text default null
) returns boolean
language plpgsql
security definer
set search_path = pg_catalog, platform
as $$
declare
    current_approval platform.approvals%rowtype;
begin
    if platform.current_tenant_id() is distinct from p_tenant_id then
        raise exception 'tenant scope mismatch' using errcode = '42501';
    end if;
    if p_run_id is null or p_action is null or p_action <> btrim(p_action)
       or p_resource is null or p_resource <> btrim(p_resource)
       or (p_intent_fingerprint is not null and p_intent_fingerprint !~ '^[0-9a-f]{64}$') then
        raise exception 'invalid approval binding' using errcode = '22023';
    end if;

    perform platform.expire_approval_if_due(p_tenant_id, p_approval_id);
    select * into current_approval
      from platform.approvals
     where tenant_id = p_tenant_id and approval_id = p_approval_id
     for update;
    if not found or current_approval.status <> 'approved' then
        return false;
    end if;
    if current_approval.run_id <> p_run_id
       or current_approval.action <> p_action
       or current_approval.resource <> p_resource
       or (
            p_intent_fingerprint is not null
            and current_approval.intent_fingerprint is distinct from p_intent_fingerprint
       ) then
        raise exception 'approval does not bind to this action' using errcode = '42501';
    end if;

    update platform.approvals
       set status = 'consumed',
           consumed_at = clock_timestamp()
     where tenant_id = p_tenant_id and approval_id = p_approval_id;
    insert into platform.approval_events (
        event_id, tenant_id, approval_id, event_type, actor_subject_id,
        intent_fingerprint, metadata
    ) values (
        gen_random_uuid(), p_tenant_id, p_approval_id, 'consumed',
        current_approval.requested_by, current_approval.intent_fingerprint, '{}'::jsonb
    );
    return true;
end;
$$;

alter function platform.request_approval(uuid, uuid, uuid, text, text, text, text, jsonb, timestamptz, text, jsonb)
    owner to platform_approval_executor;
alter function platform.expire_approval_if_due(uuid, uuid)
    owner to platform_approval_executor;
alter function platform.decide_approval(uuid, uuid, boolean, text, text)
    owner to platform_approval_executor;
alter function platform.consume_approval(uuid, uuid, uuid, text, text, text)
    owner to platform_approval_executor;

revoke all on function platform.request_approval(uuid, uuid, uuid, text, text, text, text, jsonb, timestamptz, text, jsonb) from public;
revoke all on function platform.expire_approval_if_due(uuid, uuid) from public;
revoke all on function platform.decide_approval(uuid, uuid, boolean, text, text) from public;
revoke all on function platform.consume_approval(uuid, uuid, uuid, text, text, text) from public;

grant execute on function platform.request_approval(uuid, uuid, uuid, text, text, text, text, jsonb, timestamptz, text, jsonb)
    to platform_approval_client;
grant execute on function platform.expire_approval_if_due(uuid, uuid)
    to platform_approval_client;
grant execute on function platform.decide_approval(uuid, uuid, boolean, text, text)
    to platform_approval_client;
grant execute on function platform.consume_approval(uuid, uuid, uuid, text, text, text)
    to platform_approval_client;
