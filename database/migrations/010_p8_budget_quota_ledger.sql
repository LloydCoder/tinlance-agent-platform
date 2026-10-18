-- P8: transactional budget/quota ledger. Apply as a versioned migration.
-- The calling Platform transaction must set platform.tenant_id before invoking
-- any quota function. Lock order is tenant limit then organization limit.
create table if not exists platform.organizations (
    organization_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    name text not null check (length(trim(name)) > 0),
    status text not null default 'active'
        check (status in ('active', 'suspended', 'disabled')),
    created_at timestamptz not null default now(),
    unique (tenant_id, organization_id)
);

create table if not exists platform.tenant_budget_limits (
    tenant_id uuid primary key references platform.tenants(tenant_id),
    max_concurrency integer not null check (max_concurrency > 0),
    max_tool_calls bigint not null check (max_tool_calls >= 0),
    max_token_units bigint not null check (max_token_units >= 0),
    max_cost_units numeric(20, 6) not null check (max_cost_units >= 0 and max_cost_units::text <> 'NaN'),
    used_tool_calls bigint not null default 0 check (used_tool_calls >= 0),
    used_token_units bigint not null default 0 check (used_token_units >= 0),
    used_cost_units numeric(20, 6) not null default 0 check (used_cost_units >= 0 and used_cost_units::text <> 'NaN'),
    version bigint not null default 1 check (version > 0),
    updated_at timestamptz not null default now()
);

create table if not exists platform.organization_budget_limits (
    tenant_id uuid not null,
    organization_id uuid not null,
    max_concurrency integer not null check (max_concurrency > 0),
    max_tool_calls bigint not null check (max_tool_calls >= 0),
    max_token_units bigint not null check (max_token_units >= 0),
    max_cost_units numeric(20, 6) not null check (max_cost_units >= 0),
    used_tool_calls bigint not null default 0 check (used_tool_calls >= 0),
    used_token_units bigint not null default 0 check (used_token_units >= 0),
    used_cost_units numeric(20, 6) not null default 0 check (used_cost_units >= 0),
    version bigint not null default 1 check (version > 0),
    updated_at timestamptz not null default now(),
    primary key (tenant_id, organization_id),
    foreign key (tenant_id, organization_id)
        references platform.organizations(tenant_id, organization_id)
);

create table if not exists platform.quota_reservations (
    reservation_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    organization_id uuid,
    agent_id uuid not null,
    run_id uuid not null,
    action text not null check (length(trim(action)) between 1 and 256 and action !~ '[[:cntrl:]]'),
    resource text not null check (length(trim(resource)) between 1 and 256 and resource !~ '[[:cntrl:]]'),
    idempotency_key text not null check (
        length(idempotency_key) between 16 and 256
    ),
    reserved_concurrency integer not null check (reserved_concurrency > 0),
    reserved_tool_calls bigint not null check (reserved_tool_calls >= 0),
    reserved_token_units bigint not null check (reserved_token_units >= 0),
    reserved_cost_units numeric(20, 6) not null check (reserved_cost_units >= 0 and reserved_cost_units::text <> 'NaN'),
    actual_tool_calls bigint,
    actual_token_units bigint,
    actual_cost_units numeric(20, 6),
    state text not null default 'reserved'
        check (state in ('reserved', 'settled', 'released')),
    created_at timestamptz not null default now(),
    settled_at timestamptz,
    released_at timestamptz,
    unique (tenant_id, idempotency_key),
    unique (tenant_id, reservation_id),
    foreign key (tenant_id, organization_id)
        references platform.organizations(tenant_id, organization_id),
    foreign key (tenant_id, agent_id)
        references platform.agents(tenant_id, agent_id),
    foreign key (tenant_id, run_id)
        references platform.runs(tenant_id, run_id),
    check (
        (state = 'reserved' and settled_at is null and released_at is null
            and actual_tool_calls is null and actual_token_units is null and actual_cost_units is null)
        or (state = 'settled' and settled_at is not null and released_at is null
            and actual_tool_calls is not null and actual_tool_calls >= 0
            and actual_token_units is not null and actual_token_units >= 0
            and actual_cost_units is not null and actual_cost_units >= 0)
        or (state = 'released' and released_at is not null and settled_at is null
            and actual_tool_calls is null and actual_token_units is null and actual_cost_units is null)
    )
);

create index if not exists idx_quota_reservations_active_tenant
    on platform.quota_reservations(tenant_id, state, created_at);
create index if not exists idx_quota_reservations_active_org
    on platform.quota_reservations(tenant_id, organization_id, state, created_at);

-- Immutable cost/audit trail. State transitions remain on the reservation row;
-- each transition and the exact usage is captured as an append-only ledger fact.
create table if not exists platform.quota_ledger (
    ledger_id uuid primary key,
    tenant_id uuid not null references platform.tenants(tenant_id),
    organization_id uuid,
    reservation_id uuid not null,
    run_id uuid not null,
    event_type text not null check (
        event_type in ('reserved', 'settled', 'released', 'overrun')
    ),
    tool_calls bigint not null check (tool_calls >= 0),
    token_units bigint not null check (token_units >= 0),
    cost_units numeric(20, 6) not null check (cost_units >= 0 and cost_units::text <> 'NaN'),
    idempotency_key text not null,
    evidence jsonb not null default '{}'::jsonb,
    occurred_at timestamptz not null default now(),
    unique (tenant_id, reservation_id, event_type),
    foreign key (tenant_id, reservation_id)
        references platform.quota_reservations(tenant_id, reservation_id),
    foreign key (tenant_id, organization_id)
        references platform.organizations(tenant_id, organization_id),
    foreign key (tenant_id, run_id)
        references platform.runs(tenant_id, run_id)
);

alter table platform.organizations enable row level security;
alter table platform.organizations force row level security;
alter table platform.tenant_budget_limits enable row level security;
alter table platform.tenant_budget_limits force row level security;
alter table platform.organization_budget_limits enable row level security;
alter table platform.organization_budget_limits force row level security;
alter table platform.quota_reservations enable row level security;
alter table platform.quota_reservations force row level security;
alter table platform.quota_ledger enable row level security;
alter table platform.quota_ledger force row level security;

create policy organizations_tenant_isolation on platform.organizations
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy tenant_budget_limits_isolation on platform.tenant_budget_limits
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy organization_budget_limits_isolation on platform.organization_budget_limits
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy quota_reservations_tenant_isolation on platform.quota_reservations
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
create policy quota_ledger_tenant_isolation on platform.quota_ledger
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());

revoke update, delete, truncate on platform.quota_ledger from public;

-- Defense in depth: broader application grants must not make the ledger mutable.
create or replace function platform.reject_quota_ledger_mutation()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog, platform
as $$
begin
    raise exception 'quota ledger is append-only' using errcode = '42501';
end;
$$;

create trigger quota_ledger_append_only
before update or delete on platform.quota_ledger
for each row execute function platform.reject_quota_ledger_mutation();
create trigger quota_ledger_no_truncate
before truncate on platform.quota_ledger
for each statement execute function platform.reject_quota_ledger_mutation();

-- Usage evidence is deliberately metadata-only; arbitrary prompts, payloads,
-- credentials and nested provider responses must never be copied into the ledger.
create or replace function platform.quota_evidence_is_safe(p_evidence jsonb)
returns boolean
language sql
immutable
set search_path = pg_catalog, platform
as $$
    select jsonb_typeof(coalesce(p_evidence, '{}'::jsonb)) = 'object'
       and octet_length(coalesce(p_evidence, '{}'::jsonb)::text) <= 4096
       and not exists (
           select 1
             from jsonb_each(coalesce(p_evidence, '{}'::jsonb)) as item(key, value)
            where item.key not in (
                'provider', 'model', 'price_book_version', 'measurement_ref',
                'source_event_id', 'cancellation_reason', 'metering_source',
                'billing_unit', 'policy_ref', 'correlation_id', 'trace_id',
                'traceparent'
            )
               or jsonb_typeof(item.value) not in ('string', 'number', 'boolean')
               or (jsonb_typeof(item.value) = 'string' and length(item.value #>> '{}') > 512)
               or (item.key = 'cancellation_reason' and (jsonb_typeof(item.value) <> 'string'
                   or item.value #>> '{}' !~ '^[a-z0-9][a-z0-9._:-]{0,127}$'))
       )
$$;

alter table platform.quota_ledger
    add constraint quota_ledger_safe_evidence
    check (platform.quota_evidence_is_safe(evidence));

-- Reservation admission serializes on limit rows so concurrent workers cannot
-- oversubscribe either tenant or organization limits.
create or replace function platform.reserve_quota(
    p_reservation_id uuid,
    p_tenant_id uuid,
    p_organization_id uuid,
    p_agent_id uuid,
    p_run_id uuid,
    p_action text,
    p_resource text,
    p_idempotency_key text,
    p_concurrency integer,
    p_tool_calls bigint,
    p_token_units bigint,
    p_cost_units numeric
) returns uuid
language plpgsql
security invoker
set search_path = pg_catalog, platform
as $$
declare
    tenant_limit platform.tenant_budget_limits%rowtype;
    org_limit platform.organization_budget_limits%rowtype;
    existing platform.quota_reservations%rowtype;
    reserved_concurrency bigint;
    reserved_calls bigint;
    reserved_tokens bigint;
    reserved_cost numeric(20, 6);
begin
    if platform.current_tenant_id() is distinct from p_tenant_id then
        raise exception 'tenant scope mismatch' using errcode = '42501';
    end if;
    if p_concurrency is null or p_concurrency < 1
       or p_tool_calls is null or p_tool_calls < 0
       or p_token_units is null or p_token_units < 0
       or p_cost_units is null or p_cost_units < 0 or p_cost_units::text in ('NaN', 'Infinity', '-Infinity')
       or p_action is null or length(trim(p_action)) not between 1 and 256
       or p_action <> btrim(p_action) or p_action ~ '[[:cntrl:]]'
       or p_resource is null or length(trim(p_resource)) not between 1 and 256
       or p_resource <> btrim(p_resource) or p_resource ~ '[[:cntrl:]]'
       or p_idempotency_key is null
       or length(p_idempotency_key) not between 16 and 256
       or p_idempotency_key <> btrim(p_idempotency_key)
       or p_idempotency_key ~ '[[:cntrl:]]' then
        raise exception 'invalid quota reservation' using errcode = '22023';
    end if;

    select * into tenant_limit from platform.tenant_budget_limits
     where tenant_id = p_tenant_id for update;
    if not found then
        raise exception 'tenant budget limits are not configured' using errcode = 'P0002';
    end if;

    if not exists (
        select 1 from platform.tenants
         where tenant_id = p_tenant_id and status = 'active'
    ) then
        raise exception 'tenant is not active' using errcode = '42501';
    end if;

    select * into existing from platform.quota_reservations
     where tenant_id = p_tenant_id and idempotency_key = p_idempotency_key
     for update;
    if found then
        if existing.organization_id is not distinct from p_organization_id
           and existing.agent_id = p_agent_id and existing.run_id = p_run_id
           and existing.action = p_action and existing.resource = p_resource
           and existing.reserved_concurrency = p_concurrency
           and existing.reserved_tool_calls = p_tool_calls
           and existing.reserved_token_units = p_token_units
           and existing.reserved_cost_units = p_cost_units then
            -- Return the original reservation for every identical replay,
            -- regardless of its current state. Callers must inspect that state
            -- before starting work; a retry must never create duplicate capacity.
            return existing.reservation_id;
        end if;
        raise exception 'idempotency key conflicts with existing reservation' using errcode = '23505';
    end if;

    if p_organization_id is not null then
        select * into org_limit from platform.organization_budget_limits
         where tenant_id = p_tenant_id and organization_id = p_organization_id for update;
        if not found then
            raise exception 'organization budget limits are not configured' using errcode = 'P0002';
        end if;
        if not exists (
            select 1 from platform.organizations
             where tenant_id = p_tenant_id and organization_id = p_organization_id and status = 'active'
        ) then
            raise exception 'organization is not active' using errcode = '42501';
        end if;
    end if;

    select coalesce(sum(qr.reserved_concurrency), 0),
           coalesce(sum(qr.reserved_tool_calls), 0),
           coalesce(sum(qr.reserved_token_units), 0),
           coalesce(sum(qr.reserved_cost_units), 0)
      into reserved_concurrency, reserved_calls, reserved_tokens, reserved_cost
      from platform.quota_reservations qr
     where qr.tenant_id = p_tenant_id and qr.state = 'reserved';

    if tenant_limit.used_tool_calls + reserved_calls + p_tool_calls > tenant_limit.max_tool_calls
       or tenant_limit.used_token_units + reserved_tokens + p_token_units > tenant_limit.max_token_units
       or tenant_limit.used_cost_units + reserved_cost + p_cost_units > tenant_limit.max_cost_units
       or reserved_concurrency + p_concurrency > tenant_limit.max_concurrency then
        raise exception 'tenant quota exhausted' using errcode = 'P0001';
    end if;

    if p_organization_id is not null then
        select coalesce(sum(qr.reserved_concurrency), 0),
               coalesce(sum(qr.reserved_tool_calls), 0),
               coalesce(sum(qr.reserved_token_units), 0),
               coalesce(sum(qr.reserved_cost_units), 0)
          into reserved_concurrency, reserved_calls, reserved_tokens, reserved_cost
          from platform.quota_reservations qr
         where qr.tenant_id = p_tenant_id and qr.organization_id = p_organization_id
           and qr.state = 'reserved';
        if org_limit.used_tool_calls + reserved_calls + p_tool_calls > org_limit.max_tool_calls
           or org_limit.used_token_units + reserved_tokens + p_token_units > org_limit.max_token_units
           or org_limit.used_cost_units + reserved_cost + p_cost_units > org_limit.max_cost_units
           or reserved_concurrency + p_concurrency > org_limit.max_concurrency then
            raise exception 'organization quota exhausted' using errcode = 'P0001';
        end if;
    end if;

    insert into platform.quota_reservations (
        reservation_id, tenant_id, organization_id, agent_id, run_id, action, resource,
        idempotency_key, reserved_concurrency, reserved_tool_calls, reserved_token_units,
        reserved_cost_units
    ) values (
        p_reservation_id, p_tenant_id, p_organization_id, p_agent_id, p_run_id, p_action, p_resource,
        p_idempotency_key, p_concurrency, p_tool_calls, p_token_units, p_cost_units
    );

    insert into platform.quota_ledger (
        ledger_id, tenant_id, organization_id, reservation_id, run_id, event_type,
        tool_calls, token_units, cost_units, idempotency_key, evidence
    ) values (
        gen_random_uuid(), p_tenant_id, p_organization_id, p_reservation_id, p_run_id, 'reserved',
        p_tool_calls, p_token_units, p_cost_units, p_idempotency_key, '{}'::jsonb
    );
    return p_reservation_id;
end;
$$;

create or replace function platform.settle_quota(
    p_tenant_id uuid,
    p_reservation_id uuid,
    p_actual_tool_calls bigint,
    p_actual_token_units bigint,
    p_actual_cost_units numeric,
    p_evidence jsonb default '{}'::jsonb
) returns text
language plpgsql
security invoker
set search_path = pg_catalog, platform
as $$
declare
    reservation platform.quota_reservations%rowtype;
    tenant_limit platform.tenant_budget_limits%rowtype;
    org_limit platform.organization_budget_limits%rowtype;
    other_calls bigint;
    other_tokens bigint;
    other_cost numeric(20, 6);
    event_kind text := 'settled';
begin
    if platform.current_tenant_id() is distinct from p_tenant_id then
        raise exception 'tenant scope mismatch' using errcode = '42501';
    end if;
    if p_actual_tool_calls is null or p_actual_tool_calls < 0
       or p_actual_token_units is null or p_actual_token_units < 0
       or p_actual_cost_units is null or p_actual_cost_units < 0
       or p_actual_cost_units::text in ('NaN', 'Infinity', '-Infinity')
       or not platform.quota_evidence_is_safe(p_evidence) then
        raise exception 'invalid settlement amounts' using errcode = '22023';
    end if;

    select * into tenant_limit from platform.tenant_budget_limits
     where tenant_id = p_tenant_id for update;
    if not found then raise exception 'tenant budget limits are not configured' using errcode = 'P0002'; end if;
    select * into reservation from platform.quota_reservations
     where tenant_id = p_tenant_id and reservation_id = p_reservation_id for update;
    if not found then raise exception 'reservation not found' using errcode = 'P0002'; end if;
    if reservation.state = 'settled' then
        if reservation.actual_tool_calls = p_actual_tool_calls
           and reservation.actual_token_units = p_actual_token_units
           and reservation.actual_cost_units = p_actual_cost_units then
            return 'already_settled';
        end if;
        raise exception 'conflicting duplicate settlement' using errcode = '23505';
    end if;
    if reservation.state <> 'reserved' then
        raise exception 'released reservation cannot be settled' using errcode = '55000';
    end if;

    if reservation.organization_id is not null then
        select * into org_limit from platform.organization_budget_limits
         where tenant_id = p_tenant_id and organization_id = reservation.organization_id for update;
    end if;

    select coalesce(sum(qr.reserved_tool_calls), 0), coalesce(sum(qr.reserved_token_units), 0),
           coalesce(sum(qr.reserved_cost_units), 0)
      into other_calls, other_tokens, other_cost
      from platform.quota_reservations qr
     where qr.tenant_id = p_tenant_id and qr.state = 'reserved'
       and qr.reservation_id <> p_reservation_id;
    if tenant_limit.used_tool_calls + other_calls + p_actual_tool_calls > tenant_limit.max_tool_calls
       or tenant_limit.used_token_units + other_tokens + p_actual_token_units > tenant_limit.max_token_units
       or tenant_limit.used_cost_units + other_cost + p_actual_cost_units > tenant_limit.max_cost_units then
        event_kind := 'overrun';
    end if;

    if reservation.organization_id is not null then
        select coalesce(sum(qr.reserved_tool_calls), 0), coalesce(sum(qr.reserved_token_units), 0),
               coalesce(sum(qr.reserved_cost_units), 0)
          into other_calls, other_tokens, other_cost
          from platform.quota_reservations qr
         where qr.tenant_id = p_tenant_id and qr.organization_id = reservation.organization_id
           and qr.state = 'reserved' and qr.reservation_id <> p_reservation_id;
        if org_limit.used_tool_calls + other_calls + p_actual_tool_calls > org_limit.max_tool_calls
           or org_limit.used_token_units + other_tokens + p_actual_token_units > org_limit.max_token_units
           or org_limit.used_cost_units + other_cost + p_actual_cost_units > org_limit.max_cost_units then
            event_kind := 'overrun';
        end if;
    end if;

    -- Record actual usage even on overrun; the caller must stop subsequent work.
    update platform.tenant_budget_limits
       set used_tool_calls = used_tool_calls + p_actual_tool_calls,
           used_token_units = used_token_units + p_actual_token_units,
           used_cost_units = used_cost_units + p_actual_cost_units,
           version = version + 1, updated_at = now()
     where tenant_id = p_tenant_id;
    if reservation.organization_id is not null then
        update platform.organization_budget_limits
           set used_tool_calls = used_tool_calls + p_actual_tool_calls,
               used_token_units = used_token_units + p_actual_token_units,
               used_cost_units = used_cost_units + p_actual_cost_units,
               version = version + 1, updated_at = now()
         where tenant_id = p_tenant_id and organization_id = reservation.organization_id;
    end if;

    update platform.quota_reservations
       set state = 'settled', actual_tool_calls = p_actual_tool_calls,
           actual_token_units = p_actual_token_units, actual_cost_units = p_actual_cost_units,
           settled_at = now()
     where tenant_id = p_tenant_id and reservation_id = p_reservation_id;

    insert into platform.quota_ledger (
        ledger_id, tenant_id, organization_id, reservation_id, run_id, event_type,
        tool_calls, token_units, cost_units, idempotency_key, evidence
    ) values (
        gen_random_uuid(), p_tenant_id, reservation.organization_id, p_reservation_id, reservation.run_id,
        event_kind, p_actual_tool_calls, p_actual_token_units, p_actual_cost_units,
        reservation.idempotency_key, coalesce(p_evidence, '{}'::jsonb)
    );
    if event_kind = 'overrun' then
        return 'overrun';
    end if;
    return 'settled';
end;
$$;

create or replace function platform.release_quota(
    p_tenant_id uuid,
    p_reservation_id uuid,
    p_reason text,
    p_evidence jsonb default '{}'::jsonb
) returns boolean
language plpgsql
security invoker
set search_path = pg_catalog, platform
as $$
declare
    reservation platform.quota_reservations%rowtype;
begin
    if platform.current_tenant_id() is distinct from p_tenant_id then
        raise exception 'tenant scope mismatch' using errcode = '42501';
    end if;
    if p_reason is null or p_reason !~ '^[a-z0-9][a-z0-9._:-]{0,127}$'
       or not platform.quota_evidence_is_safe(p_evidence) then
        raise exception 'release reason or evidence is invalid' using errcode = '22023';
    end if;
    perform 1 from platform.tenant_budget_limits
     where tenant_id = p_tenant_id for update;
    if not found then raise exception 'tenant budget limits are not configured' using errcode = 'P0002'; end if;
    select * into reservation from platform.quota_reservations
     where tenant_id = p_tenant_id and reservation_id = p_reservation_id for update;
    if not found then raise exception 'reservation not found' using errcode = 'P0002'; end if;
    if reservation.state = 'released' then return false; end if;
    if reservation.state <> 'reserved' then
        raise exception 'settled reservation cannot be released' using errcode = '55000';
    end if;
    update platform.quota_reservations
       set state = 'released', released_at = now()
     where tenant_id = p_tenant_id and reservation_id = p_reservation_id;
    insert into platform.quota_ledger (
        ledger_id, tenant_id, organization_id, reservation_id, run_id, event_type,
        tool_calls, token_units, cost_units, idempotency_key, evidence
    ) values (
        gen_random_uuid(), p_tenant_id, reservation.organization_id, p_reservation_id, reservation.run_id,
        'released', 0, 0, 0, reservation.idempotency_key,
        coalesce(p_evidence, '{}'::jsonb) || jsonb_build_object('cancellation_reason', p_reason)
    );
    return true;
end;
$$;

-- Only the Platform runtime role should execute these procedures in production.
revoke all on function platform.reserve_quota(uuid, uuid, uuid, uuid, uuid, text, text, text, integer, bigint, bigint, numeric) from public;
revoke all on function platform.settle_quota(uuid, uuid, bigint, bigint, numeric, jsonb) from public;
revoke all on function platform.release_quota(uuid, uuid, text, jsonb) from public;
