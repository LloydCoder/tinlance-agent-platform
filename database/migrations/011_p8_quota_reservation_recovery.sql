-- P8 recovery hardening: expired leases are flagged for reconciliation, never
-- silently refunded. A crashed worker may have completed a consequential side effect.
alter table platform.quota_reservations
    add column if not exists lease_expires_at timestamptz not null default (now() + interval '15 minutes'),
    add column if not exists recovery_requested_at timestamptz,
    add column if not exists recovery_attempts integer not null default 0
        check (recovery_attempts >= 0);

create index if not exists idx_quota_reservations_expiry
    on platform.quota_reservations(tenant_id, lease_expires_at)
    where state = 'reserved' and recovery_requested_at is null;

alter table platform.quota_ledger
    drop constraint if exists quota_ledger_event_type_check;
alter table platform.quota_ledger
    add constraint quota_ledger_event_type_check
    check (event_type in ('reserved', 'settled', 'released', 'overrun', 'recovery_requested'));

create or replace function platform.renew_quota_reservation(
    p_tenant_id uuid,
    p_reservation_id uuid,
    p_lease_seconds integer default 900
) returns timestamptz
language plpgsql
security invoker
set search_path = pg_catalog, platform
as $$
declare
    reservation platform.quota_reservations%rowtype;
    new_expiry timestamptz;
begin
    if platform.current_tenant_id() is distinct from p_tenant_id then
        raise exception 'tenant scope mismatch' using errcode = '42501';
    end if;
    if p_lease_seconds is null or p_lease_seconds < 60 or p_lease_seconds > 3600 then
        raise exception 'lease duration must be between 60 and 3600 seconds' using errcode = '22023';
    end if;

    select * into reservation
      from platform.quota_reservations
     where tenant_id = p_tenant_id and reservation_id = p_reservation_id
     for update;
    if not found then
        raise exception 'reservation not found' using errcode = 'P0002';
    end if;
    if reservation.state <> 'reserved'
       or reservation.lease_expires_at <= now()
       or reservation.recovery_requested_at is not null then
        raise exception 'reservation is expired or requires reconciliation' using errcode = '55000';
    end if;

    new_expiry := now() + make_interval(secs => p_lease_seconds);
    update platform.quota_reservations
       set lease_expires_at = new_expiry
     where tenant_id = p_tenant_id and reservation_id = p_reservation_id;
    return new_expiry;
end;
$$;

-- A lease expiry is a reconciliation signal, not a refund. The reservation
-- remains reserved and continues consuming its quota until settle/release is
-- resolved with evidence. SKIP LOCKED allows multiple tenant-scoped sweepers.
create or replace function platform.request_expired_quota_reconciliation(
    p_tenant_id uuid,
    p_limit integer default 100
) returns integer
language plpgsql
security invoker
set search_path = pg_catalog, platform
as $$
declare
    requested_count integer;
begin
    if platform.current_tenant_id() is distinct from p_tenant_id then
        raise exception 'tenant scope mismatch' using errcode = '42501';
    end if;
    if p_limit is null or p_limit < 1 or p_limit > 1000 then
        raise exception 'reconciliation batch limit must be between 1 and 1000' using errcode = '22023';
    end if;

    with expired as (
        select q.reservation_id
          from platform.quota_reservations q
         where q.tenant_id = p_tenant_id
           and q.state = 'reserved'
           and q.lease_expires_at <= now()
           and q.recovery_requested_at is null
         order by q.lease_expires_at, q.reservation_id
         for update skip locked
         limit p_limit
    ), marked as (
        update platform.quota_reservations q
           set recovery_requested_at = now(),
               recovery_attempts = q.recovery_attempts + 1
          from expired e
         where q.tenant_id = p_tenant_id
           and q.reservation_id = e.reservation_id
        returning q.*
    )
    insert into platform.quota_ledger(
        ledger_id, tenant_id, organization_id, reservation_id, run_id, event_type,
        tool_calls, token_units, cost_units, idempotency_key, evidence
    )
    select gen_random_uuid(), m.tenant_id, m.organization_id, m.reservation_id, m.run_id,
           'recovery_requested', 0, 0, 0, m.idempotency_key,
           jsonb_build_object(
               'cancellation_reason', 'lease-expired',
               'source_event_id', m.idempotency_key
           )
      from marked m;

    get diagnostics requested_count = row_count;
    return requested_count;
end;
$$;

revoke all on function platform.renew_quota_reservation(uuid, uuid, integer) from public;
revoke all on function platform.request_expired_quota_reconciliation(uuid, integer) from public;
