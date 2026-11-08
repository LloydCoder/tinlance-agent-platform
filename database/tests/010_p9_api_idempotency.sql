begin;

create role p9_idempotency_app nologin;
grant usage on schema platform to p9_idempotency_app;
grant select, insert, update on platform.api_idempotency_records to p9_idempotency_app;

insert into platform.tenants (tenant_id, name) values
('00000000-0000-0000-0000-000000000091', 'p9-idempotency-tenant-a'),
('00000000-0000-0000-0000-000000000092', 'p9-idempotency-tenant-b')
on conflict (tenant_id) do nothing;

set role p9_idempotency_app;
select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000091', true);

insert into platform.api_idempotency_records (
    tenant_id, subject_id, idempotency_key, operation, request_fingerprint,
    status, lease_expires_at
) values (
    '00000000-0000-0000-0000-000000000091',
    'user-a', 'durable-replay-key-0001',
    'extensions.outbox.dead_letter.replay', repeat('b', 64),
    'processing', now() + interval '5 minutes'
);

do $$
declare inserted integer;
begin
    insert into platform.api_idempotency_records (
        tenant_id, subject_id, idempotency_key, operation, request_fingerprint,
        status, lease_expires_at
    ) values (
        '00000000-0000-0000-0000-000000000091',
        'user-a', 'durable-replay-key-0001',
        'extensions.outbox.dead_letter.replay', repeat('b', 64),
        'processing', now() + interval '5 minutes'
    )
    on conflict (tenant_id, subject_id, idempotency_key) do nothing;
    get diagnostics inserted = row_count;
    if inserted <> 0 then
        raise exception 'duplicate idempotency reservation was inserted';
    end if;
end
$$;

update platform.api_idempotency_records
   set status = 'completed',
       response_status = 'success',
       response_payload = '{"status":"requeued"}'::jsonb,
       lease_expires_at = null,
       completed_at = now(),
       updated_at = now()
 where tenant_id = '00000000-0000-0000-0000-000000000091'
   and subject_id = 'user-a'
   and idempotency_key = 'durable-replay-key-0001'
   and status = 'processing';

do $$
begin
    if (select response_payload->>'status'
        from platform.api_idempotency_records
        where idempotency_key = 'durable-replay-key-0001') <> 'requeued' then
        raise exception 'completed idempotency response was not durable';
    end if;
end
$$;

insert into platform.api_idempotency_records (
    tenant_id, subject_id, idempotency_key, operation, request_fingerprint,
    status, lease_expires_at
) values (
    '00000000-0000-0000-0000-000000000091',
    'user-a', 'durable-unknown-key-0001',
    'extensions.outbox.dead_letter.replay', repeat('c', 64),
    'processing', now() - interval '1 second'
);

update platform.api_idempotency_records
   set status = 'outcome_unknown', lease_expires_at = null, updated_at = now()
 where idempotency_key = 'durable-unknown-key-0001'
   and status = 'processing';
do $$
begin
    if (select status from platform.api_idempotency_records
        where idempotency_key = 'durable-unknown-key-0001') <> 'outcome_unknown' then
        raise exception 'expired processing reservation was not fenced as unknown';
    end if;
end
$$;

select set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000092', true);
do $$
begin
    if exists (
        select 1 from platform.api_idempotency_records
        where tenant_id = '00000000-0000-0000-0000-000000000091'
    ) then
        raise exception 'cross-tenant idempotency visibility detected';
    end if;
end
$$;

insert into platform.api_idempotency_records (
    tenant_id, subject_id, idempotency_key, operation, request_fingerprint,
    status, lease_expires_at
) values (
    '00000000-0000-0000-0000-000000000092',
    'user-a', 'durable-replay-key-0001',
    'extensions.outbox.dead_letter.replay', repeat('b', 64),
    'processing', now() + interval '5 minutes'
);

rollback;
