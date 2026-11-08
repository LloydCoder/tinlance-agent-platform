-- Durable idempotency state for guarded API operations across Platform replicas.
create table if not exists platform.api_idempotency_records (
    tenant_id uuid not null references platform.tenants(tenant_id),
    subject_id text not null check (length(subject_id) between 1 and 512),
    idempotency_key text not null check (
        length(idempotency_key) between 1 and 256
        and idempotency_key !~ '[[:cntrl:]]'
    ),
    operation text not null check (length(operation) between 1 and 256),
    request_fingerprint text not null check (request_fingerprint ~ '^[0-9a-f]{64}$'),
    status text not null check (status in ('processing', 'completed', 'outcome_unknown')),
    response_status text,
    response_payload jsonb,
    lease_expires_at timestamptz,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now(),
    completed_at timestamptz,
    expires_at timestamptz not null default (now() + interval '30 days'),
    primary key (tenant_id, subject_id, idempotency_key),
    check (
        (status = 'completed')
        = (response_status is not null and response_payload is not null and completed_at is not null)
    ),
    check (
        response_payload is null or jsonb_typeof(response_payload) = 'object'
    ),
    check (
        (status = 'processing') = (lease_expires_at is not null)
    )
);

create index if not exists idx_api_idempotency_expiry
    on platform.api_idempotency_records (tenant_id, expires_at)
    where status = 'completed';
create index if not exists idx_api_idempotency_processing_lease
    on platform.api_idempotency_records (tenant_id, lease_expires_at)
    where status = 'processing';

alter table platform.api_idempotency_records enable row level security;
alter table platform.api_idempotency_records force row level security;
create policy api_idempotency_tenant_isolation on platform.api_idempotency_records
    using (tenant_id = platform.current_tenant_id())
    with check (tenant_id = platform.current_tenant_id());
