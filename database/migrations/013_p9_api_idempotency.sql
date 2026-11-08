-- Durable idempotency state for guarded API operations across Platform replicas.
CREATE TABLE IF NOT EXISTS platform.api_idempotency_records (
    tenant_id uuid NOT NULL REFERENCES platform.tenants(tenant_id),
    subject_id text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 512),
    idempotency_key text NOT NULL CHECK (
        length(idempotency_key) BETWEEN 1 AND 256
        AND idempotency_key !~ '[^!-~]'
    ),
    operation text NOT NULL CHECK (length(operation) BETWEEN 1 AND 256),
    request_fingerprint text NOT NULL CHECK (request_fingerprint ~ '^[0-9a-f]{64}$'),
    status text NOT NULL CHECK (status IN ('processing', 'completed', 'outcome_unknown')),
    response_status text,
    response_payload jsonb,
    lease_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '30 days'),
    PRIMARY KEY (tenant_id, subject_id, idempotency_key),
    CHECK (
        (status = 'completed')
        = (
            response_status IS NOT NULL
            AND response_payload IS NOT NULL
            AND completed_at IS NOT NULL
        )
    ),
    CHECK (response_payload IS NULL OR jsonb_typeof(response_payload) = 'object'),
    CHECK ((status = 'processing') = (lease_expires_at IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_api_idempotency_expiry
    ON platform.api_idempotency_records (tenant_id, expires_at)
    WHERE status = 'completed';
CREATE INDEX IF NOT EXISTS idx_api_idempotency_processing_lease
    ON platform.api_idempotency_records (tenant_id, lease_expires_at)
    WHERE status = 'processing';

ALTER TABLE platform.api_idempotency_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.api_idempotency_records FORCE ROW LEVEL SECURITY;
CREATE POLICY api_idempotency_tenant_isolation ON platform.api_idempotency_records
    USING (tenant_id = platform.current_tenant_id())
    WITH CHECK (tenant_id = platform.current_tenant_id());
