-- W6 durable restore idempotency, tenant isolation and append-only evidence.
CREATE TABLE IF NOT EXISTS platform.workspace_restore_operations (
    tenant_id uuid NOT NULL REFERENCES platform.tenants(tenant_id),
    workspace_id uuid NOT NULL,
    restore_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    status text NOT NULL CHECK (status IN ('started', 'completed', 'failed')),
    snapshot_digest text CHECK (
        snapshot_digest IS NULL OR snapshot_digest ~ '^[0-9a-f]{64}$'
    ),
    failure_code text CHECK (
        failure_code IS NULL OR failure_code ~ '^[A-Za-z][A-Za-z0-9_]{0,63}$'
    ),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    completed_at timestamptz,
    PRIMARY KEY (tenant_id, restore_id),
    FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES platform.workspace_leases (tenant_id, workspace_id),
    CHECK ((status = 'completed') = (completed_at IS NOT NULL)),
    CHECK ((status = 'completed') = (snapshot_digest IS NOT NULL)),
    CHECK ((status = 'failed') = (failure_code IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_workspace_restore_operations_workspace
    ON platform.workspace_restore_operations (tenant_id, workspace_id, created_at DESC);

CREATE TABLE IF NOT EXISTS platform.workspace_restore_events (
    event_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    restore_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    event_type text NOT NULL CHECK (event_type IN ('started', 'completed', 'failed')),
    snapshot_digest text CHECK (
        snapshot_digest IS NULL OR snapshot_digest ~ '^[0-9a-f]{64}$'
    ),
    failure_code text CHECK (
        failure_code IS NULL OR failure_code ~ '^[A-Za-z][A-Za-z0-9_]{0,63}$'
    ),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id, restore_id)
        REFERENCES platform.workspace_restore_operations (tenant_id, restore_id)
);

CREATE INDEX IF NOT EXISTS idx_workspace_restore_events_history
    ON platform.workspace_restore_events (tenant_id, workspace_id, occurred_at, event_id);

ALTER TABLE platform.workspace_restore_operations ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.workspace_restore_operations FORCE ROW LEVEL SECURITY;
ALTER TABLE platform.workspace_restore_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.workspace_restore_events FORCE ROW LEVEL SECURITY;

CREATE POLICY workspace_restore_operations_tenant_isolation
    ON platform.workspace_restore_operations
    USING (tenant_id = platform.current_tenant_id())
    WITH CHECK (tenant_id = platform.current_tenant_id());

CREATE POLICY workspace_restore_events_tenant_isolation
    ON platform.workspace_restore_events
    USING (tenant_id = platform.current_tenant_id())
    WITH CHECK (tenant_id = platform.current_tenant_id());

CREATE OR REPLACE FUNCTION platform.reject_workspace_restore_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, platform
AS $$
BEGIN
    RAISE EXCEPTION 'workspace restore event history is append-only' USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER workspace_restore_events_append_only
BEFORE UPDATE OR DELETE ON platform.workspace_restore_events
FOR EACH ROW EXECUTE FUNCTION platform.reject_workspace_restore_event_mutation();

CREATE TRIGGER workspace_restore_events_no_truncate
BEFORE TRUNCATE ON platform.workspace_restore_events
FOR EACH STATEMENT EXECUTE FUNCTION platform.reject_workspace_restore_event_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON platform.workspace_restore_events FROM PUBLIC;

CREATE OR REPLACE FUNCTION platform.begin_workspace_restore(
    p_tenant_id uuid,
    p_workspace_id uuid,
    p_restore_id uuid,
    p_snapshot_id uuid,
    p_fencing_token bigint
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, platform
AS $$
DECLARE
    inserted_count integer;
BEGIN
    IF platform.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'tenant scope mismatch' USING ERRCODE = '42501';
    END IF;
    IF p_workspace_id IS NULL OR p_restore_id IS NULL OR p_snapshot_id IS NULL
       OR p_fencing_token IS NULL OR p_fencing_token < 1 THEN
        RAISE EXCEPTION 'invalid workspace restore identity or fencing token' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM platform.workspace_leases
         WHERE tenant_id = p_tenant_id
           AND workspace_id = p_workspace_id
           AND fencing_token = p_fencing_token
           AND status = 'active'
           AND lease_expires_at > clock_timestamp()
    ) THEN
        RAISE EXCEPTION 'workspace restore requires the current active lease fence'
            USING ERRCODE = '55000';
    END IF;

    INSERT INTO platform.workspace_restore_operations (
        tenant_id, workspace_id, restore_id, snapshot_id, fencing_token, status
    ) VALUES (
        p_tenant_id, p_workspace_id, p_restore_id, p_snapshot_id, p_fencing_token, 'started'
    ) ON CONFLICT (tenant_id, restore_id) DO NOTHING;
    GET DIAGNOSTICS inserted_count = ROW_COUNT;
    IF inserted_count = 0 THEN
        RETURN false;
    END IF;

    INSERT INTO platform.workspace_restore_events (
        event_id, tenant_id, workspace_id, restore_id, snapshot_id,
        fencing_token, event_type
    ) VALUES (
        gen_random_uuid(), p_tenant_id, p_workspace_id, p_restore_id, p_snapshot_id,
        p_fencing_token, 'started'
    );
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION platform.complete_workspace_restore(
    p_tenant_id uuid,
    p_workspace_id uuid,
    p_restore_id uuid,
    p_snapshot_digest text
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, platform
AS $$
DECLARE
    current_operation platform.workspace_restore_operations%rowtype;
BEGIN
    IF platform.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'tenant scope mismatch' USING ERRCODE = '42501';
    END IF;
    IF p_snapshot_digest IS NULL OR p_snapshot_digest !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid workspace snapshot digest' USING ERRCODE = '22023';
    END IF;

    UPDATE platform.workspace_restore_operations
       SET status = 'completed',
           snapshot_digest = p_snapshot_digest,
           completed_at = clock_timestamp(),
           updated_at = clock_timestamp()
     WHERE tenant_id = p_tenant_id
       AND workspace_id = p_workspace_id
       AND restore_id = p_restore_id
       AND status = 'started'
    RETURNING * INTO current_operation;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    INSERT INTO platform.workspace_restore_events (
        event_id, tenant_id, workspace_id, restore_id, snapshot_id,
        fencing_token, event_type, snapshot_digest
    ) VALUES (
        gen_random_uuid(), p_tenant_id, p_workspace_id, p_restore_id,
        current_operation.snapshot_id, current_operation.fencing_token,
        'completed', p_snapshot_digest
    );
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION platform.fail_workspace_restore(
    p_tenant_id uuid,
    p_workspace_id uuid,
    p_restore_id uuid,
    p_reason_code text
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, platform
AS $$
DECLARE
    current_operation platform.workspace_restore_operations%rowtype;
BEGIN
    IF platform.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'tenant scope mismatch' USING ERRCODE = '42501';
    END IF;
    IF p_reason_code IS NULL OR p_reason_code !~ '^[A-Za-z][A-Za-z0-9_]{0,63}$' THEN
        RAISE EXCEPTION 'invalid workspace restore failure code' USING ERRCODE = '22023';
    END IF;

    UPDATE platform.workspace_restore_operations
       SET status = 'failed',
           failure_code = p_reason_code,
           updated_at = clock_timestamp()
     WHERE tenant_id = p_tenant_id
       AND workspace_id = p_workspace_id
       AND restore_id = p_restore_id
       AND status = 'started'
    RETURNING * INTO current_operation;
    IF NOT FOUND THEN
        RETURN false;
    END IF;

    INSERT INTO platform.workspace_restore_events (
        event_id, tenant_id, workspace_id, restore_id, snapshot_id,
        fencing_token, event_type, failure_code
    ) VALUES (
        gen_random_uuid(), p_tenant_id, p_workspace_id, p_restore_id,
        current_operation.snapshot_id, current_operation.fencing_token,
        'failed', p_reason_code
    );
    RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION platform.begin_workspace_restore(uuid, uuid, uuid, uuid, bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.complete_workspace_restore(uuid, uuid, uuid, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.fail_workspace_restore(uuid, uuid, uuid, text) FROM PUBLIC;


-- Durable snapshot catalog. The object body is stored encrypted in the object
-- store; this tenant-scoped catalog makes references discoverable after restart.
CREATE TABLE IF NOT EXISTS platform.workspace_snapshots (
    tenant_id uuid NOT NULL REFERENCES platform.tenants(tenant_id),
    snapshot_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    created_at timestamptz NOT NULL,
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    storage_key text NOT NULL CHECK (storage_key ~ '^[0-9a-f]{32}[.]snapshot$'),
    status text NOT NULL DEFAULT 'available' CHECK (status IN ('available', 'deleted')),
    PRIMARY KEY (tenant_id, snapshot_id),
    UNIQUE (tenant_id, workspace_id, snapshot_id),
    FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES platform.workspace_leases (tenant_id, workspace_id)
);

CREATE INDEX IF NOT EXISTS idx_workspace_snapshots_workspace
    ON platform.workspace_snapshots (tenant_id, workspace_id, created_at DESC);

CREATE TABLE IF NOT EXISTS platform.workspace_snapshot_events (
    event_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    snapshot_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    event_type text NOT NULL CHECK (event_type IN ('created')),
    digest text NOT NULL CHECK (digest ~ '^[0-9a-f]{64}$'),
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id, snapshot_id)
        REFERENCES platform.workspace_snapshots (tenant_id, snapshot_id)
);

ALTER TABLE platform.workspace_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.workspace_snapshots FORCE ROW LEVEL SECURITY;
ALTER TABLE platform.workspace_snapshot_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.workspace_snapshot_events FORCE ROW LEVEL SECURITY;

CREATE POLICY workspace_snapshots_tenant_isolation
    ON platform.workspace_snapshots
    USING (tenant_id = platform.current_tenant_id())
    WITH CHECK (tenant_id = platform.current_tenant_id());

CREATE POLICY workspace_snapshot_events_tenant_isolation
    ON platform.workspace_snapshot_events
    USING (tenant_id = platform.current_tenant_id())
    WITH CHECK (tenant_id = platform.current_tenant_id());

CREATE OR REPLACE FUNCTION platform.reject_workspace_snapshot_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, platform
AS $$
BEGIN
    RAISE EXCEPTION 'workspace snapshot event history is append-only' USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER workspace_snapshot_events_append_only
BEFORE UPDATE OR DELETE ON platform.workspace_snapshot_events
FOR EACH ROW EXECUTE FUNCTION platform.reject_workspace_snapshot_event_mutation();

CREATE TRIGGER workspace_snapshot_events_no_truncate
BEFORE TRUNCATE ON platform.workspace_snapshot_events
FOR EACH STATEMENT EXECUTE FUNCTION platform.reject_workspace_snapshot_event_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON platform.workspace_snapshot_events FROM PUBLIC;

CREATE OR REPLACE FUNCTION platform.record_workspace_snapshot(
    p_tenant_id uuid,
    p_snapshot_id uuid,
    p_workspace_id uuid,
    p_fencing_token bigint,
    p_created_at timestamptz,
    p_digest text,
    p_storage_key text
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, platform
AS $$
DECLARE
    inserted_count integer;
BEGIN
    IF platform.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'tenant scope mismatch' USING ERRCODE = '42501';
    END IF;
    IF p_snapshot_id IS NULL OR p_workspace_id IS NULL
       OR p_fencing_token IS NULL OR p_fencing_token < 1
       OR p_created_at IS NULL
       OR p_digest IS NULL OR p_digest !~ '^[0-9a-f]{64}$'
       OR p_storage_key IS DISTINCT FROM replace(p_snapshot_id::text, '-', '') || '.snapshot' THEN
        RAISE EXCEPTION 'invalid workspace snapshot metadata' USING ERRCODE = '22023';
    END IF;

    INSERT INTO platform.workspace_snapshots (
        tenant_id, snapshot_id, workspace_id, fencing_token,
        created_at, digest, storage_key, status
    ) VALUES (
        p_tenant_id, p_snapshot_id, p_workspace_id, p_fencing_token,
        p_created_at, p_digest, p_storage_key, 'available'
    ) ON CONFLICT (tenant_id, snapshot_id) DO NOTHING;
    GET DIAGNOSTICS inserted_count = ROW_COUNT;
    IF inserted_count = 0 THEN
        RETURN false;
    END IF;

    INSERT INTO platform.workspace_snapshot_events (
        event_id, tenant_id, snapshot_id, workspace_id, fencing_token,
        event_type, digest
    ) VALUES (
        gen_random_uuid(), p_tenant_id, p_snapshot_id, p_workspace_id,
        p_fencing_token, 'created', p_digest
    );
    RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION platform.record_workspace_snapshot(uuid, uuid, uuid, bigint, timestamptz, text, text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION platform.get_workspace_snapshot(
    p_tenant_id uuid,
    p_workspace_id uuid,
    p_snapshot_id uuid
) RETURNS TABLE (
    snapshot_id uuid,
    tenant_id uuid,
    workspace_id uuid,
    fencing_token bigint,
    created_at timestamptz,
    digest text,
    status text
)
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, platform
AS $$
BEGIN
    IF platform.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'tenant scope mismatch' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT s.snapshot_id, s.tenant_id, s.workspace_id, s.fencing_token,
           s.created_at, s.digest, s.status
      FROM platform.workspace_snapshots AS s
     WHERE s.tenant_id = p_tenant_id
       AND s.workspace_id = p_workspace_id
       AND s.snapshot_id = p_snapshot_id
       AND s.status = 'available';
END;
$$;

REVOKE ALL ON FUNCTION platform.get_workspace_snapshot(uuid, uuid, uuid) FROM PUBLIC;
