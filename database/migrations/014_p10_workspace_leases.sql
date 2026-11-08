-- W5 durable workspace leases with monotonic fencing tokens and append-only lifecycle evidence.
CREATE TABLE IF NOT EXISTS platform.workspace_leases (
    tenant_id uuid NOT NULL REFERENCES platform.tenants(tenant_id),
    workspace_id uuid NOT NULL,
    lease_id uuid NOT NULL,
    owner_subject_id text NOT NULL CHECK (length(owner_subject_id) BETWEEN 1 AND 512),
    worker_id text NOT NULL CHECK (length(worker_id) BETWEEN 1 AND 256),
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    status text NOT NULL CHECK (status IN ('active', 'expired', 'revoked', 'released')),
    lease_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    revoked_at timestamptz,
    released_at timestamptz,
    PRIMARY KEY (tenant_id, workspace_id),
    UNIQUE (tenant_id, lease_id),
    CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),
    CHECK ((status = 'released') = (released_at IS NOT NULL))
);

CREATE INDEX IF NOT EXISTS idx_workspace_leases_expiry
    ON platform.workspace_leases (tenant_id, lease_expires_at)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS platform.workspace_lease_events (
    event_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    workspace_id uuid NOT NULL,
    lease_id uuid NOT NULL,
    fencing_token bigint NOT NULL CHECK (fencing_token > 0),
    event_type text NOT NULL CHECK (
        event_type IN ('acquired', 'renewed', 'expired', 'revoked', 'released')
    ),
    owner_subject_id text NOT NULL,
    worker_id text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    FOREIGN KEY (tenant_id, workspace_id)
        REFERENCES platform.workspace_leases (tenant_id, workspace_id)
);

CREATE INDEX IF NOT EXISTS idx_workspace_lease_events_history
    ON platform.workspace_lease_events (tenant_id, workspace_id, occurred_at, event_id);

ALTER TABLE platform.workspace_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.workspace_leases FORCE ROW LEVEL SECURITY;
ALTER TABLE platform.workspace_lease_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE platform.workspace_lease_events FORCE ROW LEVEL SECURITY;

CREATE POLICY workspace_leases_tenant_isolation ON platform.workspace_leases
    USING (tenant_id = platform.current_tenant_id())
    WITH CHECK (tenant_id = platform.current_tenant_id());
CREATE POLICY workspace_lease_events_tenant_isolation ON platform.workspace_lease_events
    USING (tenant_id = platform.current_tenant_id())
    WITH CHECK (tenant_id = platform.current_tenant_id());

CREATE OR REPLACE FUNCTION platform.reject_workspace_lease_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, platform
AS $$
BEGIN
    RAISE EXCEPTION 'workspace lease event history is append-only' USING ERRCODE = '42501';
END;
$$;

CREATE TRIGGER workspace_lease_events_append_only
BEFORE UPDATE OR DELETE ON platform.workspace_lease_events
FOR EACH ROW EXECUTE FUNCTION platform.reject_workspace_lease_event_mutation();
CREATE TRIGGER workspace_lease_events_no_truncate
BEFORE TRUNCATE ON platform.workspace_lease_events
FOR EACH STATEMENT EXECUTE FUNCTION platform.reject_workspace_lease_event_mutation();
REVOKE UPDATE, DELETE, TRUNCATE ON platform.workspace_lease_events FROM PUBLIC;

CREATE OR REPLACE FUNCTION platform.acquire_workspace_lease(
    p_tenant_id uuid,
    p_workspace_id uuid,
    p_lease_id uuid,
    p_owner_subject_id text,
    p_worker_id text,
    p_lease_seconds integer
) RETURNS TABLE (
    lease_id uuid,
    tenant_id uuid,
    workspace_id uuid,
    owner_subject_id text,
    worker_id text,
    fencing_token bigint,
    lease_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, platform
AS $$
DECLARE
    current_lease platform.workspace_leases%rowtype;
    inserted_count integer;
    new_token bigint;
    new_expiry timestamptz;
BEGIN
    IF platform.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'tenant scope mismatch' USING ERRCODE = '42501';
    END IF;
    IF p_workspace_id IS NULL OR p_lease_id IS NULL
       OR p_owner_subject_id IS NULL OR length(btrim(p_owner_subject_id)) NOT BETWEEN 1 AND 512
       OR p_owner_subject_id <> btrim(p_owner_subject_id)
       OR p_worker_id IS NULL OR length(btrim(p_worker_id)) NOT BETWEEN 1 AND 256
       OR p_worker_id <> btrim(p_worker_id)
       OR p_lease_seconds IS NULL OR p_lease_seconds < 60 OR p_lease_seconds > 3600 THEN
        RAISE EXCEPTION 'invalid workspace lease request' USING ERRCODE = '22023';
    END IF;

    new_expiry := clock_timestamp() + make_interval(secs => p_lease_seconds);
    INSERT INTO platform.workspace_leases (
        tenant_id, workspace_id, lease_id, owner_subject_id, worker_id,
        fencing_token, status, lease_expires_at
    ) VALUES (
        p_tenant_id, p_workspace_id, p_lease_id, p_owner_subject_id, p_worker_id,
        1, 'active', new_expiry
    ) ON CONFLICT ON CONSTRAINT workspace_leases_pkey DO NOTHING;
    GET DIAGNOSTICS inserted_count = ROW_COUNT;

    IF inserted_count = 1 THEN
        INSERT INTO platform.workspace_lease_events (
            event_id, tenant_id, workspace_id, lease_id, fencing_token,
            event_type, owner_subject_id, worker_id
        ) VALUES (
            gen_random_uuid(), p_tenant_id, p_workspace_id, p_lease_id, 1,
            'acquired', p_owner_subject_id, p_worker_id
        );
        RETURN QUERY SELECT p_lease_id, p_tenant_id, p_workspace_id,
            p_owner_subject_id, p_worker_id, 1::bigint, new_expiry;
        RETURN;
    END IF;

    SELECT wl.* INTO current_lease
      FROM platform.workspace_leases AS wl
     WHERE wl.tenant_id = p_tenant_id AND wl.workspace_id = p_workspace_id
     FOR UPDATE;
    IF current_lease.status = 'active' AND current_lease.lease_expires_at > clock_timestamp() THEN
        RETURN;
    END IF;

    IF current_lease.status = 'active' THEN
        UPDATE platform.workspace_leases AS wl
           SET status = 'expired', updated_at = clock_timestamp()
         WHERE wl.tenant_id = p_tenant_id AND wl.workspace_id = p_workspace_id;
        INSERT INTO platform.workspace_lease_events (
            event_id, tenant_id, workspace_id, lease_id, fencing_token,
            event_type, owner_subject_id, worker_id
        ) VALUES (
            gen_random_uuid(), p_tenant_id, p_workspace_id, current_lease.lease_id,
            current_lease.fencing_token, 'expired',
            current_lease.owner_subject_id, current_lease.worker_id
        );
    END IF;

    new_token := current_lease.fencing_token + 1;
    UPDATE platform.workspace_leases AS wl
       SET lease_id = p_lease_id,
           owner_subject_id = p_owner_subject_id,
           worker_id = p_worker_id,
           fencing_token = new_token,
           status = 'active',
           lease_expires_at = new_expiry,
           updated_at = clock_timestamp(),
           revoked_at = NULL,
           released_at = NULL
     WHERE wl.tenant_id = p_tenant_id AND wl.workspace_id = p_workspace_id;

    INSERT INTO platform.workspace_lease_events (
        event_id, tenant_id, workspace_id, lease_id, fencing_token,
        event_type, owner_subject_id, worker_id
    ) VALUES (
        gen_random_uuid(), p_tenant_id, p_workspace_id, p_lease_id, new_token,
        'acquired', p_owner_subject_id, p_worker_id
    );

    RETURN QUERY SELECT p_lease_id, p_tenant_id, p_workspace_id,
        p_owner_subject_id, p_worker_id, new_token, new_expiry;
END;
$$;

CREATE OR REPLACE FUNCTION platform.renew_workspace_lease(
    p_tenant_id uuid,
    p_workspace_id uuid,
    p_lease_id uuid,
    p_fencing_token bigint,
    p_owner_subject_id text,
    p_worker_id text,
    p_lease_seconds integer
) RETURNS timestamptz
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, platform
AS $$
DECLARE
    current_lease platform.workspace_leases%rowtype;
    new_expiry timestamptz;
BEGIN
    IF platform.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'tenant scope mismatch' USING ERRCODE = '42501';
    END IF;
    IF p_lease_seconds IS NULL OR p_lease_seconds < 60 OR p_lease_seconds > 3600 THEN
        RAISE EXCEPTION 'lease duration must be between 60 and 3600 seconds' USING ERRCODE = '22023';
    END IF;
    SELECT * INTO current_lease FROM platform.workspace_leases
     WHERE tenant_id = p_tenant_id AND workspace_id = p_workspace_id FOR UPDATE;
    IF NOT FOUND OR current_lease.status <> 'active'
       OR current_lease.lease_id <> p_lease_id
       OR current_lease.fencing_token <> p_fencing_token
       OR current_lease.owner_subject_id <> p_owner_subject_id
       OR current_lease.worker_id <> p_worker_id
       OR current_lease.lease_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'workspace lease is expired, revoked, or fenced' USING ERRCODE = '55000';
    END IF;
    new_expiry := clock_timestamp() + make_interval(secs => p_lease_seconds);
    UPDATE platform.workspace_leases SET lease_expires_at = new_expiry, updated_at = clock_timestamp()
     WHERE tenant_id = p_tenant_id AND workspace_id = p_workspace_id;
    INSERT INTO platform.workspace_lease_events (
        event_id, tenant_id, workspace_id, lease_id, fencing_token,
        event_type, owner_subject_id, worker_id
    ) VALUES (
        gen_random_uuid(), p_tenant_id, p_workspace_id, p_lease_id, p_fencing_token,
        'renewed', current_lease.owner_subject_id, current_lease.worker_id
    );
    RETURN new_expiry;
END;
$$;

CREATE OR REPLACE FUNCTION platform.assert_workspace_lease(
    p_tenant_id uuid,
    p_workspace_id uuid,
    p_lease_id uuid,
    p_fencing_token bigint,
    p_owner_subject_id text,
    p_worker_id text
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, platform
AS $$
BEGIN
    IF platform.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'tenant scope mismatch' USING ERRCODE = '42501';
    END IF;
    RETURN EXISTS (
        SELECT 1 FROM platform.workspace_leases
         WHERE tenant_id = p_tenant_id AND workspace_id = p_workspace_id
           AND lease_id = p_lease_id AND fencing_token = p_fencing_token
           AND owner_subject_id = p_owner_subject_id AND worker_id = p_worker_id
           AND status = 'active' AND lease_expires_at > clock_timestamp()
    );
END;
$$;

CREATE OR REPLACE FUNCTION platform.revoke_workspace_lease(
    p_tenant_id uuid,
    p_workspace_id uuid,
    p_lease_id uuid,
    p_fencing_token bigint,
    p_owner_subject_id text,
    p_worker_id text
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, platform
AS $$
DECLARE
    current_lease platform.workspace_leases%rowtype;
BEGIN
    IF platform.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'tenant scope mismatch' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO current_lease FROM platform.workspace_leases
     WHERE tenant_id = p_tenant_id AND workspace_id = p_workspace_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF current_lease.lease_id <> p_lease_id OR current_lease.fencing_token <> p_fencing_token
       OR current_lease.owner_subject_id <> p_owner_subject_id
       OR current_lease.worker_id <> p_worker_id THEN
        RAISE EXCEPTION 'workspace lease fencing token mismatch' USING ERRCODE = '42501';
    END IF;
    IF current_lease.status = 'revoked' THEN
        RETURN false;
    END IF;
    IF current_lease.status <> 'active' THEN
        RAISE EXCEPTION 'workspace lease is not active' USING ERRCODE = '55000';
    END IF;
    UPDATE platform.workspace_leases
       SET status = 'revoked', lease_expires_at = clock_timestamp(),
           revoked_at = clock_timestamp(), updated_at = clock_timestamp()
     WHERE tenant_id = p_tenant_id AND workspace_id = p_workspace_id;
    INSERT INTO platform.workspace_lease_events (
        event_id, tenant_id, workspace_id, lease_id, fencing_token,
        event_type, owner_subject_id, worker_id
    ) VALUES (
        gen_random_uuid(), p_tenant_id, p_workspace_id, p_lease_id, p_fencing_token,
        'revoked', current_lease.owner_subject_id, current_lease.worker_id
    );
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION platform.release_workspace_lease(
    p_tenant_id uuid,
    p_workspace_id uuid,
    p_lease_id uuid,
    p_fencing_token bigint,
    p_owner_subject_id text,
    p_worker_id text
) RETURNS boolean
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, platform
AS $$
DECLARE
    current_lease platform.workspace_leases%rowtype;
BEGIN
    IF platform.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
        RAISE EXCEPTION 'tenant scope mismatch' USING ERRCODE = '42501';
    END IF;
    SELECT * INTO current_lease FROM platform.workspace_leases
     WHERE tenant_id = p_tenant_id AND workspace_id = p_workspace_id FOR UPDATE;
    IF NOT FOUND THEN
        RETURN false;
    END IF;
    IF current_lease.lease_id <> p_lease_id OR current_lease.fencing_token <> p_fencing_token
       OR current_lease.owner_subject_id <> p_owner_subject_id
       OR current_lease.worker_id <> p_worker_id THEN
        RAISE EXCEPTION 'workspace lease fencing token mismatch' USING ERRCODE = '42501';
    END IF;
    IF current_lease.status = 'released' THEN
        RETURN false;
    END IF;
    IF current_lease.status <> 'active' OR current_lease.lease_expires_at <= clock_timestamp() THEN
        RAISE EXCEPTION 'workspace lease is not active' USING ERRCODE = '55000';
    END IF;
    UPDATE platform.workspace_leases
       SET status = 'released', lease_expires_at = clock_timestamp(),
           released_at = clock_timestamp(), updated_at = clock_timestamp()
     WHERE tenant_id = p_tenant_id AND workspace_id = p_workspace_id;
    INSERT INTO platform.workspace_lease_events (
        event_id, tenant_id, workspace_id, lease_id, fencing_token,
        event_type, owner_subject_id, worker_id
    ) VALUES (
        gen_random_uuid(), p_tenant_id, p_workspace_id, p_lease_id, p_fencing_token,
        'released', current_lease.owner_subject_id, current_lease.worker_id
    );
    RETURN true;
END;
$$;

REVOKE ALL ON FUNCTION platform.acquire_workspace_lease(uuid, uuid, uuid, text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.renew_workspace_lease(uuid, uuid, uuid, bigint, text, text, integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.assert_workspace_lease(uuid, uuid, uuid, bigint, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.revoke_workspace_lease(uuid, uuid, uuid, bigint, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform.release_workspace_lease(uuid, uuid, uuid, bigint, text, text) FROM PUBLIC;
