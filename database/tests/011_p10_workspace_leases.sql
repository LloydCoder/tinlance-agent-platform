-- W5 workspace lease acceptance: durable ownership, expiry, revocation, fencing and audit continuity.
BEGIN;

INSERT INTO platform.tenants (tenant_id, name)
VALUES ('00000000-0000-0000-0000-000000000092', 'w5-workspace-lease-tenant');

SELECT set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000092', true);

DO $$
DECLARE
    tenant uuid := '00000000-0000-0000-0000-000000000092';
    workspace uuid := '20000000-0000-0000-0000-000000000092';
    lease_one uuid := '30000000-0000-0000-0000-000000000092';
    lease_two uuid := '40000000-0000-0000-0000-000000000092';
    lease_three uuid := '50000000-0000-0000-0000-000000000092';
    lease_four uuid := '60000000-0000-0000-0000-000000000092';
    first_row record;
    second_row record;
    third_row record;
    fourth_row record;
    renewed_until timestamptz;
    event_count integer;
BEGIN
    SELECT * INTO first_row FROM platform.acquire_workspace_lease(
        tenant, workspace, lease_one, 'owner-a', 'worker-a', 600
    );
    IF first_row.lease_id <> lease_one OR first_row.fencing_token <> 1 THEN
        RAISE EXCEPTION 'first workspace lease did not start at fencing token 1';
    END IF;
    IF NOT platform.assert_workspace_lease(
        tenant, workspace, lease_one, 1::bigint, 'owner-a', 'worker-a'
    ) THEN
        RAISE EXCEPTION 'new workspace lease did not assert active';
    END IF;

    SELECT * INTO second_row FROM platform.acquire_workspace_lease(
        tenant, workspace, lease_two, 'owner-b', 'worker-b', 600
    );
    IF second_row.lease_id IS NOT NULL THEN
        RAISE EXCEPTION 'concurrent active workspace lease was acquired twice';
    END IF;

    BEGIN
        PERFORM platform.renew_workspace_lease(
            tenant, workspace, NULL::uuid, NULL::bigint, NULL::text, NULL::text, 600
        );
        RAISE EXCEPTION 'null lease identity bypassed renewal fencing';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;
    BEGIN
        PERFORM platform.revoke_workspace_lease(
            tenant, workspace, NULL::uuid, NULL::bigint, NULL::text, NULL::text
        );
        RAISE EXCEPTION 'null lease identity bypassed revocation fencing';
    EXCEPTION WHEN SQLSTATE '42501' THEN
        NULL;
    END;

    renewed_until := platform.renew_workspace_lease(tenant, workspace, lease_one, 1::bigint, 'owner-a', 'worker-a', 900);
    IF renewed_until <= clock_timestamp() THEN
        RAISE EXCEPTION 'workspace lease renewal did not advance expiry';
    END IF;

    IF platform.revoke_workspace_lease(tenant, workspace, lease_one, 1::bigint, 'owner-a', 'worker-a') IS NOT TRUE THEN
        RAISE EXCEPTION 'active workspace lease was not revoked';
    END IF;
    IF platform.assert_workspace_lease(
        tenant, workspace, lease_one, 1::bigint, 'owner-a', 'worker-a'
    ) THEN
        RAISE EXCEPTION 'revoked worker retained active lease authority';
    END IF;
    IF platform.revoke_workspace_lease(tenant, workspace, lease_one, 1::bigint, 'owner-a', 'worker-a') IS NOT FALSE THEN
        RAISE EXCEPTION 'duplicate revocation was not idempotent';
    END IF;

    BEGIN
        PERFORM platform.renew_workspace_lease(tenant, workspace, lease_one, 1::bigint, 'owner-a', 'worker-a', 600);
        RAISE EXCEPTION 'revoked lease was renewed';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;

    SELECT * INTO second_row FROM platform.acquire_workspace_lease(
        tenant, workspace, lease_two, 'owner-b', 'worker-b', 600
    );
    IF second_row.fencing_token <> 2 THEN
        RAISE EXCEPTION 'reacquisition did not increment the fencing token';
    END IF;
    IF platform.assert_workspace_lease(
        tenant, workspace, lease_one, 1::bigint, 'owner-a', 'worker-a'
    ) THEN
        RAISE EXCEPTION 'stale worker passed fencing after a new acquisition';
    END IF;
    IF NOT platform.assert_workspace_lease(
        tenant, workspace, lease_two, 2::bigint, 'owner-b', 'worker-b'
    ) THEN
        RAISE EXCEPTION 'new worker failed fencing assertion';
    END IF;

    IF platform.release_workspace_lease(tenant, workspace, lease_two, 2::bigint, 'owner-b', 'worker-b') IS NOT TRUE THEN
        RAISE EXCEPTION 'active workspace lease was not released';
    END IF;
    SELECT * INTO third_row FROM platform.acquire_workspace_lease(
        tenant, workspace, lease_three, 'owner-c', 'worker-c', 600
    );
    IF third_row.fencing_token <> 3 THEN
        RAISE EXCEPTION 'release/reacquire did not advance fencing token';
    END IF;

    UPDATE platform.workspace_leases
       SET lease_expires_at = clock_timestamp() - interval '1 second'
     WHERE tenant_id = tenant AND workspace_id = workspace;
    SELECT * INTO fourth_row FROM platform.acquire_workspace_lease(
        tenant, workspace, lease_four, 'owner-d', 'worker-d', 600
    );
    IF fourth_row.fencing_token <> 4 THEN
        RAISE EXCEPTION 'expired lease recovery did not advance fencing token';
    END IF;
    IF platform.assert_workspace_lease(
        tenant, workspace, lease_three, 3::bigint, 'owner-c', 'worker-c'
    ) THEN
        RAISE EXCEPTION 'expired stale worker passed fencing assertion';
    END IF;

    SELECT count(*) INTO event_count FROM platform.workspace_lease_events
     WHERE tenant_id = tenant AND workspace_id = workspace;
    IF event_count <> 8 THEN
        RAISE EXCEPTION 'workspace lease audit history is incomplete: % events', event_count;
    END IF;

    BEGIN
        UPDATE platform.workspace_lease_events
           SET worker_id = 'tampered'
         WHERE tenant_id = tenant AND workspace_id = workspace;
        RAISE EXCEPTION 'append-only workspace lease events were mutable';
    EXCEPTION WHEN SQLSTATE '42501' THEN
        NULL;
    END;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
         WHERE schemaname = 'platform'
           AND tablename = 'workspace_leases'
           AND policyname = 'workspace_leases_tenant_isolation'
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_policies
         WHERE schemaname = 'platform'
           AND tablename = 'workspace_lease_events'
           AND policyname = 'workspace_lease_events_tenant_isolation'
    ) THEN
        RAISE EXCEPTION 'workspace lease tenant RLS policies are missing';
    END IF;
END;
$$;

ROLLBACK;
