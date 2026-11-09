-- W6 acceptance: durable restore claims, one-way transitions, RLS and append-only evidence.
BEGIN;

INSERT INTO platform.tenants (tenant_id, name)
VALUES
    ('00000000-0000-0000-0000-000000000093', 'w6-restore-tenant-a'),
    ('00000000-0000-0000-0000-000000000094', 'w6-restore-tenant-b');

SELECT set_config('platform.tenant_id', '00000000-0000-0000-0000-000000000093', true);

DO $$
DECLARE
    tenant uuid := '00000000-0000-0000-0000-000000000093';
    other_tenant uuid := '00000000-0000-0000-0000-000000000094';
    workspace uuid := '20000000-0000-0000-0000-000000000093';
    restore_one uuid := '30000000-0000-0000-0000-000000000093';
    restore_two uuid := '40000000-0000-0000-0000-000000000093';
    snapshot_one uuid := '50000000-0000-0000-0000-000000000093';
    snapshot_two uuid := '60000000-0000-0000-0000-000000000093';
    digest text := repeat('a', 64);
    event_count integer;
    visible_count integer;
BEGIN
    IF platform.begin_workspace_restore(tenant, workspace, restore_one, snapshot_one, 5) IS NOT TRUE THEN
        RAISE EXCEPTION 'first restore claim was not created';
    END IF;
    IF platform.begin_workspace_restore(tenant, workspace, restore_one, snapshot_one, 5) IS NOT FALSE THEN
        RAISE EXCEPTION 'restore operation replay was not rejected';
    END IF;
    IF platform.complete_workspace_restore(tenant, workspace, restore_one, digest) IS NOT TRUE THEN
        RAISE EXCEPTION 'started restore did not complete';
    END IF;
    IF platform.complete_workspace_restore(tenant, workspace, restore_one, digest) IS NOT FALSE THEN
        RAISE EXCEPTION 'completed restore was not one-way';
    END IF;
    IF platform.fail_workspace_restore(tenant, workspace, restore_one, 'late_failure') IS NOT FALSE THEN
        RAISE EXCEPTION 'completed restore was changed to failed';
    END IF;

    IF platform.begin_workspace_restore(tenant, workspace, restore_two, snapshot_two, 6) IS NOT TRUE THEN
        RAISE EXCEPTION 'second restore claim was not created';
    END IF;
    IF platform.fail_workspace_restore(tenant, workspace, restore_two, 'credential_refresh_failed') IS NOT TRUE THEN
        RAISE EXCEPTION 'started restore did not record failure';
    END IF;
    IF platform.complete_workspace_restore(tenant, workspace, restore_two, digest) IS NOT FALSE THEN
        RAISE EXCEPTION 'failed restore was changed to completed';
    END IF;

    SELECT count(*) INTO event_count FROM platform.workspace_restore_events
     WHERE tenant_id = tenant AND workspace_id = workspace;
    IF event_count <> 4 THEN
        RAISE EXCEPTION 'restore event ledger has % rows, expected 4', event_count;
    END IF;

    BEGIN
        UPDATE platform.workspace_restore_events
           SET event_type = 'tampered'
         WHERE tenant_id = tenant AND workspace_id = workspace;
        RAISE EXCEPTION 'restore event history was mutable';
    EXCEPTION WHEN SQLSTATE '42501' THEN
        NULL;
    END;

    BEGIN
        PERFORM platform.begin_workspace_restore(tenant, workspace, uuid_generate_v4(), snapshot_one, 0);
        RAISE EXCEPTION 'zero fencing token was accepted';
    EXCEPTION WHEN SQLSTATE '22023' THEN
        NULL;
    END;

    BEGIN
        PERFORM platform.fail_workspace_restore(tenant, workspace, restore_two, 'contains sensitive details');
        RAISE EXCEPTION 'un-normalized failure code was accepted';
    EXCEPTION WHEN SQLSTATE '22023' THEN
        NULL;
    END;

    SELECT count(*) INTO visible_count FROM platform.workspace_restore_operations
     WHERE tenant_id = tenant;
    IF visible_count <> 2 THEN
        RAISE EXCEPTION 'tenant could not read its own restore operations';
    END IF;

    PERFORM set_config('platform.tenant_id', other_tenant::text, true);
    SELECT count(*) INTO visible_count FROM platform.workspace_restore_operations
     WHERE tenant_id = tenant;
    IF visible_count <> 0 THEN
        RAISE EXCEPTION 'cross-tenant restore operations were visible';
    END IF;
    SELECT count(*) INTO visible_count FROM platform.workspace_restore_events
     WHERE tenant_id = tenant;
    IF visible_count <> 0 THEN
        RAISE EXCEPTION 'cross-tenant restore events were visible';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_policies
         WHERE schemaname = 'platform'
           AND tablename = 'workspace_restore_operations'
           AND policyname = 'workspace_restore_operations_tenant_isolation'
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_policies
         WHERE schemaname = 'platform'
           AND tablename = 'workspace_restore_events'
           AND policyname = 'workspace_restore_events_tenant_isolation'
    ) THEN
        RAISE EXCEPTION 'workspace restore RLS policies are missing';
    END IF;
END;
$$;

ROLLBACK;
