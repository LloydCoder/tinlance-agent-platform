from __future__ import annotations

from pathlib import Path
from uuid import UUID, uuid4

import pytest

from tinlance_agent_platform_durability.snapshots import (
    AESGCMCipher,
    FilesystemSnapshotStore,
    HMACSnapshotSigner,
    SnapshotConflictError,
    SnapshotError,
    SnapshotIntegrityError,
    WorkspaceSnapshotService,
)

TENANT = UUID("10000000-0000-0000-0000-000000000001")
WORKSPACE = UUID("20000000-0000-0000-0000-000000000001")


class LeaseAuthority:
    def __init__(self, outcomes: list[bool] | None = None) -> None:
        self.outcomes = outcomes or [True, True]
        self.calls = 0

    def assert_active(self, tenant_id, workspace_id, fencing_token):
        self.calls += 1
        return self.outcomes[min(self.calls - 1, len(self.outcomes) - 1)]


class Ledger:
    def __init__(self):
        self.claimed = set()
        self.completed = {}
        self.failed = {}

    def begin(self, tenant_id, workspace_id, restore_id, snapshot_id, fencing_token):
        if restore_id in self.claimed:
            return False
        self.claimed.add(restore_id)
        return True

    def complete(self, tenant_id, workspace_id, restore_id, snapshot_digest):
        self.completed[restore_id] = snapshot_digest

    def fail(self, tenant_id, workspace_id, restore_id, reason_code):
        self.failed[restore_id] = reason_code


class Credentials:
    def __init__(self, values=None, error=None):
        self.values = values or {"browser": "secret-ref://tenant/workspace/browser"}
        self.error = error

    def refresh(self, tenant_id, workspace_id, fencing_token):
        if self.error:
            raise self.error
        return self.values


def service(tmp_path: Path) -> WorkspaceSnapshotService:
    return WorkspaceSnapshotService(
        store=FilesystemSnapshotStore(tmp_path / "objects"),
        cipher=AESGCMCipher(b"e" * 32),
        signer=HMACSnapshotSigner(b"s" * 32),
    )


def make_snapshot(tmp_path: Path):
    return service(tmp_path).create(
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        fencing_token=4,
        files={
            "workspace/README.md": b"durable workspace",
            "workspace/bin/run.sh": b"#!/bin/sh\necho ok\n",
            "browser-profile/Preferences": b'{"theme":"dark"}',
        },
        file_modes={"workspace/bin/run.sh": 0o700},
    )


def test_snapshot_round_trip_restores_clean_workspace_with_new_fence_and_refreshed_credentials(
    tmp_path,
):
    snapshots = service(tmp_path)
    reference = snapshots.create(
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        fencing_token=4,
        files={"workspace/README.md": b"durable workspace"},
    )
    destination = tmp_path / "clean-host" / "workspace"
    destination.parent.mkdir()
    ledger = Ledger()
    result = snapshots.restore(
        reference=reference,
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        restore_id=uuid4(),
        fencing_token=5,
        destination=destination,
        lease_authority=LeaseAuthority(),
        ledger=ledger,
        credential_refresher=Credentials(),
    )
    assert (destination / "workspace/README.md").read_bytes() == b"durable workspace"
    assert result.fencing_token == 5
    assert result.credential_references["browser"].startswith("secret-ref://")
    assert ledger.completed[result.restore_id] == reference.digest
    assert not ledger.failed


def test_snapshot_preserves_executable_mode_without_restoring_credentials(tmp_path):
    snapshots = service(tmp_path)
    reference = snapshots.create(
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        fencing_token=4,
        files={"workspace/bin/run.sh": b"#!/bin/sh\n"},
        file_modes={"workspace/bin/run.sh": 0o700},
    )
    destination = tmp_path / "host" / "workspace"
    destination.parent.mkdir()
    snapshots.restore(
        reference=reference,
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        restore_id=uuid4(),
        fencing_token=5,
        destination=destination,
        lease_authority=LeaseAuthority(),
        ledger=Ledger(),
        credential_refresher=Credentials(),
    )
    assert (destination / "workspace/bin/run.sh").stat().st_mode & 0o777 == 0o700
    assert not list(destination.rglob("*cookie*"))


@pytest.mark.parametrize(
    "path",
    [
        "../escape",
        "/absolute",
        "workspace/../escape",
        "workspace/.env",
        "workspace/.aws/credentials",
        "browser-profile/Cookies",
        "workspace/private_key.pem",
        "workspace/token",
    ],
)
def test_snapshot_rejects_traversal_and_sensitive_identity_material(tmp_path, path):
    with pytest.raises(SnapshotError):
        service(tmp_path).create(
            tenant_id=TENANT,
            workspace_id=WORKSPACE,
            fencing_token=1,
            files={path: b"must not be captured"},
        )


def test_snapshot_rejects_naive_timestamps_and_invalid_modes(tmp_path):
    with pytest.raises(SnapshotError, match="timezone-aware"):
        service(tmp_path).create(
            tenant_id=TENANT,
            workspace_id=WORKSPACE,
            fencing_token=1,
            files={"workspace/a": b"a"},
            created_at=__import__("datetime").datetime(2026, 1, 1),
        )
    with pytest.raises(SnapshotError, match="mode"):
        service(tmp_path).create(
            tenant_id=TENANT,
            workspace_id=WORKSPACE,
            fencing_token=1,
            files={"workspace/a": b"a"},
            file_modes={"workspace/a": 0o777},
        )


def test_snapshot_rejects_empty_and_oversized_inputs(tmp_path):
    snapshots = service(tmp_path)
    with pytest.raises(SnapshotError, match="between 1"):
        snapshots.create(tenant_id=TENANT, workspace_id=WORKSPACE, fencing_token=1, files={})
    with pytest.raises(SnapshotError, match="per-file"):
        snapshots.create(
            tenant_id=TENANT,
            workspace_id=WORKSPACE,
            fencing_token=1,
            files={"workspace/large": b"x" * (snapshots.MAX_FILE_BYTES + 1)},
        )


def test_snapshot_store_is_immutable_and_rejects_duplicate_identifiers(tmp_path):
    store = FilesystemSnapshotStore(tmp_path / "objects")
    snapshot_id = uuid4()
    store.put_if_absent(snapshot_id, b"encrypted")
    with pytest.raises(SnapshotConflictError):
        store.put_if_absent(snapshot_id, b"replacement")
    assert store.get(snapshot_id) == b"encrypted"


def test_restore_rejects_cross_tenant_workspace_and_stale_fencing(tmp_path):
    snapshots = service(tmp_path)
    reference = snapshots.create(
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        fencing_token=4,
        files={"workspace/a": b"a"},
    )
    args = dict(
        reference=reference,
        workspace_id=WORKSPACE,
        restore_id=uuid4(),
        fencing_token=5,
        destination=tmp_path / "host" / "workspace",
        lease_authority=LeaseAuthority(),
        ledger=Ledger(),
        credential_refresher=Credentials(),
    )
    args["destination"].parent.mkdir()
    with pytest.raises(SnapshotError, match="cross-tenant"):
        snapshots.restore(tenant_id=uuid4(), **args)
    with pytest.raises(SnapshotError, match="newer"):
        snapshots.restore(
            reference=reference,
            tenant_id=TENANT,
            workspace_id=WORKSPACE,
            restore_id=uuid4(),
            fencing_token=4,
            destination=tmp_path / "other" / "workspace",
            lease_authority=LeaseAuthority(),
            ledger=Ledger(),
            credential_refresher=Credentials(),
        )


def test_restore_requires_active_lease_before_and_after_materialization(tmp_path):
    snapshots = service(tmp_path)
    reference = snapshots.create(
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        fencing_token=4,
        files={"workspace/a": b"a"},
    )
    destination = tmp_path / "host" / "workspace"
    destination.parent.mkdir()
    ledger = Ledger()
    with pytest.raises(SnapshotError, match="lease is not active"):
        snapshots.restore(
            reference=reference,
            tenant_id=TENANT,
            workspace_id=WORKSPACE,
            restore_id=uuid4(),
            fencing_token=5,
            destination=destination,
            lease_authority=LeaseAuthority([False]),
            ledger=ledger,
            credential_refresher=Credentials(),
        )
    assert not ledger.claimed
    with pytest.raises(SnapshotError, match="revoked before publication"):
        snapshots.restore(
            reference=reference,
            tenant_id=TENANT,
            workspace_id=WORKSPACE,
            restore_id=uuid4(),
            fencing_token=5,
            destination=destination,
            lease_authority=LeaseAuthority([True, False]),
            ledger=ledger,
            credential_refresher=Credentials(),
        )
    assert not destination.exists()
    assert not list(destination.parent.glob(".*.restore-*"))


def test_restore_rejects_replayed_operation_and_non_clean_destination(tmp_path):
    snapshots = service(tmp_path)
    reference = snapshots.create(
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        fencing_token=4,
        files={"workspace/a": b"a"},
    )
    destination = tmp_path / "host" / "workspace"
    destination.parent.mkdir()
    destination.mkdir()
    ledger = Ledger()
    with pytest.raises(SnapshotConflictError, match="must not exist"):
        snapshots.restore(
            reference=reference,
            tenant_id=TENANT,
            workspace_id=WORKSPACE,
            restore_id=uuid4(),
            fencing_token=5,
            destination=destination,
            lease_authority=LeaseAuthority(),
            ledger=ledger,
            credential_refresher=Credentials(),
        )
    destination.rmdir()
    restore_id = uuid4()
    args = dict(
        reference=reference,
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        restore_id=restore_id,
        fencing_token=5,
        destination=destination,
        lease_authority=LeaseAuthority(),
        ledger=ledger,
        credential_refresher=Credentials(),
    )
    snapshots.restore(**args)
    with pytest.raises(SnapshotConflictError, match="already claimed"):
        snapshots.restore(**args)


def test_restore_failure_cleans_partial_tree_and_records_failure(tmp_path):
    snapshots = service(tmp_path)
    reference = snapshots.create(
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        fencing_token=4,
        files={"workspace/a": b"a", "workspace/b": b"b"},
    )
    destination = tmp_path / "host" / "workspace"
    destination.parent.mkdir()
    ledger = Ledger()
    with pytest.raises(RuntimeError, match="credential refresh unavailable"):
        snapshots.restore(
            reference=reference,
            tenant_id=TENANT,
            workspace_id=WORKSPACE,
            restore_id=uuid4(),
            fencing_token=5,
            destination=destination,
            lease_authority=LeaseAuthority(),
            ledger=ledger,
            credential_refresher=Credentials(error=RuntimeError("credential refresh unavailable")),
        )
    assert not destination.exists()
    assert not list(destination.parent.glob(".*.restore-*"))
    assert len(ledger.failed) == 1


def test_restore_rejects_invalid_credential_reference_payload(tmp_path):
    snapshots = service(tmp_path)
    reference = snapshots.create(
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        fencing_token=4,
        files={"workspace/a": b"a"},
    )
    destination = tmp_path / "host" / "workspace"
    destination.parent.mkdir()
    with pytest.raises(SnapshotError, match="credential references"):
        snapshots.restore(
            reference=reference,
            tenant_id=TENANT,
            workspace_id=WORKSPACE,
            restore_id=uuid4(),
            fencing_token=5,
            destination=destination,
            lease_authority=LeaseAuthority(),
            ledger=Ledger(),
            credential_refresher=Credentials(values={"browser": ""}),
        )
    assert not destination.exists()


def test_restore_rejects_tampered_ciphertext_and_modified_reference_digest(tmp_path):
    snapshots = service(tmp_path)
    reference = snapshots.create(
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        fencing_token=4,
        files={"workspace/a": b"a"},
    )
    object_path = tmp_path / "objects" / (reference.snapshot_id.hex + ".snapshot")
    ciphertext = object_path.read_bytes()
    object_path.write_bytes(ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]))
    with pytest.raises(SnapshotIntegrityError):
        snapshots.restore(
            reference=reference,
            tenant_id=TENANT,
            workspace_id=WORKSPACE,
            restore_id=uuid4(),
            fencing_token=5,
            destination=tmp_path / "host" / "workspace",
            lease_authority=LeaseAuthority(),
            ledger=Ledger(),
            credential_refresher=Credentials(),
        )


def test_filesystem_snapshot_store_rejects_symlink_root(tmp_path):
    actual = tmp_path / "actual"
    actual.mkdir()
    link = tmp_path / "link"
    link.symlink_to(actual, target_is_directory=True)
    with pytest.raises(ValueError, match="real directory"):
        FilesystemSnapshotStore(link)


class Catalog:
    def __init__(self):
        self.references = {}

    def record(self, reference):
        key = (reference.tenant_id, reference.workspace_id, reference.snapshot_id)
        if key in self.references:
            raise SnapshotConflictError("snapshot catalog entry already exists")
        self.references[key] = reference

    def get(self, tenant_id, workspace_id, snapshot_id):
        return self.references.get((tenant_id, workspace_id, snapshot_id))


def test_snapshot_catalog_records_and_requires_exact_tenant_scoped_reference(tmp_path):
    store = FilesystemSnapshotStore(tmp_path / "catalog-objects")
    catalog = Catalog()
    snapshots = WorkspaceSnapshotService(
        store=store,
        cipher=AESGCMCipher(b"e" * 32),
        signer=HMACSnapshotSigner(b"s" * 32),
        catalog=catalog,
    )
    reference = snapshots.create(
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        fencing_token=4,
        files={"workspace/a": b"catalog-bound"},
    )
    assert catalog.get(TENANT, WORKSPACE, reference.snapshot_id) == reference

    untrusted = WorkspaceSnapshotService(
        store=store,
        cipher=AESGCMCipher(b"e" * 32),
        signer=HMACSnapshotSigner(b"s" * 32),
        catalog=Catalog(),
    )

    with pytest.raises(SnapshotIntegrityError, match="catalog"):
        untrusted.restore(
            reference=reference,
            tenant_id=TENANT,
            workspace_id=WORKSPACE,
            restore_id=uuid4(),
            fencing_token=5,
            destination=tmp_path / "clean-host" / "workspace",
            lease_authority=LeaseAuthority(),
            ledger=Ledger(),
            credential_refresher=Credentials(),
        )


def test_restore_preserves_published_tree_when_ledger_completion_is_ambiguous(tmp_path):
    class AmbiguousCompletionLedger(Ledger):
        def complete(self, tenant_id, workspace_id, restore_id, snapshot_digest):
            raise RuntimeError("database connection lost after commit")

    snapshots = service(tmp_path)
    reference = snapshots.create(
        tenant_id=TENANT,
        workspace_id=WORKSPACE,
        fencing_token=4,
        files={"workspace/README.md": b"published atomically"},
    )
    destination = tmp_path / "host" / "workspace"
    destination.parent.mkdir()
    ledger = AmbiguousCompletionLedger()

    with pytest.raises(RuntimeError, match="database connection lost"):
        snapshots.restore(
            reference=reference,
            tenant_id=TENANT,
            workspace_id=WORKSPACE,
            restore_id=uuid4(),
            fencing_token=5,
            destination=destination,
            lease_authority=LeaseAuthority(),
            ledger=ledger,
            credential_refresher=Credentials(),
        )

    assert (destination / "workspace/README.md").read_bytes() == b"published atomically"
    assert not ledger.failed


class S3Body:
    def __init__(self, value):
        self.value = value
        self.closed = False

    def read(self, size):
        return self.value[:size]

    def close(self):
        self.closed = True


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.put_calls = []
        self.get_calls = []

    def put_object(self, **kwargs):
        self.put_calls.append(kwargs)
        key = (kwargs["Bucket"], kwargs["Key"])
        if key in self.objects:
            error = RuntimeError("precondition failed")
            error.response = {
                "Error": {"Code": "PreconditionFailed"},
                "ResponseMetadata": {"HTTPStatusCode": 412},
            }
            raise error
        self.objects[key] = kwargs["Body"]
        return {"ETag": '"immutable"'}

    def get_object(self, **kwargs):
        self.get_calls.append(kwargs)
        value = self.objects[(kwargs["Bucket"], kwargs["Key"])]
        return {
            "Body": S3Body(value),
            "ContentLength": len(value),
            "ServerSideEncryption": "aws:kms",
            "SSEKMSKeyId": "arn:aws:kms:eu-west-1:123456789012:key/example",
        }


def test_s3_snapshot_store_uses_conditional_create_and_sse_kms(tmp_path):
    from tinlance_agent_platform_durability.snapshots import S3SnapshotStore

    s3 = FakeS3()
    store = S3SnapshotStore(
        s3_client=s3,
        bucket="tinlance-snapshots",
        sse_kms_key_id="arn:aws:kms:eu-west-1:123456789012:key/example",
    )
    snapshot_id = uuid4()
    store.put_if_absent(snapshot_id, b"encrypted snapshot")
    with pytest.raises(SnapshotConflictError, match="already exists"):
        store.put_if_absent(snapshot_id, b"replacement")
    assert s3.put_calls[0]["IfNoneMatch"] == "*"
    assert s3.put_calls[0]["ServerSideEncryption"] == "aws:kms"
    assert s3.put_calls[0]["SSEKMSKeyId"].endswith("key/example")
    assert store.get(snapshot_id) == b"encrypted snapshot"


def test_s3_snapshot_store_rejects_invalid_prefix_and_oversized_objects():
    from tinlance_agent_platform_durability.snapshots import S3SnapshotStore

    with pytest.raises(ValueError, match="normalized"):
        S3SnapshotStore(
            s3_client=FakeS3(),
            bucket="tinlance-snapshots",
            sse_kms_key_id="arn:aws:kms:eu-west-1:123456789012:key/example",
            prefix="../escape",
        )
    store = S3SnapshotStore(
        s3_client=FakeS3(),
        bucket="tinlance-snapshots",
        sse_kms_key_id="arn:aws:kms:eu-west-1:123456789012:key/example",
    )
    with pytest.raises(ValueError, match="size limit"):
        store.put_if_absent(uuid4(), b"x" * (store.MAX_OBJECT_BYTES + 1))
