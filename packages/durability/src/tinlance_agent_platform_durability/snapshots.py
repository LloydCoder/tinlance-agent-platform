"""Encrypted, tenant-bound persistent workspace snapshots and clean-host restore."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import shutil
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Protocol
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class SnapshotError(ValueError):
    """The snapshot request or its authenticated content is invalid."""


class SnapshotIntegrityError(SnapshotError):
    """The stored snapshot failed authenticated integrity verification."""


class SnapshotConflictError(RuntimeError):
    """The snapshot or restore operation conflicts with an existing object."""


class SnapshotCipher(Protocol):
    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes: ...
    def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes: ...


class SnapshotSigner(Protocol):
    def sign(self, payload: bytes) -> bytes: ...
    def verify(self, payload: bytes, signature: bytes) -> bool: ...


class SnapshotObjectStore(Protocol):
    def put_if_absent(self, snapshot_id: UUID, value: bytes) -> None: ...
    def get(self, snapshot_id: UUID) -> bytes: ...


class RestoreLeaseAuthority(Protocol):
    def assert_active(self, tenant_id: UUID, workspace_id: UUID, fencing_token: int) -> bool: ...


class RestoreLedger(Protocol):
    def begin(
        self, tenant_id: UUID, workspace_id: UUID, restore_id: UUID,
        snapshot_id: UUID, fencing_token: int,
    ) -> bool: ...
    def complete(self, restore_id: UUID, snapshot_digest: str) -> None: ...
    def fail(self, restore_id: UUID, reason_code: str) -> None: ...


class CredentialRefresher(Protocol):
    def refresh(
        self, tenant_id: UUID, workspace_id: UUID, fencing_token: int
    ) -> Mapping[str, str]: ...


@dataclass(frozen=True, slots=True)
class SnapshotReference:
    snapshot_id: UUID
    tenant_id: UUID
    workspace_id: UUID
    fencing_token: int
    created_at: datetime
    digest: str


@dataclass(frozen=True, slots=True)
class RestoreResult:
    restore_id: UUID
    snapshot_id: UUID
    destination: Path
    fencing_token: int
    credential_references: Mapping[str, str]


class AESGCMCipher:
    """AES-256-GCM using a KMS-issued data key supplied by the caller."""

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError("snapshot encryption key must be exactly 32 bytes")
        self._key = key

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(self._key).encrypt(nonce, plaintext, associated_data)

    def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
        if not isinstance(ciphertext, bytes) or len(ciphertext) < 12 + 16:
            raise SnapshotIntegrityError("snapshot ciphertext is truncated")
        try:
            return AESGCM(self._key).decrypt(ciphertext[:12], ciphertext[12:], associated_data)
        except Exception as exc:
            raise SnapshotIntegrityError("snapshot authenticated decryption failed") from exc


class HMACSnapshotSigner:
    """HMAC-SHA-256 signer; key material must be independently KMS-managed."""

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, bytes) or len(key) < 32:
            raise ValueError("snapshot signing key must contain at least 32 bytes")
        self._key = key

    def sign(self, payload: bytes) -> bytes:
        return hmac.new(self._key, payload, hashlib.sha256).digest()

    def verify(self, payload: bytes, signature: bytes) -> bool:
        return hmac.compare_digest(self.sign(payload), signature)


class FilesystemSnapshotStore:
    """Atomic, immutable local object store for controlled-host and test deployments."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self._root.is_symlink() or not self._root.is_dir():
            raise ValueError("snapshot store root must be a real directory")
        os.chmod(self._root, 0o700)

    def _path(self, snapshot_id: UUID) -> Path:
        if not isinstance(snapshot_id, UUID):
            raise TypeError("snapshot_id must be a UUID")
        return self._root / (snapshot_id.hex + ".snapshot")

    def put_if_absent(self, snapshot_id: UUID, value: bytes) -> None:
        if not isinstance(value, bytes) or not value:
            raise ValueError("snapshot object must be non-empty bytes")
        path = self._path(snapshot_id)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError as exc:
            raise SnapshotConflictError("snapshot identifier already exists") from exc
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            directory_fd = os.open(self._root, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def get(self, snapshot_id: UUID) -> bytes:
        path = self._path(snapshot_id)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(path, flags)
        except FileNotFoundError as exc:
            raise SnapshotError("snapshot object does not exist") from exc
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > 160 * 1024 * 1024:
                raise SnapshotIntegrityError("snapshot object type or size is invalid")
            return stream.read()


class WorkspaceSnapshotService:
    """Creates authenticated snapshots and restores them under a newer lease fence.

    Only regular workspace files are captured. Credentials, browser authentication
    state, tokens, private keys and machine-local identity material are excluded.
    Secrets are reacquired through CredentialRefresher after clean-host materialization.
    """

    SCHEMA_VERSION = 1
    MAX_FILES = 10_000
    MAX_FILE_BYTES = 16 * 1024 * 1024
    MAX_TOTAL_BYTES = 128 * 1024 * 1024
    _SENSITIVE_SEGMENTS = frozenset({
        ".aws", ".azure", ".gcloud", ".kube", ".ssh", ".env", ".env.local",
        "secrets", "secret", "credentials", "credential", "tokens", "token",
        "cookies", "cookies-journal", "login data", "web data", "local state",
        "key4.db", "cert9.db", "private", "private_key",
    })

    def __init__(
        self, *, store: SnapshotObjectStore, cipher: SnapshotCipher,
        signer: SnapshotSigner,
    ) -> None:
        self._store = store
        self._cipher = cipher
        self._signer = signer

    @classmethod
    def _safe_path(cls, value: str) -> str:
        if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
            raise SnapshotError("snapshot file path is invalid")
        path = PurePosixPath(value)
        if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
            raise SnapshotError("snapshot paths must be normalized relative paths")
        sensitive = any(
            part.casefold() in cls._SENSITIVE_SEGMENTS
            or part.casefold().startswith(".env")
            or "private_key" in part.casefold()
            or part.casefold() in {"id_rsa", "id_ed25519", "authorized_keys"}
            or part.casefold().endswith((".pem", ".p12", ".pfx", ".key"))
            for part in path.parts
        )
        if sensitive:
            raise SnapshotError("snapshot path contains excluded credential or identity material")
        normalized = path.as_posix()
        if normalized != value or len(normalized) > 1024:
            raise SnapshotError("snapshot path is not canonical")
        return normalized

    @staticmethod
    def _identity(tenant_id: UUID, workspace_id: UUID, fencing_token: int) -> None:
        if not isinstance(tenant_id, UUID) or not isinstance(workspace_id, UUID):
            raise TypeError("tenant_id and workspace_id must be UUID values")
        if (
            isinstance(fencing_token, bool)
            or not isinstance(fencing_token, int)
            or fencing_token < 1
        ):
            raise ValueError("fencing_token must be a positive integer")

    @staticmethod
    def _aad(snapshot_id: UUID, tenant_id: UUID, workspace_id: UUID) -> bytes:
        return f"tinlance-workspace-snapshot:v1:{snapshot_id}:{tenant_id}:{workspace_id}".encode()

    def create(
        self, *, tenant_id: UUID, workspace_id: UUID, fencing_token: int,
        files: Mapping[str, bytes], file_modes: Mapping[str, int] | None = None,
        created_at: datetime | None = None,
    ) -> SnapshotReference:
        self._identity(tenant_id, workspace_id, fencing_token)
        if not isinstance(files, Mapping) or not files or len(files) > self.MAX_FILES:
            raise SnapshotError("snapshot must contain between 1 and 10000 files")
        modes = file_modes or {}
        entries: list[dict[str, object]] = []
        total = 0
        seen: set[str] = set()
        for raw_path, content in sorted(files.items()):
            path = self._safe_path(raw_path)
            if path in seen:
                raise SnapshotError("snapshot contains duplicate normalized paths")
            seen.add(path)
            if not isinstance(content, bytes):
                raise SnapshotError("snapshot file content must be bytes")
            if len(content) > self.MAX_FILE_BYTES:
                raise SnapshotError("snapshot file exceeds the per-file size limit")
            total += len(content)
            if total > self.MAX_TOTAL_BYTES:
                raise SnapshotError("snapshot exceeds the total size limit")
            mode = modes.get(raw_path, 0o600)
            if isinstance(mode, bool) or mode not in (0o600, 0o644, 0o700, 0o755):
                raise SnapshotError("snapshot file mode is not an allowed regular-file mode")
            entries.append({
                "path": path,
                "mode": mode,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "data": base64.b64encode(content).decode("ascii"),
            })
        timestamp = created_at or datetime.now(UTC)
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise SnapshotError("snapshot timestamp must be timezone-aware")
        snapshot_id = uuid4()
        payload_object = {
            "schema_version": self.SCHEMA_VERSION,
            "snapshot_id": str(snapshot_id),
            "tenant_id": str(tenant_id),
            "workspace_id": str(workspace_id),
            "fencing_token": fencing_token,
            "created_at": timestamp.astimezone(UTC).isoformat(),
            "files": entries,
        }
        payload = json.dumps(
            payload_object, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        signature = self._signer.sign(payload)
        envelope = json.dumps({
            "payload": base64.b64encode(payload).decode("ascii"),
            "signature": base64.b64encode(signature).decode("ascii"),
        }, sort_keys=True, separators=(",", ":")).encode("ascii")
        ciphertext = self._cipher.encrypt(
            envelope, self._aad(snapshot_id, tenant_id, workspace_id)
        )
        self._store.put_if_absent(snapshot_id, ciphertext)
        return SnapshotReference(
            snapshot_id=snapshot_id,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            fencing_token=fencing_token,
            created_at=timestamp.astimezone(UTC),
            digest=hashlib.sha256(payload).hexdigest(),
        )

    def _read_verified(self, reference: SnapshotReference) -> dict[str, object]:
        ciphertext = self._store.get(reference.snapshot_id)
        envelope_bytes = self._cipher.decrypt(
            ciphertext,
            self._aad(reference.snapshot_id, reference.tenant_id, reference.workspace_id),
        )
        try:
            envelope = json.loads(envelope_bytes)
            payload = base64.b64decode(envelope["payload"], validate=True)
            signature = base64.b64decode(envelope["signature"], validate=True)
            decoded = json.loads(payload)
        except (KeyError, TypeError, ValueError, UnicodeDecodeError) as exc:
            raise SnapshotIntegrityError("snapshot envelope is malformed") from exc
        if not self._signer.verify(payload, signature):
            raise SnapshotIntegrityError("snapshot signature is invalid")
        if not hmac.compare_digest(hashlib.sha256(payload).hexdigest(), reference.digest):
            raise SnapshotIntegrityError("snapshot digest does not match its reference")
        if (
            decoded.get("schema_version") != self.SCHEMA_VERSION
            or decoded.get("snapshot_id") != str(reference.snapshot_id)
            or decoded.get("tenant_id") != str(reference.tenant_id)
            or decoded.get("workspace_id") != str(reference.workspace_id)
            or decoded.get("fencing_token") != reference.fencing_token
        ):
            raise SnapshotIntegrityError("snapshot provenance does not match its reference")
        return decoded

    def restore(
        self, *, reference: SnapshotReference, tenant_id: UUID, workspace_id: UUID,
        restore_id: UUID, fencing_token: int, destination: Path,
        lease_authority: RestoreLeaseAuthority, ledger: RestoreLedger,
        credential_refresher: CredentialRefresher,
    ) -> RestoreResult:
        self._identity(tenant_id, workspace_id, fencing_token)
        if not isinstance(reference, SnapshotReference) or not isinstance(restore_id, UUID):
            raise TypeError("reference and restore_id have invalid types")
        if reference.tenant_id != tenant_id or reference.workspace_id != workspace_id:
            raise SnapshotError("cross-tenant or cross-workspace restore is denied")
        if fencing_token <= reference.fencing_token:
            raise SnapshotError("restore requires a fencing token newer than the snapshot")
        if not lease_authority.assert_active(tenant_id, workspace_id, fencing_token):
            raise SnapshotError("restore lease is not active")
        decoded = self._read_verified(reference)
        entries = decoded.get("files")
        if not isinstance(entries, list) or not entries or len(entries) > self.MAX_FILES:
            raise SnapshotIntegrityError("snapshot file manifest is invalid")
        if not ledger.begin(
            tenant_id, workspace_id, restore_id, reference.snapshot_id, fencing_token
        ):
            raise SnapshotConflictError("restore operation was already claimed")
        target = Path(destination)
        if target.exists() or target.is_symlink():
            ledger.fail(restore_id, "destination_not_clean")
            raise SnapshotConflictError("restore destination must not exist on the clean host")
        parent = target.parent.resolve(strict=True)
        target = parent / target.name
        staging = parent / f".{target.name}.restore-{restore_id.hex}"
        if staging.exists() or staging.is_symlink():
            ledger.fail(restore_id, "staging_path_exists")
            raise SnapshotConflictError("restore staging path already exists")
        staging.mkdir(mode=0o700)
        try:
            total = 0
            seen: set[str] = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    raise SnapshotIntegrityError("snapshot file entry is malformed")
                path = self._safe_path(entry.get("path"))
                if path in seen:
                    raise SnapshotIntegrityError("snapshot contains duplicate file paths")
                seen.add(path)
                data = base64.b64decode(entry.get("data", ""), validate=True)
                if (
                    len(data) != entry.get("size")
                    or len(data) > self.MAX_FILE_BYTES
                    or hashlib.sha256(data).hexdigest() != entry.get("sha256")
                ):
                    raise SnapshotIntegrityError("snapshot file digest or size is invalid")
                total += len(data)
                if total > self.MAX_TOTAL_BYTES:
                    raise SnapshotIntegrityError("snapshot total size limit exceeded")
                mode = entry.get("mode")
                if isinstance(mode, bool) or mode not in (0o600, 0o644, 0o700, 0o755):
                    raise SnapshotIntegrityError("snapshot file mode is invalid")
                output = staging.joinpath(*PurePosixPath(path).parts)
                output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                with output.open("xb") as stream:
                    stream.write(data)
                os.chmod(output, mode)
            credentials = credential_refresher.refresh(tenant_id, workspace_id, fencing_token)
            if not isinstance(credentials, Mapping) or any(
                not isinstance(k, str) or not isinstance(v, str) or not k or not v
                for k, v in credentials.items()
            ):
                raise SnapshotError(
                    "credential refresher must return non-empty credential references"
                )
            if not lease_authority.assert_active(tenant_id, workspace_id, fencing_token):
                raise SnapshotError("restore lease was revoked before publication")
            if target.exists() or target.is_symlink():
                raise SnapshotConflictError("restore destination appeared before publication")
            os.replace(staging, target)
            ledger.complete(restore_id, reference.digest)
            return RestoreResult(
                restore_id=restore_id, snapshot_id=reference.snapshot_id,
                destination=target, fencing_token=fencing_token,
                credential_references=dict(credentials),
            )
        except BaseException as exc:
            if staging.exists():
                shutil.rmtree(staging)
            ledger.fail(restore_id, type(exc).__name__)
            raise
