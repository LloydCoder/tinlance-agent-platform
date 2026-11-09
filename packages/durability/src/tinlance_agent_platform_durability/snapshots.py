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
from contextlib import suppress
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


class SnapshotCatalog(Protocol):
    def record(self, reference: SnapshotReference) -> None: ...
    def get(
        self, tenant_id: UUID, workspace_id: UUID, snapshot_id: UUID
    ) -> SnapshotReference | None: ...


class RestoreLeaseAuthority(Protocol):
    def assert_active(self, tenant_id: UUID, workspace_id: UUID, fencing_token: int) -> bool: ...


class RestoreLedger(Protocol):
    def begin(
        self,
        tenant_id: UUID,
        workspace_id: UUID,
        restore_id: UUID,
        snapshot_id: UUID,
        fencing_token: int,
    ) -> bool: ...
    def complete(
        self, tenant_id: UUID, workspace_id: UUID, restore_id: UUID, snapshot_digest: str
    ) -> None: ...
    def fail(
        self, tenant_id: UUID, workspace_id: UUID, restore_id: UUID, reason_code: str
    ) -> None: ...


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



class KMSAESGCMCipher:
    """Envelope encryption using an AWS KMS-managed AES-256 data key per snapshot."""

    MAGIC = b"TLW6"
    MAX_ENCRYPTED_DATA_KEY_BYTES = 65_536

    def __init__(self, *, kms_client: object, key_arn: str) -> None:
        if not isinstance(key_arn, str) or not key_arn.startswith("arn:aws:kms:"):
            raise ValueError("snapshot KMS key must be an AWS KMS key ARN")
        self._kms = kms_client
        self._key_arn = key_arn

    @staticmethod
    def _context(associated_data: bytes) -> dict[str, str]:
        if not isinstance(associated_data, bytes) or not associated_data:
            raise ValueError("snapshot associated data must be non-empty bytes")
        return {
            "purpose": "tinlance-workspace-snapshot-v1",
            "associated_data_sha256": hashlib.sha256(associated_data).hexdigest(),
        }

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        if not isinstance(plaintext, bytes):
            raise TypeError("snapshot plaintext must be bytes")
        context = self._context(associated_data)
        result = self._kms.generate_data_key(  # type: ignore[attr-defined]
            KeyId=self._key_arn,
            KeySpec="AES_256",
            EncryptionContext=context,
        )
        data_key = result.get("Plaintext")
        encrypted_key = result.get("CiphertextBlob")
        if (
            not isinstance(data_key, bytes)
            or len(data_key) != 32
            or not isinstance(encrypted_key, bytes)
            or not encrypted_key
            or len(encrypted_key) > self.MAX_ENCRYPTED_DATA_KEY_BYTES
        ):
            raise RuntimeError("KMS returned an invalid snapshot data key")
        nonce = os.urandom(12)
        ciphertext = AESGCM(data_key).encrypt(nonce, plaintext, associated_data)
        return b"".join(
            (
                self.MAGIC,
                len(encrypted_key).to_bytes(4, "big"),
                encrypted_key,
                nonce,
                ciphertext,
            )
        )

    def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
        minimum = len(self.MAGIC) + 4 + 1 + 12 + 16
        if not isinstance(ciphertext, bytes) or len(ciphertext) < minimum:
            raise SnapshotIntegrityError("KMS snapshot envelope is truncated")
        if not ciphertext.startswith(self.MAGIC):
            raise SnapshotIntegrityError("KMS snapshot envelope version is invalid")
        key_length = int.from_bytes(ciphertext[4:8], "big")
        if not 1 <= key_length <= self.MAX_ENCRYPTED_DATA_KEY_BYTES:
            raise SnapshotIntegrityError("KMS encrypted data key length is invalid")
        key_start = 8
        nonce_start = key_start + key_length
        payload_start = nonce_start + 12
        if len(ciphertext) < payload_start + 16:
            raise SnapshotIntegrityError("KMS snapshot envelope is truncated")
        encrypted_key = ciphertext[key_start:nonce_start]
        nonce = ciphertext[nonce_start:payload_start]
        encrypted_payload = ciphertext[payload_start:]
        context = self._context(associated_data)
        result = self._kms.decrypt(  # type: ignore[attr-defined]
            CiphertextBlob=encrypted_key,
            EncryptionContext=context,
        )
        data_key = result.get("Plaintext")
        if not isinstance(data_key, bytes) or len(data_key) != 32:
            raise SnapshotIntegrityError("KMS returned an invalid decrypted snapshot key")
        try:
            return AESGCM(data_key).decrypt(nonce, encrypted_payload, associated_data)
        except Exception as exc:
            raise SnapshotIntegrityError("KMS snapshot authenticated decryption failed") from exc


class KMSSnapshotSigner:
    """HMAC-SHA-256 signatures backed by a dedicated AWS KMS HMAC key."""

    def __init__(self, *, kms_client: object, key_arn: str) -> None:
        if not isinstance(key_arn, str) or not key_arn.startswith("arn:aws:kms:"):
            raise ValueError("snapshot signing key must be an AWS KMS key ARN")
        self._kms = kms_client
        self._key_arn = key_arn

    def sign(self, payload: bytes) -> bytes:
        if not isinstance(payload, bytes):
            raise TypeError("snapshot signature payload must be bytes")
        result = self._kms.generate_mac(  # type: ignore[attr-defined]
            KeyId=self._key_arn,
            Message=payload,
            MacAlgorithm="HMAC_SHA_256",
        )
        signature = result.get("Mac")
        if not isinstance(signature, bytes) or len(signature) != 32:
            raise RuntimeError("KMS returned an invalid HMAC snapshot signature")
        return signature

    def verify(self, payload: bytes, signature: bytes) -> bool:
        if not isinstance(payload, bytes) or not isinstance(signature, bytes):
            return False
        result = self._kms.verify_mac(  # type: ignore[attr-defined]
            KeyId=self._key_arn,
            Message=payload,
            Mac=signature,
            MacAlgorithm="HMAC_SHA_256",
        )
        valid = result.get("MacValid")
        if not isinstance(valid, bool):
            raise RuntimeError("KMS returned an invalid MAC verification result")
        return valid


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



class S3SnapshotStore:
    """Immutable S3 object storage with conditional creation and SSE-KMS."""

    MAX_OBJECT_BYTES = 160 * 1024 * 1024

    def __init__(
        self,
        *,
        s3_client: object,
        bucket: str,
        sse_kms_key_id: str,
        prefix: str = "tinlance/workspace-snapshots/v1",
    ) -> None:
        if not isinstance(bucket, str) or not bucket or "/" in bucket:
            raise ValueError("snapshot S3 bucket name is invalid")
        if not isinstance(sse_kms_key_id, str) or not sse_kms_key_id.startswith("arn:aws:kms:"):
            raise ValueError("snapshot S3 storage requires an AWS KMS key ARN")
        if (
            not isinstance(prefix, str)
            or not prefix
            or prefix.startswith("/")
            or any(part in ("", ".", "..") for part in prefix.split("/"))
        ):
            raise ValueError("snapshot S3 prefix must be a normalized relative key prefix")
        self._s3 = s3_client
        self._bucket = bucket
        self._kms_key_id = sse_kms_key_id
        self._prefix = prefix

    def _key(self, snapshot_id: UUID) -> str:
        if not isinstance(snapshot_id, UUID):
            raise TypeError("snapshot_id must be a UUID")
        return f"{self._prefix}/{snapshot_id.hex}.snapshot"

    def put_if_absent(self, snapshot_id: UUID, value: bytes) -> None:
        if not isinstance(value, bytes) or not value or len(value) > self.MAX_OBJECT_BYTES:
            raise ValueError(
                "snapshot object must be non-empty bytes within the storage size limit"
            )
        try:
            response = self._s3.put_object(  # type: ignore[attr-defined]
                Bucket=self._bucket,
                Key=self._key(snapshot_id),
                Body=value,
                ContentType="application/octet-stream",
                IfNoneMatch="*",
                ServerSideEncryption="aws:kms",
                SSEKMSKeyId=self._kms_key_id,
            )
            if (
                response.get("ServerSideEncryption") != "aws:kms"
                or response.get("SSEKMSKeyId") != self._kms_key_id
            ):
                raise RuntimeError("S3 did not confirm the configured snapshot SSE-KMS key")
        except Exception as exc:
            response = getattr(exc, "response", {})
            error = response.get("Error", {}) if isinstance(response, dict) else {}
            metadata = response.get("ResponseMetadata", {}) if isinstance(response, dict) else {}
            if error.get("Code") in {
                "PreconditionFailed",
                "ConditionalRequestConflict",
            } or metadata.get("HTTPStatusCode") in {409, 412}:
                raise SnapshotConflictError("snapshot identifier already exists in S3") from exc
            raise

    def get(self, snapshot_id: UUID) -> bytes:
        try:
            response = self._s3.get_object(  # type: ignore[attr-defined]
                Bucket=self._bucket,
                Key=self._key(snapshot_id),
            )
        except Exception as exc:
            response = getattr(exc, "response", {})
            error = response.get("Error", {}) if isinstance(response, dict) else {}
            metadata = response.get("ResponseMetadata", {}) if isinstance(response, dict) else {}
            if (
                error.get("Code") in {"NoSuchKey", "NotFound"}
                or metadata.get("HTTPStatusCode") == 404
            ):
                raise SnapshotError("snapshot object does not exist in S3") from exc
            raise
        body = response.get("Body")
        if (
            response.get("ServerSideEncryption") != "aws:kms"
            or response.get("SSEKMSKeyId") != self._kms_key_id
        ):
            if body is not None:
                body.close()
            raise SnapshotIntegrityError(
                "S3 snapshot object is not encrypted with the configured KMS key"
            )
        length = response.get("ContentLength")
        if (
            body is None
            or isinstance(length, bool)
            or not isinstance(length, int)
            or length < 1
            or length > self.MAX_OBJECT_BYTES
        ):
            if body is not None:
                body.close()
            raise SnapshotIntegrityError("S3 snapshot object type or size is invalid")
        try:
            value = body.read(self.MAX_OBJECT_BYTES + 1)
        finally:
            body.close()
        if (
            not isinstance(value, bytes)
            or len(value) != length
            or len(value) > self.MAX_OBJECT_BYTES
        ):
            raise SnapshotIntegrityError("S3 snapshot object length does not match its metadata")
        return value


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
    _SENSITIVE_SEGMENTS = frozenset(
        {
            ".aws",
            ".azure",
            ".gcloud",
            ".kube",
            ".ssh",
            ".env",
            ".env.local",
            "secrets",
            "secret",
            "credentials",
            "credential",
            "tokens",
            "token",
            "cookies",
            "cookies-journal",
            "login data",
            "web data",
            "local state",
            "key4.db",
            "cert9.db",
            "private",
            "private_key",
        }
    )

    def __init__(
        self,
        *,
        store: SnapshotObjectStore,
        cipher: SnapshotCipher,
        signer: SnapshotSigner,
        catalog: SnapshotCatalog | None = None,
    ) -> None:
        self._store = store
        self._cipher = cipher
        self._signer = signer
        self._catalog = catalog

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
        self,
        *,
        tenant_id: UUID,
        workspace_id: UUID,
        fencing_token: int,
        files: Mapping[str, bytes],
        file_modes: Mapping[str, int] | None = None,
        created_at: datetime | None = None,
    ) -> SnapshotReference:
        self._identity(tenant_id, workspace_id, fencing_token)
        if not isinstance(files, Mapping) or not files or len(files) > self.MAX_FILES:
            raise SnapshotError("snapshot must contain between 1 and 10000 files")
        modes = file_modes or {}
        if not isinstance(modes, Mapping) or not set(modes).issubset(files):
            raise SnapshotError("file modes may only refer to included snapshot files")
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
            entries.append(
                {
                    "path": path,
                    "mode": mode,
                    "size": len(content),
                    "sha256": hashlib.sha256(content).hexdigest(),
                    "data": base64.b64encode(content).decode("ascii"),
                }
            )
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
        envelope = json.dumps(
            {
                "payload": base64.b64encode(payload).decode("ascii"),
                "signature": base64.b64encode(signature).decode("ascii"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        ciphertext = self._cipher.encrypt(envelope, self._aad(snapshot_id, tenant_id, workspace_id))
        self._store.put_if_absent(snapshot_id, ciphertext)
        reference = SnapshotReference(
            snapshot_id=snapshot_id,
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            fencing_token=fencing_token,
            created_at=timestamp.astimezone(UTC),
            digest=hashlib.sha256(payload).hexdigest(),
        )
        if self._catalog is not None:
            self._catalog.record(reference)
        return reference

    def _read_verified(self, reference: SnapshotReference) -> dict[str, object]:
        if self._catalog is not None:
            stored = self._catalog.get(
                reference.tenant_id, reference.workspace_id, reference.snapshot_id
            )
            if stored != reference:
                raise SnapshotIntegrityError(
                    "snapshot reference is absent or differs from its catalog"
                )
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
        if not isinstance(decoded, dict):
            raise SnapshotIntegrityError("snapshot payload must be an object")
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
        self,
        *,
        reference: SnapshotReference,
        tenant_id: UUID,
        workspace_id: UUID,
        restore_id: UUID,
        fencing_token: int,
        destination: Path,
        lease_authority: RestoreLeaseAuthority,
        ledger: RestoreLedger,
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
        published = False
        staging_created = False
        target_reserved = False
        staging: Path | None = None
        try:
            if target.exists() or target.is_symlink():
                raise SnapshotConflictError("restore destination must not exist on the clean host")
            parent = target.parent.resolve(strict=True)
            target = parent / target.name
            staging = parent / f".{target.name}.restore-{restore_id.hex}"
            if staging.exists() or staging.is_symlink():
                raise SnapshotConflictError("restore staging path already exists")
            staging.mkdir(mode=0o700)
            staging_created = True
            total = 0
            seen: set[str] = set()
            for entry in entries:
                if not isinstance(entry, dict):
                    raise SnapshotIntegrityError("snapshot file entry is malformed")
                raw_path = entry.get("path")
                if not isinstance(raw_path, str):
                    raise SnapshotIntegrityError("snapshot file path must be text")
                path = self._safe_path(raw_path)
                if path in seen:
                    raise SnapshotIntegrityError("snapshot contains duplicate file paths")
                seen.add(path)
                data = base64.b64decode(entry.get("data", ""), validate=True)
                declared_size = entry.get("size")
                if (
                    isinstance(declared_size, bool)
                    or not isinstance(declared_size, int)
                    or len(data) != declared_size
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
                not isinstance(k, str)
                or not isinstance(v, str)
                or not k
                or not (v.startswith("secret-ref://") or v.startswith("arn:aws:secretsmanager:"))
                for k, v in credentials.items()
            ):
                raise SnapshotError(
                    "credential references must be opaque secret references, never secret values"
                )
            if not lease_authority.assert_active(tenant_id, workspace_id, fencing_token):
                raise SnapshotError("restore lease was revoked before publication")
            # Reserve the final path exclusively, then atomically replace the empty
            # reservation with the fully materialized tree.
            target.mkdir(mode=0o700)
            target_reserved = True
            os.replace(staging, target)
            target_reserved = False
            published = True
            try:
                ledger.complete(tenant_id, workspace_id, restore_id, reference.digest)
            except Exception:
                # The commit result may be ambiguous after a network failure. The SQL
                # transition is idempotent, so retry once before reporting uncertainty.
                ledger.complete(tenant_id, workspace_id, restore_id, reference.digest)
            return RestoreResult(
                restore_id=restore_id,
                snapshot_id=reference.snapshot_id,
                destination=target,
                fencing_token=fencing_token,
                credential_references=dict(credentials),
            )
        except BaseException as exc:
            if staging_created and staging is not None and staging.exists():
                shutil.rmtree(staging)
            if not published:
                if target_reserved and target.exists() and not any(target.iterdir()):
                    target.rmdir()
                with suppress(Exception):
                    ledger.fail(tenant_id, workspace_id, restore_id, type(exc).__name__)
            # Once the destination has been atomically published, never delete it
            # because a database acknowledgement was lost. Keep it for reconciliation.
            raise
