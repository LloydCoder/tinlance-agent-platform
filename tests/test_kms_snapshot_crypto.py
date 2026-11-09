from __future__ import annotations

import hashlib
import hmac

import pytest

from tinlance_agent_platform_durability.snapshots import (
    KMSAESGCMCipher,
    KMSSnapshotSigner,
    SnapshotIntegrityError,
)


class FakeKMS:
    def __init__(self):
        self.data_keys = {}
        self.calls = []
        self.mac_key = b"k" * 32

    def generate_data_key(self, **kwargs):
        self.calls.append(("generate_data_key", kwargs))
        plaintext = b"d" * 32
        encrypted = b"encrypted-data-key"
        self.data_keys[encrypted] = plaintext
        return {"Plaintext": plaintext, "CiphertextBlob": encrypted}

    def decrypt(self, **kwargs):
        self.calls.append(("decrypt", kwargs))
        return {"Plaintext": self.data_keys[kwargs["CiphertextBlob"]]}

    def generate_mac(self, **kwargs):
        self.calls.append(("generate_mac", kwargs))
        return {"Mac": hmac.new(self.mac_key, kwargs["Message"], hashlib.sha256).digest()}

    def verify_mac(self, **kwargs):
        self.calls.append(("verify_mac", kwargs))
        expected = hmac.new(self.mac_key, kwargs["Message"], hashlib.sha256).digest()
        return {"MacValid": hmac.compare_digest(expected, kwargs["Mac"])}


def test_kms_envelope_encryption_round_trips_and_binds_associated_data():
    kms = FakeKMS()
    cipher = KMSAESGCMCipher(
        kms_client=kms,
        key_arn="arn:aws:kms:eu-west-1:123456789012:key/00000000-0000-0000-0000-000000000001",
    )
    associated_data = b"tenant-a/workspace-1/snapshot-1"
    encrypted = cipher.encrypt(b"snapshot bytes", associated_data)
    assert encrypted.startswith(KMSAESGCMCipher.MAGIC)
    assert cipher.decrypt(encrypted, associated_data) == b"snapshot bytes"
    assert kms.calls[0][1]["EncryptionContext"]["associated_data_sha256"] == (
        hashlib.sha256(associated_data).hexdigest()
    )
    with pytest.raises(SnapshotIntegrityError):
        cipher.decrypt(encrypted, b"tenant-b/workspace-1/snapshot-1")


def test_kms_cipher_rejects_malformed_envelope_before_kms_decrypt():
    kms = FakeKMS()
    cipher = KMSAESGCMCipher(kms_client=kms, key_arn="arn:aws:kms:eu-west-1:123:key/abc")
    with pytest.raises(SnapshotIntegrityError):
        cipher.decrypt(b"bad", b"aad")
    assert not any(name == "decrypt" for name, _ in kms.calls)


def test_kms_signer_uses_kms_hmac_and_verifies_signature():
    kms = FakeKMS()
    signer = KMSSnapshotSigner(
        kms_client=kms,
        key_arn="arn:aws:kms:eu-west-1:123456789012:key/00000000-0000-0000-0000-000000000002",
    )
    payload = b"canonical snapshot payload"
    signature = signer.sign(payload)
    assert signer.verify(payload, signature)
    assert not signer.verify(payload + b"tamper", signature)
    assert all(call[1]["MacAlgorithm"] == "HMAC_SHA_256" for call in kms.calls)


def test_kms_signer_rejects_invalid_mac_response():
    class InvalidKMS(FakeKMS):
        def generate_mac(self, **kwargs):
            return {}

    signer = KMSSnapshotSigner(kms_client=InvalidKMS(), key_arn="arn:aws:kms:eu-west-1:123:key/abc")
    with pytest.raises(RuntimeError, match="MAC"):
        signer.sign(b"payload")
