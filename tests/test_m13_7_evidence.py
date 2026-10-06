from uuid import uuid4

import pytest

from tinlance_agent_platform_evidence import InMemoryEvidenceStore, attest


class Signer:
    def sign(self, message: bytes) -> bytes:
        return b"sig:" + message

    def verify(self, message: bytes, signature: bytes) -> bool:
        return signature == self.sign(message)


def test_evidence_hash_chain_is_tamper_evident() -> None:
    store = InMemoryEvidenceStore()
    run_id = uuid4()
    first = store.append("tenant-a", run_id, "first", actor_id="agent-a")
    second = store.append("tenant-a", run_id, "second", actor_id="agent-a")
    assert second.previous_hash == first.record_hash
    assert second.sequence == first.sequence + 1
    assert store.verify("tenant-a", run_id)

    store._items[0] = first.__class__(
        first.evidence_id,
        first.tenant_id,
        first.run_id,
        first.content_hash,
        "tampered",
        first.sequence,
        first.execution_id,
        first.actor_id,
        first.provenance,
        first.occurred_at,
        first.previous_hash,
        first.record_hash,
    )
    assert not store.verify("tenant-a", run_id)


def test_evidence_attestation_verifies_external_signature() -> None:
    store = InMemoryEvidenceStore()
    evidence = store.append("tenant-a", uuid4(), "decision", actor_id="agent-a")
    receipt = attest(evidence.evidence_id, evidence.record_hash, "kms-key-1", Signer())
    assert receipt.verify(Signer())
    tampered = receipt.__class__(
        uuid4(), receipt.record_hash, receipt.signer_id, receipt.signature
    )
    assert not tampered.verify(Signer())


def test_evidence_rejects_unbounded_or_invalid_actor() -> None:
    store = InMemoryEvidenceStore()
    with pytest.raises(ValueError):
        store.append("tenant-a", uuid4(), "x", actor_id=" agent-a ")


def test_audit_chain_detects_tampering() -> None:
    from tinlance_agent_platform_evidence import InMemoryAuditStore

    store = InMemoryAuditStore()
    run_id = uuid4()
    first = store.append("tenant-a", run_id, "agent-a", "write", "doc:1", "allow")
    second = store.append("tenant-a", run_id, "agent-a", "write", "doc:2", "deny")
    assert second.previous_hash == first.record_hash
    assert second.sequence == first.sequence + 1
    assert store.verify("tenant-a", run_id)
