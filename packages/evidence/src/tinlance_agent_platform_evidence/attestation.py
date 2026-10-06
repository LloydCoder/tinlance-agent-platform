from dataclasses import dataclass
from typing import Protocol
from uuid import UUID


class EvidenceSigner(Protocol):
    def sign(self, message: bytes) -> bytes: ...

    def verify(self, message: bytes, signature: bytes) -> bool: ...


@dataclass(frozen=True, slots=True)
class EvidenceAttestation:
    evidence_id: UUID
    record_hash: str
    signer_id: str
    signature: bytes

    def verify(self, signer: EvidenceSigner) -> bool:
        if not self.signer_id or not self.record_hash or not self.signature:
            return False
        return signer.verify(self.record_hash.encode(), self.signature)


def attest(
    evidence_id: UUID,
    record_hash: str,
    signer_id: str,
    signer: EvidenceSigner,
) -> EvidenceAttestation:
    if not signer_id or signer_id != signer_id.strip():
        raise ValueError("signer identifier must be normalized")
    if not record_hash:
        raise ValueError("record hash is required")
    signature = signer.sign(record_hash.encode())
    if not signature:
        raise ValueError("signer returned an empty signature")
    return EvidenceAttestation(evidence_id, record_hash, signer_id, signature)
