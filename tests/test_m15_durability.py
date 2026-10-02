from uuid import uuid4

import pytest

from tinlance_agent_platform_durability.leases import WorkLease, WorkLeaseStore
from tinlance_agent_platform_durability.outbox import TransactionalOutbox


def test_outbox_requires_normalized_scope_and_event_type() -> None:
    outbox = TransactionalOutbox()
    with pytest.raises(ValueError):
        outbox.append(" tenant-a", uuid4(), "event", b"x")
    with pytest.raises(ValueError):
        outbox.append("tenant-a", uuid4(), "", b"x")


def test_outbox_lease_acknowledgement_is_owner_bound() -> None:
    outbox = TransactionalOutbox()
    event_id = outbox.append("tenant-a", uuid4(), "execution.completed", b"ok")
    leased = outbox.lease()
    assert len(leased) == 1
    with pytest.raises(PermissionError):
        outbox.acknowledge(event_id, uuid4())
    outbox.acknowledge(event_id, leased[0].lease_id)  # type: ignore[arg-type]
    assert outbox.pending() == ()


def test_outbox_failed_publication_can_be_released_and_released_record_is_leaseable() -> None:
    outbox = TransactionalOutbox()
    outbox.append("tenant-a", uuid4(), "execution.completed", b"ok")
    first = outbox.lease()
    assert len(first) == 1
    assert outbox.release(first[0].lease_id)  # type: ignore[arg-type]
    second = outbox.lease()
    assert len(second) == 1
    assert second[0].event_id == first[0].event_id
    assert second[0].attempts == 2


def test_worker_lease_prevents_double_claim_and_requires_owner_for_renewal() -> None:
    store = WorkLeaseStore()
    work_id = uuid4()
    first = store.claim(work_id, "worker-a")
    assert first is not None
    assert store.claim(work_id, "worker-b") is None
    with pytest.raises(PermissionError):
        store.renew(
            WorkLease(first.lease_id, first.work_id, "worker-b", first.expires_at),
            ttl_seconds=30,
        )
    renewed = store.renew(first)
    assert renewed.lease_id == first.lease_id
    store.release(renewed)
    assert store.claim(work_id, "worker-b") is not None
