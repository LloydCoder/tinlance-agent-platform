from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from scripts.soak_persistent_computer_w5 import (
    _atomic_json,
    _lease_from_state,
    _open_or_recover_lease,
    _read_state,
    _save_lease,
)
from tinlance_agent_platform_durability import WorkspaceLease

TENANT = UUID("00000000-0000-0000-0000-000000000092")
WORKSPACE = UUID("20000000-0000-0000-0000-000000000092")


class LeaseStore:
    def __init__(self, active=True):
        self.active = active
        self.revoked = []
        self.acquired = []

    def assert_active(self, lease):
        return self.active

    def revoke(self, lease):
        self.revoked.append(lease)
        self.active = False
        return True

    def acquire(self, tenant, workspace, owner, worker, *, lease_seconds):
        self.acquired.append((tenant, workspace, owner, worker, lease_seconds))
        self.active = True
        return WorkspaceLease(
            tenant,
            workspace,
            uuid4(),
            owner,
            worker,
            2,
            datetime.now(UTC) + timedelta(seconds=lease_seconds),
        )


def prior_lease():
    return WorkspaceLease(
        TENANT,
        WORKSPACE,
        UUID("30000000-0000-0000-0000-000000000092"),
        "owner",
        "worker-before-restart",
        1,
        datetime.now(UTC) + timedelta(minutes=10),
    )


def test_w5_state_round_trips_atomically_with_private_permissions(tmp_path: Path):
    path = tmp_path / "state" / "soak.json"
    state = {"status": "running", "browser_marker": "12"}

    _atomic_json(path, state)

    assert _read_state(path) == state
    assert path.stat().st_mode & 0o777 == 0o600


def test_w5_lease_state_preserves_fencing_and_owner_identity():
    lease = prior_lease()
    state = {}
    _save_lease(state, lease)

    assert _lease_from_state(state) == lease


def test_w5_process_restart_keeps_a_live_lease_without_reacquiring():
    store = LeaseStore(active=True)
    prior = prior_lease()
    state = {}
    _save_lease(state, prior)

    recovered = _open_or_recover_lease(
        store, state, TENANT, WORKSPACE, "owner", "worker-after-process-restart"
    )

    assert recovered == prior
    assert store.revoked == []
    assert store.acquired == []


def test_w5_host_restart_revokes_old_worker_and_increments_fencing():
    store = LeaseStore(active=True)
    prior = prior_lease()
    state = {}
    _save_lease(state, prior)

    recovered = _open_or_recover_lease(
        store,
        state,
        TENANT,
        WORKSPACE,
        "owner",
        "worker-after-host-reboot",
        force_reacquire=True,
    )

    assert store.revoked == [prior]
    assert recovered.fencing_token == 2
    assert recovered.worker_id == "worker-after-host-reboot"
    assert state["stale_lease_rejected"] is True


def test_w5_expired_lease_is_reacquired_instead_of_reused():
    store = LeaseStore(active=False)
    prior = prior_lease()
    state = {}
    _save_lease(state, prior)

    recovered = _open_or_recover_lease(
        store, state, TENANT, WORKSPACE, "owner", "worker-after-expiry"
    )

    assert recovered.fencing_token == 2
    assert store.acquired == [(TENANT, WORKSPACE, "owner", "worker-after-expiry", 900)]
