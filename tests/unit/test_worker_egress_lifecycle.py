from __future__ import annotations

import pytest

from tinlance_agent_platform_sandbox.worker_egress_lifecycle import (
    WorkerEgressError,
    WorkerEgressLifecycle,
    WorkerNetworkSpec,
)


def spec() -> WorkerNetworkSpec:
    return WorkerNetworkSpec(
        worker_id="worker-01",
        namespace="tnl-worker01",
        browser_interface="tbbrowser1",
        uplink_interface="tbuplink1",
        dns_server="10.20.0.2",
        policy_revision="policy-v1",
    )


class Backend:
    def __init__(self, *, exists=False, verified=True, fail_at=None):
        self.exists = exists
        self.verified = verified
        self.fail_at = fail_at
        self.calls = []

    def _call(self, name):
        self.calls.append(name)
        if self.fail_at == name:
            raise RuntimeError(name)

    def namespace_exists(self, namespace):
        self._call("exists")
        return self.exists

    def create_namespace(self, namespace):
        self._call("create")

    def attach_interfaces(self, spec):
        self._call("attach")

    def install_policy(self, spec):
        self._call("install")

    def verify_policy(self, spec):
        self._call("verify")
        return self.verified

    def destroy_worker_network(self, spec):
        self._call("destroy")


def test_provisions_only_after_policy_is_installed_and_verified():
    backend = Backend()
    lease = WorkerEgressLifecycle(backend).provision(spec())

    assert lease.verified is True
    assert backend.calls == ["exists", "create", "attach", "install", "verify"]


def test_refuses_to_adopt_an_existing_namespace():
    backend = Backend(exists=True)

    with pytest.raises(WorkerEgressError, match="unowned namespace"):
        WorkerEgressLifecycle(backend).provision(spec())

    assert backend.calls == ["exists"]


def test_verification_failure_cleans_up_created_worker_network():
    backend = Backend(verified=False)

    with pytest.raises(WorkerEgressError, match="verification failed"):
        WorkerEgressLifecycle(backend).provision(spec())

    assert backend.calls == ["exists", "create", "attach", "install", "verify", "destroy"]


def test_provisioning_failure_rolls_back_created_worker_network():
    backend = Backend(fail_at="install")

    with pytest.raises(WorkerEgressError, match="provisioning failed"):
        WorkerEgressLifecycle(backend).provision(spec())

    assert backend.calls == ["exists", "create", "attach", "install", "destroy"]


def test_cleanup_failure_is_reported_as_a_separate_critical_failure():
    backend = Backend(fail_at="install")

    def fail_cleanup(spec):
        backend.calls.append("destroy")
        raise RuntimeError("cleanup failed")

    backend.destroy_worker_network = fail_cleanup

    with pytest.raises(WorkerEgressError, match="cleanup also failed"):
        WorkerEgressLifecycle(backend).provision(spec())


@pytest.mark.parametrize(
    "field,value",
    [
        ("namespace", "root"),
        ("browser_interface", "eth0"),
        ("uplink_interface", "lo"),
        ("dns_server", "127.0.0.1"),
        ("policy_revision", ""),
    ],
)
def test_rejects_unowned_or_unsafe_network_identifiers(field, value):
    from dataclasses import replace

    with pytest.raises(ValueError):
        replace(spec(), **{field: value}).validate()
