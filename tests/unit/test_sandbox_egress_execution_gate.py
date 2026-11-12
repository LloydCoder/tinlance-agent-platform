from __future__ import annotations

from uuid import uuid4

import pytest

from tinlance_agent_platform_contracts import SandboxRequest
from tinlance_agent_platform_sandbox.bubblewrap import SandboxLimits
from tinlance_agent_platform_sandbox.executor import ProcessResult, WorkspaceLeaseLost
from tinlance_agent_platform_sandbox.policy import SandboxPolicy
from tinlance_agent_platform_sandbox.service import SandboxUnavailable, execute_request


class FakeProvider:
    def command(self, argv, limits, workspace_paths=(), *, network=False):
        return ["sandbox", *argv]


class FakeSupervisor:
    def __init__(self):
        self.executed = False
        self.argv = []

    def execute(self, assertion, argv, *, cwd, limits):
        if assertion() is not True:
            raise WorkspaceLeaseLost("workspace lease is expired, revoked, or fenced")
        self.argv = argv
        self.executed = True
        return ProcessResult(0, "ok", "")


def request(*, network: bool) -> SandboxRequest:
    return SandboxRequest(
        request_id=uuid4(),
        tenant_id="tenant-a",
        run_id=uuid4(),
        workspace_id="workspace-a",
        command=("echo", "hello"),
        timeout_seconds=10,
        network=network,
        allowed_paths=("/workspace/tenant-a",),
    )


def policy() -> SandboxPolicy:
    return SandboxPolicy(
        allowed_commands=frozenset({"echo"}),
        allow_network=True,
    )


def test_network_execution_requires_an_egress_boundary_assertion() -> None:
    supervisor = FakeSupervisor()

    with pytest.raises(SandboxUnavailable, match="egress boundary"):
        execute_request(
            request(network=True),
            policy(),
            FakeProvider(),
            SandboxLimits(),
            lease_assertion=lambda _: True,
            supervisor=supervisor,
        )

    assert supervisor.executed is False


def test_network_execution_checks_egress_boundary_before_worker_command() -> None:
    supervisor = FakeSupervisor()
    calls: list[str] = []

    result = execute_request(
        request(network=True),
        policy(),
        FakeProvider(),
        SandboxLimits(),
        lease_assertion=lambda _: True,
        egress_assertion=lambda _: calls.append("verified") or True,
        network_namespace="tln-0123456789",
        supervisor=supervisor,
    )

    assert result.stdout == "ok"
    assert calls == ["verified"]
    assert supervisor.argv[:4] == ["ip", "netns", "exec", "tln-0123456789"]
    assert supervisor.executed is True


def test_network_execution_fails_closed_when_egress_boundary_is_not_ready() -> None:
    supervisor = FakeSupervisor()

    with pytest.raises(WorkspaceLeaseLost, match="fenced"):
        execute_request(
            request(network=True),
            policy(),
            FakeProvider(),
            SandboxLimits(),
            lease_assertion=lambda _: True,
            egress_assertion=lambda _: False,
            network_namespace="tln-0123456789",
            supervisor=supervisor,
        )

    assert supervisor.executed is False


def test_non_network_execution_does_not_require_egress_assertion() -> None:
    supervisor = FakeSupervisor()

    result = execute_request(
        request(network=False),
        policy(),
        FakeProvider(),
        SandboxLimits(),
        lease_assertion=lambda _: True,
        supervisor=supervisor,
    )

    assert result.exit_code == 0
    assert supervisor.executed is True


def test_non_network_execution_rejects_malformed_egress_assertion() -> None:
    with pytest.raises(TypeError, match="egress_assertion must be callable"):
        execute_request(
            request(network=False),
            policy(),
            FakeProvider(),
            SandboxLimits(),
            lease_assertion=lambda _: True,
            egress_assertion=True,  # type: ignore[arg-type]
            supervisor=FakeSupervisor(),
        )


def test_workspace_lease_loss_prevents_egress_authority_from_being_used() -> None:
    supervisor = FakeSupervisor()
    egress_calls: list[str] = []

    with pytest.raises(WorkspaceLeaseLost, match="fenced"):
        execute_request(
            request(network=True),
            policy(),
            FakeProvider(),
            SandboxLimits(),
            lease_assertion=lambda _: False,
            egress_assertion=lambda _: egress_calls.append("called") or True,
            network_namespace="tln-0123456789",
            supervisor=supervisor,
        )

    assert egress_calls == []
    assert supervisor.executed is False


def test_network_execution_rejects_missing_or_malformed_worker_namespace() -> None:
    for namespace in (None, "tln-../../host", "worker-net"):
        with pytest.raises(SandboxUnavailable, match="worker network namespace"):
            execute_request(
                request(network=True),
                policy(),
                FakeProvider(),
                SandboxLimits(),
                lease_assertion=lambda _: True,
                egress_assertion=lambda _: True,
                network_namespace=namespace,
                supervisor=FakeSupervisor(),
            )
