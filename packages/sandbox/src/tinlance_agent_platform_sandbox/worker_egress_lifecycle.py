from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Protocol


class WorkerEgressError(RuntimeError):
    """Raised when a worker cannot be placed behind a verified egress boundary."""


@dataclass(frozen=True, slots=True)
class WorkerNetworkSpec:
    worker_id: str
    namespace: str
    browser_interface: str
    uplink_interface: str
    dns_server: str
    policy_revision: str

    def validate(self) -> None:
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}", self.worker_id):
            raise ValueError("worker_id is invalid")
        if not re.fullmatch(r"tnl-[a-z0-9]{1,10}", self.namespace):
            raise ValueError("namespace must use the platform-owned tnl- prefix")
        for interface in (self.browser_interface, self.uplink_interface):
            if not re.fullmatch(r"tb[a-z0-9]{1,10}", interface):
                raise ValueError("interfaces must use the platform-owned tb prefix")
        if self.browser_interface == self.uplink_interface:
            raise ValueError("browser and uplink interfaces must be distinct")
        address = ipaddress.ip_address(self.dns_server)
        if (
            address.version != 4
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_unspecified
            or address.is_reserved
        ):
            raise ValueError("DNS server must be an approved IPv4 resolver")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", self.policy_revision):
            raise ValueError("policy_revision is invalid")


class WorkerNetworkBackend(Protocol):
    """Privileged adapter; implementations must scope mutations to owned resources."""

    def namespace_exists(self, namespace: str) -> bool: ...
    def create_namespace(self, namespace: str) -> None: ...
    def attach_interfaces(self, spec: WorkerNetworkSpec) -> None: ...
    def install_policy(self, spec: WorkerNetworkSpec) -> None: ...
    def verify_policy(self, spec: WorkerNetworkSpec) -> bool: ...
    def destroy_worker_network(self, spec: WorkerNetworkSpec) -> None: ...


@dataclass(frozen=True, slots=True)
class WorkerEgressLease:
    worker_id: str
    namespace: str
    policy_revision: str
    verified: bool


class WorkerEgressLifecycle:
    """Admit a worker only after its network policy has been installed and verified.

    The privileged host adapter must implement atomic nftables transactions,
    durable ownership records, kernel-state verification, and safe cleanup.
    Namespace existence alone is never accepted as proof of an egress boundary.
    """

    def __init__(self, backend: WorkerNetworkBackend) -> None:
        self._backend = backend

    def provision(self, spec: WorkerNetworkSpec) -> WorkerEgressLease:
        spec.validate()
        if self._backend.namespace_exists(spec.namespace):
            raise WorkerEgressError("refusing to adopt an existing or unowned namespace")

        created = False
        try:
            self._backend.create_namespace(spec.namespace)
            created = True
            self._backend.attach_interfaces(spec)
            self._backend.install_policy(spec)
            if self._backend.verify_policy(spec) is not True:
                raise WorkerEgressError("worker egress policy verification failed")
            return WorkerEgressLease(
                worker_id=spec.worker_id,
                namespace=spec.namespace,
                policy_revision=spec.policy_revision,
                verified=True,
            )
        except Exception as exc:
            if created:
                try:
                    self._backend.destroy_worker_network(spec)
                except Exception as cleanup_error:
                    raise WorkerEgressError(
                        "provisioning failed and owned network cleanup also failed"
                    ) from cleanup_error
            if isinstance(exc, WorkerEgressError):
                raise
            raise WorkerEgressError("worker egress provisioning failed") from exc
