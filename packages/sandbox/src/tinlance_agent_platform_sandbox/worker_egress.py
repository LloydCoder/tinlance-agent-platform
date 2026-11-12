"""Persistent, worker-owned Linux network namespaces with fail-closed egress.

The controller creates a dedicated veth-connected namespace for each worker. The
worker has no default route and can reach only the host-side HTTPS proxy and DNS
resolver endpoints. Host forwarding remains disabled; outbound internet access
is performed by the separately governed proxy process, never by packet routing.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import stat
from types import TracebackType
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Protocol

from tinlance_agent_platform_contracts import SandboxRequest


class EgressBoundaryError(RuntimeError):
    """Base class for worker egress-boundary failures."""


class EgressBoundaryConflict(EgressBoundaryError):
    """Raised when a namespace or interface exists without matching ownership."""


class EgressBoundaryNotReady(EgressBoundaryError):
    """Raised when a worker's egress boundary is absent, stale, or drifted."""


@dataclass(frozen=True, slots=True)
class WorkerEgressAttachment:
    worker_id: str
    policy_revision: str
    namespace: str
    host_interface: str
    worker_interface: str
    network: str
    host_address: str
    worker_address: str
    proxy_port: int


class CommandRunner(Protocol):
    def __call__(
        self,
        argv: list[str],
        *,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]: ...


def _subprocess_runner(
    argv: list[str],
    *,
    input_text: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


class WorkerEgressController:
    """Own one isolated network namespace and its immutable egress attachment.

    The namespace has no default route. Its only permitted non-loopback output
    is to one host-side address on the configured DNS ports and HTTPS proxy
    port. The host veth is explicitly non-forwarding, so it cannot become a
    packet-routing path to the host's default route.
    """

    _TABLE = "tinlance_egress"
    _STATE_MODE = 0o600
    _DIRECTORY_MODE = 0o700
    _WORKER_NETWORK = ipaddress.IPv4Network("198.18.0.0/15")

    def __init__(
        self,
        *,
        state_dir: Path = Path("/run/tinlance-egress"),
        runner: CommandRunner | None = None,
        require_root: bool = True,
    ) -> None:
        self._state_dir = Path(state_dir)
        self._runner = runner or _subprocess_runner
        self._require_root = require_root

    def create(
        self,
        worker_id: str,
        *,
        policy_revision: str,
        proxy_port: int = 3128,
    ) -> WorkerEgressAttachment:
        self._validate_identity(worker_id, policy_revision, proxy_port)
        self._require_privilege()
        self._prepare_state_dir()
        digest = hashlib.sha256(worker_id.encode("utf-8")).hexdigest()
        state_path = self._state_path(digest)
        if state_path.exists() or state_path.is_symlink():
            existing = self._load_state(state_path)
            attachment = self._attachment_from_state(existing)
            if (
                attachment.worker_id != worker_id
                or attachment.policy_revision != policy_revision
                or attachment.proxy_port != proxy_port
            ):
                raise EgressBoundaryConflict("worker already owns a different egress attachment")
            self.assert_ready(attachment)
            return attachment

        namespace = f"tln-{digest[:10]}"
        host_interface = f"teh{digest[:8]}"
        worker_interface = f"ten{digest[:8]}"
        network = self._network_for(digest)
        self._assert_network_available(network, state_path)
        self._assert_names_available(namespace, host_interface)

        host_ip = str(network.network_address + 1)
        worker_ip = str(network.network_address + 2)
        attachment = WorkerEgressAttachment(
            worker_id=worker_id,
            policy_revision=policy_revision,
            namespace=namespace,
            host_interface=host_interface,
            worker_interface="eth0",
            network=str(network),
            host_address=host_ip,
            worker_address=worker_ip,
            proxy_port=proxy_port,
        )

        namespace_created = False
        veth_created = False
        state_written = False
        try:
            self._run(["ip", "netns", "add", namespace])
            namespace_created = True
            self._run(
                [
                    "ip",
                    "link",
                    "add",
                    host_interface,
                    "type",
                    "veth",
                    "peer",
                    "name",
                    worker_interface,
                ]
            )
            veth_created = True
            self._run(["ip", "link", "set", worker_interface, "netns", namespace])
            self._run(["ip", "addr", "add", f"{host_ip}/30", "dev", host_interface])
            self._run(["ip", "link", "set", host_interface, "up"])
            self._run(["sysctl", "-q", "-w", f"net.ipv4.conf.{host_interface}.forwarding=0"])
            self._run(["sysctl", "-q", "-w", f"net.ipv6.conf.{host_interface}.forwarding=0"])
            self._run(["ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"])
            self._run(
                [
                    "ip",
                    "netns",
                    "exec",
                    namespace,
                    "ip",
                    "link",
                    "set",
                    worker_interface,
                    "name",
                    "eth0",
                ]
            )
            self._run(
                [
                    "ip",
                    "netns",
                    "exec",
                    namespace,
                    "ip",
                    "addr",
                    "add",
                    f"{worker_ip}/30",
                    "dev",
                    "eth0",
                ]
            )
            self._run(["ip", "netns", "exec", namespace, "ip", "link", "set", "eth0", "up"])
            self._run(
                ["ip", "netns", "exec", namespace, "sysctl", "-q", "-w", "net.ipv4.ip_forward=0"]
            )
            self._run(
                [
                    "ip",
                    "netns",
                    "exec",
                    namespace,
                    "sysctl",
                    "-q",
                    "-w",
                    "net.ipv6.conf.all.forwarding=0",
                ]
            )
            self._run(
                [
                    "ip",
                    "netns",
                    "exec",
                    namespace,
                    "sysctl",
                    "-q",
                    "-w",
                    "net.ipv6.conf.all.disable_ipv6=1",
                ]
            )
            self._run(
                ["ip", "netns", "exec", namespace, "nft", "-f", "-"],
                input_text=self._ruleset(attachment),
            )
            self._write_state(state_path, attachment)
            state_written = True
            self.assert_ready(attachment)
            return attachment
        except BaseException as exc:
            cleanup_errors: list[str] = []
            if namespace_created:
                result = self._run_optional(["ip", "netns", "del", namespace])
                if result is not None:
                    cleanup_errors.append(result)
            if veth_created:
                result = self._run_optional(["ip", "link", "del", host_interface])
                if result is not None:
                    cleanup_errors.append(result)
            if state_written and state_path.exists():
                state_path.unlink()
            if cleanup_errors:
                raise EgressBoundaryNotReady(
                    "egress setup failed and owned-object cleanup was incomplete: "
                    + "; ".join(cleanup_errors)
                ) from exc
            if isinstance(exc, EgressBoundaryError):
                raise
            raise EgressBoundaryNotReady("worker egress namespace setup failed closed") from exc

    def assert_ready(self, attachment: WorkerEgressAttachment) -> None:
        """Raise unless ownership, namespace, policy, and routing remain exact."""
        self._require_privilege()
        self._prepare_state_dir()
        digest = hashlib.sha256(attachment.worker_id.encode("utf-8")).hexdigest()
        state = self._load_state(self._state_path(digest))
        if state != asdict(attachment):
            raise EgressBoundaryNotReady("worker egress ownership metadata does not match")
        namespaces = self._run(["ip", "netns", "list"]).stdout.splitlines()
        if not any(line.split()[0] == attachment.namespace for line in namespaces if line.split()):
            raise EgressBoundaryNotReady("worker network namespace is missing")
        self._run(["ip", "link", "show", "dev", attachment.host_interface])
        nft = self._run(
            [
                "ip",
                "netns",
                "exec",
                attachment.namespace,
                "nft",
                "list",
                "ruleset",
            ]
        ).stdout
        expected_accepts = {
            'iifname "lo" accept',
            "ct state established,related accept",
            'oifname "lo" accept',
            f"ip daddr {attachment.host_address} udp dport 53 accept",
            f"ip daddr {attachment.host_address} tcp dport 53 accept",
            f"ip daddr {attachment.host_address} tcp dport {attachment.proxy_port} accept",
        }
        accept_rules = (line.strip() for line in nft.splitlines())
        observed_accepts = {line for line in accept_rules if line.endswith(" accept")}
        if (
            nft.count("table ") != 1
            or f"table inet {self._TABLE}" not in nft
            or nft.count("type filter hook") != 3
            or nft.count("policy drop") != 3
            or observed_accepts != expected_accepts
            or "policy accept" in nft
        ):
            raise EgressBoundaryNotReady("worker nftables ruleset is permissive or has drifted")
        default_routes = self._run(
            ["ip", "netns", "exec", attachment.namespace, "ip", "route", "show", "default"]
        ).stdout.strip()
        if default_routes:
            raise EgressBoundaryNotReady("worker namespace unexpectedly has a default route")

    def is_ready(self, attachment: WorkerEgressAttachment) -> bool:
        """Boolean assertion suitable for the sandbox's continuous egress gate."""
        try:
            self.assert_ready(attachment)
        except Exception:
            return False
        return True

    def destroy(self, worker_id: str) -> None:
        """Remove only namespace/veth objects whose root-owned metadata matches."""
        self._validate_identity(worker_id, "destroy", 3128)
        self._require_privilege()
        self._prepare_state_dir()
        digest = hashlib.sha256(worker_id.encode("utf-8")).hexdigest()
        state_path = self._state_path(digest)
        state = self._load_state(state_path)
        attachment = self._attachment_from_state(state)
        if attachment.worker_id != worker_id:
            raise EgressBoundaryConflict("egress state belongs to another worker")
        namespaces = self._run(["ip", "netns", "list"]).stdout.splitlines()
        if any(line.split()[0] == attachment.namespace for line in namespaces if line.split()):
            self._run(["ip", "netns", "del", attachment.namespace])
        if self._exists(["ip", "link", "show", "dev", attachment.host_interface]):
            self._run(["ip", "link", "del", attachment.host_interface])
        if state_path.exists():
            state_path.unlink()

    def _validate_identity(self, worker_id: str, policy_revision: str, proxy_port: int) -> None:
        if not isinstance(worker_id, str) or not worker_id or len(worker_id) > 128:
            raise ValueError("worker_id must be a non-empty string of at most 128 characters")
        if (
            not isinstance(policy_revision, str)
            or not policy_revision
            or len(policy_revision) > 128
        ):
            raise ValueError("policy_revision must be a non-empty string of at most 128 characters")
        if (
            not isinstance(proxy_port, int)
            or isinstance(proxy_port, bool)
            or not 1 <= proxy_port <= 65535
        ):
            raise ValueError("proxy_port must be a valid TCP port")

    def _require_privilege(self) -> None:
        if self._require_root and os.geteuid() != 0:
            raise EgressBoundaryNotReady("worker egress namespace control requires root privileges")

    def _prepare_state_dir(self) -> None:
        if self._state_dir.is_symlink():
            raise EgressBoundaryNotReady("worker egress state directory must not be a symlink")
        self._state_dir.mkdir(mode=self._DIRECTORY_MODE, parents=True, exist_ok=True)
        info = self._state_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
            raise EgressBoundaryNotReady("worker egress state directory ownership is invalid")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise EgressBoundaryNotReady("worker egress state directory permissions must be 0700")

    def _state_path(self, digest: str) -> Path:
        return self._state_dir / f"{digest[:16]}.json"

    def _load_state(self, path: Path) -> dict[str, object]:
        try:
            info = path.lstat()
        except FileNotFoundError as exc:
            raise EgressBoundaryNotReady("worker egress ownership metadata is missing") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid():
            raise EgressBoundaryNotReady(
                "worker egress ownership metadata is not a trusted regular file"
            )
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise EgressBoundaryNotReady(
                "worker egress ownership metadata permissions must be 0600"
            )
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise EgressBoundaryNotReady("worker egress ownership metadata is unreadable") from exc
        if not isinstance(value, dict):
            raise EgressBoundaryNotReady("worker egress ownership metadata has an invalid shape")
        return value

    def _write_state(self, path: Path, attachment: WorkerEgressAttachment) -> None:
        payload = json.dumps(asdict(attachment), sort_keys=True, separators=(",", ":"))
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, self._STATE_MODE)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except BaseException:
            path.unlink(missing_ok=True)
            raise

    def _attachment_from_state(self, state: dict[str, object]) -> WorkerEgressAttachment:
        def string_field(name: str) -> str:
            value = state.get(name)
            if not isinstance(value, str):
                raise EgressBoundaryNotReady(
                    "worker egress ownership metadata has invalid string fields"
                )
            return value

        proxy_port = state.get("proxy_port")
        if not isinstance(proxy_port, int) or isinstance(proxy_port, bool):
            raise EgressBoundaryNotReady(
                "worker egress ownership metadata has an invalid proxy port"
            )
        attachment = WorkerEgressAttachment(
            worker_id=string_field("worker_id"),
            policy_revision=string_field("policy_revision"),
            namespace=string_field("namespace"),
            host_interface=string_field("host_interface"),
            worker_interface=string_field("worker_interface"),
            network=string_field("network"),
            host_address=string_field("host_address"),
            worker_address=string_field("worker_address"),
            proxy_port=proxy_port,
        )
        if set(state) != set(asdict(attachment)):
            raise EgressBoundaryNotReady("worker egress ownership metadata has unexpected fields")
        return attachment

    def _network_for(self, digest: str) -> ipaddress.IPv4Network:
        index = int(digest[:8], 16) % 131072
        address = int(self._WORKER_NETWORK.network_address) + index * 4
        return ipaddress.IPv4Network((address, 30))

    def _assert_network_available(self, network: ipaddress.IPv4Network, own_path: Path) -> None:
        for path in self._state_dir.glob("*.json"):
            if path == own_path:
                continue
            state = self._load_state(path)
            if state.get("network") == str(network):
                raise EgressBoundaryConflict("worker egress address pool collision detected")

    def _assert_names_available(self, namespace: str, host_interface: str) -> None:
        namespaces = self._run(["ip", "netns", "list"]).stdout.splitlines()
        if any(line.split()[0] == namespace for line in namespaces if line.split()):
            raise EgressBoundaryConflict(
                "worker namespace already exists without matching ownership metadata"
            )
        if self._exists(["ip", "link", "show", "dev", host_interface]):
            raise EgressBoundaryConflict(
                "worker host veth already exists without matching ownership metadata"
            )

    def _ruleset(self, attachment: WorkerEgressAttachment) -> str:
        return f"""table inet {self._TABLE} {{
  chain input {{
    type filter hook input priority 0; policy drop;
    iifname \"lo\" accept
    ct state established,related accept
  }}
  chain output {{
    type filter hook output priority 0; policy drop;
    oifname \"lo\" accept
    ip daddr {attachment.host_address} udp dport 53 accept
    ip daddr {attachment.host_address} tcp dport 53 accept
    ip daddr {attachment.host_address} tcp dport {attachment.proxy_port} accept
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
  }}
}}
"""

    def _run(
        self,
        argv: list[str],
        *,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = self._runner(argv, input_text=input_text)
        except (OSError, subprocess.SubprocessError) as exc:
            raise EgressBoundaryNotReady(f"required egress command failed: {argv[0]}") from exc
        if result.returncode != 0:
            reason = result.stderr.strip()[:160] or f"exit={result.returncode}"
            command_label = "nftables policy" if input_text is not None else argv[0]
            raise EgressBoundaryNotReady(
                f"required egress command failed: {command_label} ({reason})"
            )
        return result

    def _exists(self, argv: list[str]) -> bool:
        try:
            result = self._runner(argv)
        except (OSError, subprocess.SubprocessError) as exc:
            raise EgressBoundaryNotReady(f"cannot inspect egress object: {argv[0]}") from exc
        if result.returncode == 0:
            return True
        error = result.stderr.lower()
        if any(
            marker in error
            for marker in (
                "cannot find device",
                "does not exist",
                "no such file",
                "cannot open network namespace",
            )
        ):
            return False
        raise EgressBoundaryNotReady(f"cannot establish egress object state: {argv[0]}")

    def _run_optional(self, argv: list[str]) -> str | None:
        try:
            result = self._runner(argv)
        except (OSError, subprocess.SubprocessError) as exc:
            return f"{argv[0]}: {type(exc).__name__}"
        if result.returncode == 0:
            return None
        reason = result.stderr.strip()[:160] or f"exit={result.returncode}"
        return f"{argv[0]}: {reason}"


class WorkerEgressSession:
    """Bind a sandbox request to one owned namespace for exactly one execution.

    The session derives an opaque worker identity from tenant, run, workspace,
    and request identifiers. Its assertion is request-object-bound and rechecks
    the kernel boundary continuously while the command is running.
    """

    def __init__(
        self,
        controller: WorkerEgressController,
        request: SandboxRequest,
        *,
        policy_revision: str,
        proxy_port: int = 3128,
    ) -> None:
        if not request.network:
            raise ValueError("worker egress sessions require a network-enabled SandboxRequest")
        identity = json.dumps(
            {
                "tenant_id": request.tenant_id,
                "run_id": str(request.run_id),
                "workspace_id": request.workspace_id,
                "request_id": str(request.request_id),
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        self._controller = controller
        self._request = request
        self._worker_id = "worker-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()
        self._policy_revision = policy_revision
        self._proxy_port = proxy_port
        self._attachment: WorkerEgressAttachment | None = None
        self._closed = False

    def __enter__(self) -> WorkerEgressSession:
        if self._attachment is not None or self._closed:
            raise EgressBoundaryConflict("worker egress session cannot be entered more than once")
        self._attachment = self._controller.create(
            self._worker_id,
            policy_revision=self._policy_revision,
            proxy_port=self._proxy_port,
        )
        return self

    @property
    def network_namespace(self) -> str:
        if self._attachment is None or self._closed:
            raise EgressBoundaryNotReady("worker egress session is not active")
        return self._attachment.namespace

    @property
    def attachment(self) -> WorkerEgressAttachment:
        if self._attachment is None or self._closed:
            raise EgressBoundaryNotReady("worker egress session is not active")
        return self._attachment

    def assert_active(self, candidate: object) -> bool:
        attachment = self._attachment
        return (
            not self._closed
            and attachment is not None
            and candidate is self._request
            and self._controller.is_ready(attachment)
        )

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        self._closed = True
        if self._attachment is not None:
            try:
                self._controller.destroy(self._worker_id)
            except Exception as cleanup_error:
                if exc is None:
                    raise
                if hasattr(exc, "add_note"):
                    exc.add_note(f"worker egress teardown failed: {cleanup_error}")
        self._attachment = None
        return False
