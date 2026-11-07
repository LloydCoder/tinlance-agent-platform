"""Fail-closed HTTPS CONNECT proxy for isolated browser workspaces.

The browser network namespace must have no default route and may reach only this
proxy endpoint. The proxy resolves each destination once, rejects any non-public
answer, and connects to one of the validated IP literals (never the hostname).
TLS remains end-to-end between Chromium and the destination.
"""

from __future__ import annotations

import ipaddress
import math
import select
import socket
import socketserver
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit


class EgressDenied(PermissionError):
    """Raised when a browser egress destination is outside the approved scope."""


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    hostname: str
    port: int
    addresses: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    allowed_domains: frozenset[str]
    allowed_ports: frozenset[int] = frozenset({443})
    connect_timeout_seconds: float = 5.0
    tunnel_idle_timeout_seconds: float = 30.0
    tunnel_max_seconds: float = 900.0
    tunnel_max_bytes: int = 268_435_456
    max_connections: int = 64

    def __post_init__(self) -> None:
        if not self.allowed_domains or len(self.allowed_domains) > 256:
            raise ValueError("browser egress requires between 1 and 256 allowlist entries")
        if not self.allowed_ports or any(port != 443 for port in self.allowed_ports):
            raise ValueError("browser egress is HTTPS-only on TCP port 443")
        if (
            not math.isfinite(self.connect_timeout_seconds)
            or not math.isfinite(self.tunnel_idle_timeout_seconds)
            or not math.isfinite(self.tunnel_max_seconds)
            or not 0 < self.connect_timeout_seconds <= 30
            or not 0 < self.tunnel_idle_timeout_seconds <= 300
            or not 0 < self.tunnel_max_seconds <= 3600
            or not isinstance(self.tunnel_max_bytes, int)
            or not 1 <= self.tunnel_max_bytes <= 1_073_741_824
            or not isinstance(self.max_connections, int)
            or not 1 <= self.max_connections <= 1024
        ):
            raise ValueError("invalid egress resource limits")
        normalized_rules: set[str] = set()
        for raw_rule in self.allowed_domains:
            if not isinstance(raw_rule, str):
                raise ValueError("egress allowlist entries must be strings")
            wildcard = raw_rule.startswith("*.")
            domain = normalize_hostname(raw_rule[2:] if wildcard else raw_rule)
            normalized_rules.add("*." + domain if wildcard else domain)
        object.__setattr__(self, "allowed_domains", frozenset(normalized_rules))


Resolver = Callable[[str], tuple[str, ...]]


def normalize_hostname(hostname: str) -> str:
    """Canonicalize a DNS hostname without performing name resolution."""
    if not hostname or len(hostname) > 253 or "\x00" in hostname:
        raise EgressDenied("invalid destination hostname")
    candidate = hostname.rstrip(".")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise EgressDenied("IP-literal destinations are forbidden")
    try:
        normalized = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise EgressDenied("destination hostname is not valid IDNA") from exc
    labels = normalized.split(".")
    if len(labels) < 2 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(char.isalnum() or char == "-" for char in label)
        for label in labels
    ):
        raise EgressDenied("destination hostname is malformed")
    if (
        normalized
        in {
            "metadata",
            "metadata.google.internal",
            "metadata.azure.internal",
            "instance-data.ec2.internal",
        }
        or normalized.endswith(".localhost")
        or normalized.endswith(".local")
    ):
        raise EgressDenied("special-use destination hostname is forbidden")
    return normalized


def _domain_is_allowed(hostname: str, allowed_domains: frozenset[str]) -> bool:
    for raw_rule in allowed_domains:
        rule = raw_rule.strip().lower()
        if rule.startswith("*."):
            suffix = normalize_hostname(rule[2:])
            if hostname.endswith("." + suffix):
                return True
        elif hostname == normalize_hostname(rule):
            return True
    return False


def _system_resolve(hostname: str) -> tuple[str, ...]:
    """Resolve A and AAAA records with bounded DNS query lifetime."""
    try:
        import dns.exception
        import dns.resolver
    except ImportError as exc:
        raise RuntimeError("install the browser optional dependencies") from exc

    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 2.0
    resolver.lifetime = 4.0
    addresses: list[str] = []
    for record_type in ("A", "AAAA"):
        try:
            answer = resolver.resolve(hostname, record_type, lifetime=4.0, search=False)
        except dns.resolver.NoAnswer:
            continue
        except dns.resolver.NXDOMAIN as exc:
            raise EgressDenied("destination hostname does not exist") from exc
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            raise EgressDenied("destination DNS resolution failed closed") from exc
        addresses.extend(str(record) for record in answer)
    return tuple(dict.fromkeys(addresses))


def resolve_public_target(
    hostname: str,
    port: int,
    policy: EgressPolicy,
    *,
    resolver: Resolver | None = None,
) -> ResolvedTarget:
    """Validate allowlist and every DNS answer before any socket is opened.

    All answers must be globally routable. The returned IP literals are the only
    addresses the connector may use; it must not resolve the hostname again.
    """
    normalized = normalize_hostname(hostname)
    if port not in policy.allowed_ports:
        raise EgressDenied("destination port is not allowed")
    if not _domain_is_allowed(normalized, policy.allowed_domains):
        raise EgressDenied("destination hostname is not allowlisted")

    answers = (resolver or _system_resolve)(normalized)
    if not answers:
        raise EgressDenied("destination has no address records")
    if len(answers) > 32:
        raise EgressDenied("destination returned too many DNS addresses")

    validated: list[str] = []
    for raw_address in answers:
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            raise EgressDenied("DNS returned a malformed address") from exc
        if (
            not address.is_global
            or address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or getattr(address, "ipv4_mapped", None) is not None
        ):
            raise EgressDenied("DNS returned a non-public or special-use address")
        validated.append(str(address))

    return ResolvedTarget(normalized, port, tuple(dict.fromkeys(validated)))


def connect_pinned_target(target: ResolvedTarget, *, timeout_seconds: float) -> socket.socket:
    """Connect only to a validated IP literal; no second DNS lookup occurs."""
    if target.port != 443 or not target.addresses:
        raise EgressDenied("connector received an invalid validated target")
    last_error: OSError | None = None
    for raw_address in target.addresses:
        try:
            address = ipaddress.ip_address(raw_address)
        except ValueError as exc:
            raise EgressDenied("connector refuses to resolve a hostname") from exc
        if (
            not address.is_global
            or address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
            or getattr(address, "ipv4_mapped", None) is not None
        ):
            raise EgressDenied("connector refuses a non-public address")
        try:
            return socket.create_connection(
                (str(address), target.port),
                timeout=timeout_seconds,
            )
        except OSError as exc:
            last_error = exc
    raise ConnectionError("all validated destination addresses failed") from last_error


def _relay_tunnel(
    client: socket.socket,
    upstream: socket.socket,
    *,
    idle_timeout_seconds: float,
    max_seconds: float,
    max_bytes: int,
) -> None:
    started = time.monotonic()
    last_activity = started
    transferred = 0
    peers = {client: upstream, upstream: client}
    while True:
        remaining = max_seconds - (time.monotonic() - started)
        idle_remaining = idle_timeout_seconds - (time.monotonic() - last_activity)
        if remaining <= 0 or idle_remaining <= 0 or transferred >= max_bytes:
            return
        readable, _, exceptional = select.select(
            list(peers),
            [],
            list(peers),
            min(1.0, remaining, idle_remaining),
        )
        if exceptional:
            return
        for source in readable:
            try:
                chunk = source.recv(65_536)
            except OSError:
                return
            if not chunk:
                return
            transferred += len(chunk)
            if transferred > max_bytes:
                return
            try:
                peers[source].sendall(chunk)
            except OSError:
                return
            last_activity = time.monotonic()


class _BrowserProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = False
    daemon_threads = False
    block_on_close = True
    request_queue_size = 64

    def __init__(
        self,
        server_address: tuple[str, int],
        policy: EgressPolicy,
        *,
        allowed_client_network: str,
    ) -> None:
        self.policy = policy
        self.allowed_client_network = ipaddress.ip_network(allowed_client_network, strict=True)
        if self.allowed_client_network.version != 4 or not (
            self.allowed_client_network.is_private or self.allowed_client_network.is_loopback
        ):
            raise ValueError("browser proxy clients must come from a private workspace network")
        self._slots = threading.BoundedSemaphore(policy.max_connections)
        self._active_lock = threading.Lock()
        self._active_sockets: set[socket.socket] = set()
        self._closing = False
        super().__init__(server_address, _BrowserProxyHandler)

    def register_socket(self, connection: socket.socket) -> bool:
        with self._active_lock:
            if self._closing:
                return False
            self._active_sockets.add(connection)
            return True

    def unregister_socket(self, connection: socket.socket) -> None:
        with self._active_lock:
            self._active_sockets.discard(connection)

    def close_active_connections(self) -> None:
        with self._active_lock:
            self._closing = True
            connections = tuple(self._active_sockets)
            self._active_sockets.clear()
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                connection.close()
            except OSError:
                pass

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self._slots.acquire(blocking=False):
            request.close()
            return
        if not self.register_socket(request):
            self._slots.release()
            request.close()
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.unregister_socket(request)
            self._slots.release()
            raise

    def process_request_thread(
        self, request: socket.socket, client_address: tuple[str, int]
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.unregister_socket(request)
            self._slots.release()


class _BrowserProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "TinlanceBrowserEgress/1"
    sys_version = ""

    @property
    def proxy_server(self) -> _BrowserProxyServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, format: str, *args: object) -> None:
        # Do not log URLs, headers, credentials, or query strings.
        return

    def do_CONNECT(self) -> None:
        try:
            client_ip = ipaddress.ip_address(self.client_address[0])
            if client_ip not in self.proxy_server.allowed_client_network:
                raise EgressDenied("client is outside the browser network")
            parsed = urlsplit("//" + self.path)
            if (
                not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path
                or parsed.query
                or parsed.fragment
                or parsed.port is None
            ):
                raise EgressDenied("malformed CONNECT authority")
            target = resolve_public_target(
                parsed.hostname,
                parsed.port,
                self.proxy_server.policy,
            )
            upstream = connect_pinned_target(
                target,
                timeout_seconds=self.proxy_server.policy.connect_timeout_seconds,
            )
            if not self.proxy_server.register_socket(upstream):
                upstream.close()
                raise EgressDenied("browser egress proxy is shutting down")
        except (EgressDenied, ValueError, OSError, ConnectionError):
            try:
                self.send_error(403, "Destination denied by browser egress policy")
            except OSError:
                pass
            return

        try:
            self.connection.settimeout(5.0)
            upstream.settimeout(5.0)
            self.send_response(200, "Connection Established")
            self.end_headers()
            _relay_tunnel(
                self.connection,
                upstream,
                idle_timeout_seconds=self.proxy_server.policy.tunnel_idle_timeout_seconds,
                max_seconds=self.proxy_server.policy.tunnel_max_seconds,
                max_bytes=self.proxy_server.policy.tunnel_max_bytes,
            )
        finally:
            self.proxy_server.unregister_socket(upstream)
            upstream.close()

    def do_GET(self) -> None:
        self.send_error(403, "Only HTTPS CONNECT tunnels are supported")

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_PATCH = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET
    do_TRACE = do_GET


class BrowserEgressProxy:
    """Lifecycle wrapper for the per-workspace, allowlist-enforcing proxy."""

    def __init__(
        self,
        bind_host: str,
        port: int,
        policy: EgressPolicy,
        *,
        allowed_client_network: str,
    ) -> None:
        try:
            bind_ip = ipaddress.ip_address(bind_host)
        except ValueError as exc:
            raise ValueError("browser proxy must bind to a specific IP address") from exc
        if (
            not isinstance(bind_ip, ipaddress.IPv4Address)
            or bind_ip.is_unspecified
            or bind_ip.is_link_local
            or (not bind_ip.is_private and not bind_ip.is_loopback)
            or not 0 <= port <= 65_535
        ):
            raise ValueError(
                "browser proxy must bind to a specific private or loopback IPv4 address"
            )
        self._server = _BrowserProxyServer(
            (bind_host, port),
            policy,
            allowed_client_network=allowed_client_network,
        )
        self._thread: threading.Thread | None = None
        self._closed = False

    @property
    def address(self) -> tuple[str, int]:
        host, port = self._server.server_address[:2]
        return str(host), int(port)

    def start(self) -> None:
        if self._closed:
            raise RuntimeError("browser egress proxy is closed")
        if self._thread is not None:
            raise RuntimeError("browser egress proxy is already started")
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="tinlance-browser-egress",
            daemon=True,
        )
        self._thread.start()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        thread = self._thread
        if thread is not None:
            self._server.shutdown()
        self._server.close_active_connections()
        self._server.server_close()
        if thread is not None:
            thread.join(timeout=5)
            if thread.is_alive():
                raise RuntimeError("browser egress proxy did not stop within the shutdown deadline")
            self._thread = None

    def __enter__(self) -> BrowserEgressProxy:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
