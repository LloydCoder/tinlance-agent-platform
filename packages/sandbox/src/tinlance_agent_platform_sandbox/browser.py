"""Persistent, tenant-isolated Chromium workspace lifecycle."""

from __future__ import annotations

import fcntl
import hashlib
import ipaddress
import os
import stat
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .egress_proxy import normalize_hostname


class BrowserIsolationError(RuntimeError):
    """Raised when browser isolation prerequisites are not satisfied."""


def verify_browser_network_isolation(proxy_url: str) -> str:
    """Require a non-root process, a private proxy route, and no default route.

    The caller must already be running inside a dedicated Linux network
    namespace whose host-side firewall permits only the proxy TCP port.
    """
    if os.name != "posix" or os.geteuid() == 0:
        raise BrowserIsolationError("browser must run as a non-root POSIX user")

    parsed = urlsplit(proxy_url)
    if (
        parsed.scheme != "http"
        or parsed.hostname is None
        or parsed.port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise BrowserIsolationError("browser proxy must be an explicit http://IP:port endpoint")
    try:
        proxy_ip = ipaddress.ip_address(parsed.hostname)
    except ValueError as exc:
        raise BrowserIsolationError("browser proxy must use an IP literal") from exc
    if (
        not proxy_ip.is_private
        or proxy_ip.is_loopback
        or proxy_ip.is_link_local
        or proxy_ip.is_unspecified
    ):
        raise BrowserIsolationError("browser proxy must be on the private workspace link")

    route_file = Path("/proc/net/route")
    if not route_file.is_file():
        raise BrowserIsolationError("Linux IPv4 route table is unavailable")
    connected_to_proxy = False
    for line in route_file.read_text(encoding="ascii").splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8:
            continue
        destination, flags, mask = fields[1], fields[3], fields[7]
        if destination == "00000000" and mask == "00000000":
            raise BrowserIsolationError("default IPv4 route is forbidden in browser namespace")
        try:
            network_address = ipaddress.IPv4Address(
                int.from_bytes(bytes.fromhex(destination), byteorder="little")
            )
            network_mask = ipaddress.IPv4Address(
                int.from_bytes(bytes.fromhex(mask), byteorder="little")
            )
        except (ValueError, OSError):
            raise BrowserIsolationError("malformed IPv4 route table") from None
        network = ipaddress.IPv4Network(
            (network_address, network_mask), strict=False
        )
        if "0001" in flags and proxy_ip in network:
            connected_to_proxy = True
    if not connected_to_proxy:
        raise BrowserIsolationError("browser namespace has no directly connected route to its proxy")

    ipv6_route = Path("/proc/net/ipv6_route")
    if ipv6_route.is_file():
        for line in ipv6_route.read_text(encoding="ascii").splitlines():
            fields = line.split()
            if len(fields) >= 10 and fields[0] == "0" * 32 and fields[1] == "00":
                raise BrowserIsolationError("default IPv6 route is forbidden in browser namespace")

    interfaces = {entry.name for entry in Path("/sys/class/net").iterdir()}
    if "lo" not in interfaces or len(interfaces) != 2:
        raise BrowserIsolationError("browser namespace must contain loopback and exactly one proxy link")
    return str(proxy_ip)


class BrowserProfileLease:
    """Exclusive lease for one persistent (tenant, workspace) browser profile."""

    def __init__(self, profile_path: Path, lock_fd: int) -> None:
        self.profile_path = profile_path
        self._lock_fd = lock_fd
        self._closed = False

    @classmethod
    def acquire(
        cls,
        profile_root: str | Path,
        tenant_id: str,
        workspace_id: str,
    ) -> BrowserProfileLease:
        if not tenant_id or not workspace_id or "\x00" in tenant_id or "\x00" in workspace_id:
            raise ValueError("tenant and workspace identifiers are required")
        root = Path(profile_root)
        if not root.is_absolute() or ".." in root.parts:
            raise ValueError("browser profile root must be an absolute traversal-free path")
        if root.is_symlink():
            raise BrowserIsolationError("browser profile root cannot be a symlink")
        root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if root.resolve() != Path(os.path.abspath(root)):
            raise BrowserIsolationError("browser profile root contains a symlinked path component")
        root_info = root.stat()
        if root_info.st_uid != os.geteuid():
            raise BrowserIsolationError("browser profile root is not owned by the browser user")
        os.chmod(root, 0o700)

        tenant_identity = hashlib.sha256(tenant_id.encode("utf-8")).hexdigest()
        workspace_identity = hashlib.sha256(workspace_id.encode("utf-8")).hexdigest()
        tenant_marker = root / ".tenant-id"
        marker_flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            marker_fd = os.open(tenant_marker, marker_flags, 0o600)
        except FileExistsError:
            marker_fd = os.open(
                tenant_marker,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            marker_info = os.fstat(marker_fd)
            marker_value = os.read(marker_fd, 128).decode("ascii", errors="strict")
            os.close(marker_fd)
            if (
                marker_info.st_uid != os.geteuid()
                or not stat.S_ISREG(marker_info.st_mode)
                or marker_value != tenant_identity
            ):
                raise BrowserIsolationError("profile root is already bound to another tenant")
        else:
            try:
                os.write(marker_fd, tenant_identity.encode("ascii"))
                os.fsync(marker_fd)
            finally:
                os.close(marker_fd)

        profile_path = root / workspace_identity
        if profile_path.is_symlink():
            raise BrowserIsolationError("browser profile path cannot be a symlink")
        profile_path.mkdir(mode=0o700, exist_ok=True)
        profile_info = profile_path.stat()
        if profile_info.st_uid != os.geteuid():
            raise BrowserIsolationError("browser profile is not owned by the browser user")
        if not stat.S_ISDIR(profile_info.st_mode):
            raise BrowserIsolationError("browser profile path is not a directory")
        os.chmod(profile_path, 0o700)

        lock_path = profile_path / ".workspace.lock"
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        lock_fd = os.open(lock_path, flags, 0o600)
        try:
            lock_info = os.fstat(lock_fd)
            if lock_info.st_uid != os.geteuid() or not stat.S_ISREG(lock_info.st_mode):
                raise BrowserIsolationError("browser profile lock is not a regular owned file")
            os.fchmod(lock_fd, 0o600)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise BrowserIsolationError("browser profile is already in use") from exc
        except BaseException:
            os.close(lock_fd)
            raise
        return cls(profile_path, lock_fd)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(self._lock_fd)

    def __enter__(self) -> BrowserProfileLease:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class BrowserSession:
    """Owns the Playwright context and the exclusive persistent profile lease."""

    def __init__(
        self,
        playwright: Any,
        context: Any,
        lease: BrowserProfileLease,
        timeout_ms: int,
    ) -> None:
        self._playwright = playwright
        self._context = context
        self._lease = lease
        self._timeout_ms = timeout_ms
        self._closed = False
        self.page = context.new_page()

    @property
    def profile_path(self) -> Path:
        return self._lease.profile_path

    def navigate(self, url: str) -> Any:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in (None, 443)
        ):
            raise BrowserIsolationError("browser navigation is restricted to credential-free HTTPS URLs")
        normalize_hostname(parsed.hostname)
        return self.page.goto(url, wait_until="domcontentloaded", timeout=self._timeout_ms)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._context.close()
        finally:
            try:
                self._playwright.stop()
            finally:
                self._lease.close()

    def __enter__(self) -> BrowserSession:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class BrowserWorkspaceManager:
    """Launch Chromium with an exclusive profile and mandatory HTTPS proxy.

    Network isolation is checked before Playwright starts. The supervisor must
    create a per-workspace Linux network namespace with no default route and a
    host firewall that exposes only the proxy listener on the workspace link.
    """

    def __init__(
        self,
        profile_root: str | Path,
        proxy_url: str,
        *,
        tenant_id: str,
        *,
        expected_uid: int | None = None,
        navigation_timeout_ms: int = 30_000,
    ) -> None:
        if not tenant_id or "\\x00" in tenant_id:
            raise ValueError("browser manager must be bound to one tenant")
        if navigation_timeout_ms < 1 or navigation_timeout_ms > 300_000:
            raise ValueError("browser navigation timeout is outside policy")
        self.profile_root = Path(profile_root)
        self.proxy_url = proxy_url
        self.tenant_id = tenant_id
        self.expected_uid = os.geteuid() if expected_uid is None else expected_uid
        self.navigation_timeout_ms = navigation_timeout_ms

    def open(self, workspace_id: str) -> BrowserSession:
        if os.geteuid() != self.expected_uid:
            raise BrowserIsolationError("browser process UID does not match tenant supervisor binding")
        verify_browser_network_isolation(self.proxy_url)
        lease = BrowserProfileLease.acquire(
            self.profile_root,
            self.tenant_id,
            workspace_id,
        )
        playwright: Any | None = None
        try:
            try:
                from playwright.sync_api import sync_playwright
            except ImportError as exc:
                raise BrowserIsolationError(
                    "install the browser optional dependencies to launch Chromium"
                ) from exc

            playwright = sync_playwright().start()
            context = playwright.chromium.launch_persistent_context(
                user_data_dir=str(lease.profile_path),
                headless=True,
                chromium_sandbox=True,
                accept_downloads=False,
                service_workers="block",
                proxy={"server": self.proxy_url},
                args=[
                    "--proxy-bypass-list=<-loopback>",
                    "--host-resolver-rules=MAP * ~NOTFOUND",
                    "--disable-quic",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-sync",
                    "--disable-extensions",
                    "--disable-default-apps",
                    "--no-first-run",
                    "--no-default-browser-check",
                ],
            )
            return BrowserSession(
                playwright,
                context,
                lease,
                self.navigation_timeout_ms,
            )
        except BaseException:
            if playwright is not None:
                playwright.stop()
            lease.close()
            raise
