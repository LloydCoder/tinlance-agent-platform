"""OpenBao KV v2 adapter for execution-scoped secrets.

Production endpoints require HTTPS with certificate verification. Plain HTTP is
accepted only for an explicitly enabled loopback development/test endpoint.
"""

from __future__ import annotations

import ipaddress
import json
import math
import re
import ssl
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass, field
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

from .scoped import ScopedSecretHandle, SecretResolutionError

_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_VERSION = re.compile(r"^[1-9][0-9]{0,8}$")
_SIMPLE_KEY = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_MAX_TOKEN_LENGTH = 8192
_DEFAULT_MAX_RESPONSE_BYTES = 1_048_576


@dataclass(frozen=True, slots=True)
class OpenBaoSecretProvider:
    """Resolve a version-pinned value from an OpenBao KV v2 mount.

    token_provider should return a short-lived workload token where the
    deployment supports it. The token is sent only in the X-Vault-Token header
    and is excluded from object representations and all raised error messages.
    """

    base_url: str
    token_provider: Callable[[], str] = field(repr=False, compare=False)
    mount: str = "secret"
    value_field: str = "value"
    timeout_seconds: float = 3.0
    ca_bundle: str | None = field(default=None, repr=False)
    allow_insecure_loopback: bool = False
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES

    def __post_init__(self) -> None:
        if not isinstance(self.base_url, str) or not self.base_url:
            raise ValueError("OpenBao base URL is required")
        try:
            parsed = urlsplit(self.base_url)
            hostname = parsed.hostname
            port = parsed.port
        except ValueError as exc:
            raise ValueError("OpenBao base URL is invalid") from exc

        if (
            parsed.scheme not in {"https", "http"}
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or (port is not None and not 1 <= port <= 65535)
        ):
            raise ValueError("OpenBao base URL must be an origin without credentials or path")

        if parsed.scheme == "http":
            is_loopback = hostname.lower() == "localhost"
            with suppress(ValueError):
                is_loopback = is_loopback or ipaddress.ip_address(hostname).is_loopback
            if not self.allow_insecure_loopback or not is_loopback:
                raise ValueError("OpenBao requires HTTPS outside explicit loopback test mode")

        if not _SIMPLE_KEY.fullmatch(self.mount):
            raise ValueError("OpenBao KV mount is invalid")
        if not _SIMPLE_KEY.fullmatch(self.value_field):
            raise ValueError("OpenBao value field is invalid")
        if (
            not math.isfinite(self.timeout_seconds)
            or self.timeout_seconds <= 0
            or self.timeout_seconds > 30
        ):
            raise ValueError("OpenBao timeout must be greater than zero and at most 30 seconds")
        if not 1 <= self.max_response_bytes <= _DEFAULT_MAX_RESPONSE_BYTES:
            raise ValueError("OpenBao response limit must be between 1 byte and 1 MiB")
        if self.ca_bundle is not None and not self.ca_bundle:
            raise ValueError("OpenBao CA bundle path cannot be empty")
        if not callable(self.token_provider):
            raise ValueError("OpenBao token provider must be callable")

        object.__setattr__(self, "base_url", self.base_url.rstrip("/"))

    def resolve(self, handle: ScopedSecretHandle) -> str:
        """Resolve one exact KV v2 version without disclosing backend details."""
        secret_path = self._validated_secret_path(handle.tenant_id, handle.name)
        version = self._validated_version(handle.version)
        token = self._get_token()
        url = (
            f"{self.base_url}/v1/{quote(self.mount, safe='')}/data/{secret_path}"
            f"?{urlencode({'version': version})}"
        )
        request = Request(
            url,
            headers={
                "Accept": "application/json",
                "Cache-Control": "no-store",
                "Pragma": "no-cache",
                "X-Vault-Request": "true",
            },
            method="GET",
        )
        # Unredirected headers prevent urllib from forwarding the bearer token
        # if the configured endpoint unexpectedly responds with a redirect.
        request.add_unredirected_header("X-Vault-Token", token)
        context = ssl.create_default_context(cafile=self.ca_bundle)

        try:
            with urlopen(request, timeout=self.timeout_seconds, context=context) as response:
                if response.status != 200:
                    raise SecretResolutionError("OpenBao returned an unexpected status")
                if response.geturl() != url:
                    raise SecretResolutionError("OpenBao redirects are not accepted")
                body = response.read(self.max_response_bytes + 1)
        except HTTPError as exc:
            if exc.code in {401, 403}:
                raise PermissionError("OpenBao denied secret access") from None
            if exc.code == 404:
                raise SecretResolutionError("OpenBao secret version was not found") from None
            raise SecretResolutionError("OpenBao secret request failed") from None
        except OSError:
            raise SecretResolutionError("OpenBao secret transport failed") from None

        if len(body) > self.max_response_bytes:
            raise SecretResolutionError("OpenBao response exceeded the configured size limit")

        try:
            payload = json.loads(body.decode("utf-8"))
            envelope = payload["data"]
            secret_data = envelope["data"]
            metadata = envelope["metadata"]
            actual_version = metadata["version"]
            value = secret_data[self.value_field]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
            raise SecretResolutionError("OpenBao returned an invalid KV v2 response") from None

        if isinstance(actual_version, bool) or not isinstance(actual_version, int):
            raise SecretResolutionError("OpenBao returned an invalid secret version")
        if actual_version != int(version):
            raise SecretResolutionError("OpenBao returned a different secret version")
        if not isinstance(value, str) or not value:
            raise SecretResolutionError("OpenBao secret value is missing or invalid")
        return value

    def _get_token(self) -> str:
        try:
            token = self.token_provider()
        except Exception:
            raise SecretResolutionError("OpenBao authentication token is unavailable") from None
        if (
            not isinstance(token, str)
            or not token
            or len(token) > _MAX_TOKEN_LENGTH
            or any(ord(character) < 33 or ord(character) > 126 for character in token)
        ):
            raise SecretResolutionError("OpenBao authentication token is invalid")
        return token

    @staticmethod
    def _validated_secret_path(tenant_id: str, name: str) -> str:
        if not isinstance(tenant_id, str) or not _PATH_SEGMENT.fullmatch(tenant_id):
            raise SecretResolutionError("OpenBao tenant scope is invalid")
        if not isinstance(name, str) or not name or name.startswith("/") or name.endswith("/"):
            raise SecretResolutionError("OpenBao secret path is invalid")
        segments = name.split("/")
        if any(
            segment in {"", ".", ".."} or not _PATH_SEGMENT.fullmatch(segment)
            for segment in segments
        ):
            raise SecretResolutionError("OpenBao secret path is invalid")
        scoped_segments = ["tenants", tenant_id, *segments]
        return "/".join(quote(segment, safe="._-") for segment in scoped_segments)

    @staticmethod
    def _validated_version(version: str) -> str:
        if not isinstance(version, str) or not _VERSION.fullmatch(version):
            raise SecretResolutionError("OpenBao secret version is invalid")
        return version
