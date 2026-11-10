"""RFC 9449 DPoP proof verification for sender-constrained access tokens.

A verified proof is request-bound and replay-checked, but does not itself grant
Platform authority. Production callers must inject an atomic, shared replay cache.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Protocol
from urllib.parse import urlsplit

import jwt


_ALLOWED_DPOP_ALGORITHMS = frozenset({"ES256", "RS256", "PS256", "EdDSA"})
_JTI_PATTERN = re.compile(r"^[A-Za-z0-9._~-]{1,256}$")


class DPoPReplayCache(Protocol):
    """Atomic replay store; consume returns False when the proof ID was seen."""

    def consume(self, jti: str, expires_at: datetime) -> bool: ...


@dataclass(frozen=True, slots=True)
class VerifiedDPoPProof:
    jti: str
    jwk_thumbprint: str
    issued_at: datetime


@dataclass(frozen=True, slots=True)
class DPoPProofVerifier:
    replay_cache: DPoPReplayCache
    max_age_seconds: int = 300
    clock_skew_seconds: int = 30

    def __post_init__(self) -> None:
        if (
            isinstance(self.max_age_seconds, bool)
            or not isinstance(self.max_age_seconds, int)
            or not 1 <= self.max_age_seconds <= 600
        ):
            raise ValueError("DPoP maximum proof age must be between 1 and 600 seconds")
        if (
            isinstance(self.clock_skew_seconds, bool)
            or not isinstance(self.clock_skew_seconds, int)
            or not 0 <= self.clock_skew_seconds <= 120
        ):
            raise ValueError("DPoP clock skew must be between 0 and 120 seconds")

    def verify(
        self,
        proof: str,
        *,
        method: str,
        uri: str,
        access_token: str,
        now: datetime | None = None,
    ) -> VerifiedDPoPProof:
        current = now or datetime.now(UTC)
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("DPoP verification time must be timezone-aware")
        if (
            not isinstance(proof, str)
            or not proof
            or any(character.isspace() for character in proof)
            or not isinstance(method, str)
            or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", method)
            or method != method.upper()
            or not isinstance(access_token, str)
            or not access_token
            or not isinstance(uri, str)
        ):
            raise PermissionError("DPoP request context is malformed")

        try:
            header = jwt.get_unverified_header(proof)
            if header.get("typ") != "dpop+jwt":
                raise PermissionError("DPoP proof type is not trusted")
            if "crit" in header or "b64" in header:
                raise PermissionError("DPoP proof uses an unsupported JOSE critical header")
            if {"jku", "x5u", "x5c"}.intersection(header):
                raise PermissionError("DPoP proof contains an untrusted key-source header")
            algorithm = header.get("alg")
            if algorithm not in _ALLOWED_DPOP_ALGORITHMS:
                raise PermissionError("DPoP proof algorithm is not trusted")
            jwk = header.get("jwk")
            if not isinstance(jwk, dict):
                raise PermissionError("DPoP proof public JWK is required")
            public_key, thumbprint = self._public_key_and_thumbprint(jwk, algorithm)
            claims = jwt.decode(
                proof,
                public_key,
                algorithms=[algorithm],
                options={
                    "verify_signature": True,
                    "verify_exp": False,
                    "verify_iat": False,
                    "verify_nbf": False,
                    "verify_aud": False,
                    "verify_iss": False,
                    "require": ["htm", "htu", "iat", "jti", "ath"],
                },
            )
        except PermissionError:
            raise
        except Exception as exc:
            raise PermissionError("DPoP proof signature or claims are invalid") from exc

        issued_at_value = claims.get("iat")
        if (
            isinstance(issued_at_value, bool)
            or not isinstance(issued_at_value, (int, float))
            or not float(issued_at_value).is_integer()
        ):
            raise PermissionError("DPoP proof issued-at claim is malformed")
        try:
            issued_at = datetime.fromtimestamp(issued_at_value, UTC)
        except (OverflowError, OSError, ValueError) as exc:
            raise PermissionError(
                "DPoP proof issued-at claim is outside the supported range"
            ) from exc
        if (
            issued_at > current + timedelta(seconds=self.clock_skew_seconds)
            or issued_at < current - timedelta(seconds=self.max_age_seconds)
        ):
            raise PermissionError("DPoP proof freshness window has elapsed or is not yet valid")

        jti = claims.get("jti")
        if not isinstance(jti, str) or not _JTI_PATTERN.fullmatch(jti):
            raise PermissionError("DPoP proof identifier is malformed")
        if claims.get("htm") != method:
            raise PermissionError("DPoP HTTP method binding does not match")
        expected_htu = self._htu(uri)
        if claims.get("htu") != expected_htu:
            raise PermissionError("DPoP HTTP URI binding does not match")
        expected_ath = self._base64url(hashlib.sha256(access_token.encode("utf-8")).digest())
        actual_ath = claims.get("ath")
        if not isinstance(actual_ath, str) or not hmac_compare(actual_ath, expected_ath):
            raise PermissionError("DPoP access-token hash binding does not match")

        expiry = issued_at + timedelta(seconds=self.max_age_seconds + self.clock_skew_seconds)
        try:
            consumed = self.replay_cache.consume(jti, expiry)
        except Exception as exc:
            raise PermissionError("DPoP replay protection is unavailable") from exc
        if not consumed:
            raise PermissionError("DPoP proof replay detected")
        return VerifiedDPoPProof(jti=jti, jwk_thumbprint=thumbprint, issued_at=issued_at)

    @staticmethod
    def _htu(uri: str) -> str:
        try:
            parsed = urlsplit(uri)
            if (
                parsed.scheme.lower() != "https"
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.fragment
            ):
                raise ValueError
            port = parsed.port
            host = parsed.hostname.lower()
            authority = host if port in (None, 443) else f"{host}:{port}"
            return f"https://{authority}{parsed.path or '/'}"
        except (TypeError, ValueError) as exc:
            raise PermissionError("DPoP request URI must be a valid HTTPS URI") from exc

    @staticmethod
    def _public_key_and_thumbprint(
        jwk: dict[str, object], algorithm: str
    ) -> tuple[object, str]:
        kty = jwk.get("kty")
        required_members = {
            "EC": ("crv", "kty", "x", "y"),
            "RSA": ("e", "kty", "n"),
            "OKP": ("crv", "kty", "x"),
        }.get(str(kty))
        private_members = {"d", "p", "q", "dp", "dq", "qi", "oth", "k"}
        if (
            required_members is None
            or private_members.intersection(jwk)
            or any(not isinstance(jwk.get(name), str) or not jwk[name] for name in required_members)
        ):
            raise PermissionError("DPoP JWK must contain public key material only")
        if kty == "EC" and (jwk.get("crv") != "P-256" or algorithm != "ES256"):
            raise PermissionError("DPoP EC keys must use P-256 with ES256")
        if kty == "RSA" and algorithm not in {"RS256", "PS256"}:
            raise PermissionError("DPoP RSA key algorithm is not compatible")
        if kty == "OKP" and (jwk.get("crv") != "Ed25519" or algorithm != "EdDSA"):
            raise PermissionError("DPoP OKP keys must use Ed25519 with EdDSA")
        try:
            key = jwt.PyJWK.from_dict(jwk, algorithm=algorithm).key
        except Exception as exc:
            raise PermissionError("DPoP public JWK cannot be imported") from exc
        thumbprint_members = {name: jwk[name] for name in required_members}
        canonical = json.dumps(
            thumbprint_members, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        thumbprint = DPoPProofVerifier._base64url(hashlib.sha256(canonical).digest())
        return key, thumbprint

    @staticmethod
    def _base64url(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def hmac_compare(left: str, right: str) -> bool:
    """Compare proof bindings without data-dependent early exit."""
    import hmac

    return hmac.compare_digest(left.encode("ascii", errors="ignore"), right.encode("ascii"))
