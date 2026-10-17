"""Versioned CloudEvents-compatible envelope for Platform event delivery.

The SDK and OS may serialize this contract, but only the Platform authorizes
consequential execution and owns authoritative audit-event publication.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from urllib.parse import urlsplit

MAX_EVENT_BYTES = 1_048_576
_TRACE_ID = re.compile(r"^(?!0{32}$)[0-9a-f]{32}$")
_EVENT_TYPE = re.compile(r"^com\\.tinlance\\.[a-z0-9]+(?:[.-][a-z0-9]+)*$")
_SENSITIVE_KEYS = frozenset(
    {"secret", "password", "token", "api_key", "private_key", "credential", "authorization"}
)


def _freeze_json(value: object) -> object:
    if isinstance(value, dict):
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_json(item) for item in value]
    return value


def _has_sensitive_key(value: object) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            normalized = str(key).lower().replace("-", "_")
            if normalized in _SENSITIVE_KEYS or any(
                normalized.endswith("_" + marker) for marker in _SENSITIVE_KEYS
            ):
                return True
            if _has_sensitive_key(item):
                return True
    elif isinstance(value, (list, tuple)):
        return any(_has_sensitive_key(item) for item in value)
    return False


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    specversion: str
    id: str
    source: str
    type: str
    time: str
    subject: str
    datacontenttype: str
    tenantid: str
    executionid: str
    traceid: str
    correlationid: str
    data: Mapping[str, object]
    dataschema: str | None = None
    idempotencykey: str | None = None

    def __post_init__(self) -> None:
        if self.specversion != "1.0":
            raise ValueError("specversion must be CloudEvents 1.0")
        for value, name, maximum in (
            (self.id, "id", 256),
            (self.source, "source", 2048),
            (self.type, "type", 256),
            (self.subject, "subject", 256),
            (self.tenantid, "tenantid", 256),
            (self.executionid, "executionid", 256),
            (self.correlationid, "correlationid", 256),
        ):
            if not value or value != value.strip() or len(value) > maximum:
                raise ValueError(f"{name} is required, normalized, and within its size limit")
        if any(character.isspace() for character in self.source):
            raise ValueError("source must be a URI reference without whitespace")
        try:
            parsed_source = urlsplit(self.source)
        except ValueError as exc:
            raise ValueError("source must be a valid URI reference") from exc
        if not (parsed_source.scheme or self.source.startswith(("/", "./", "../", "#"))):
            raise ValueError("source must be an absolute or relative URI reference")
        if not _EVENT_TYPE.fullmatch(self.type):
            raise ValueError("type must use the versioned com.tinlance.* event namespace")
        if self.datacontenttype != "application/json":
            raise ValueError("datacontenttype must be application/json")
        try:
            parsed_time = datetime.fromisoformat(self.time.replace("Z", "+00:00"))
        except (ValueError, AttributeError) as exc:
            raise ValueError("time must be an ISO-8601 date-time") from exc
        if parsed_time.tzinfo is None or parsed_time.utcoffset() is None:
            raise ValueError("time must include a timezone")
        if not _TRACE_ID.fullmatch(self.traceid):
            raise ValueError("traceid must be a non-zero lowercase 32-hex trace identifier")
        if self.dataschema is not None:
            if not self.dataschema or self.dataschema != self.dataschema.strip():
                raise ValueError("dataschema must be normalized when provided")
            if any(character.isspace() for character in self.dataschema):
                raise ValueError("dataschema must be a URI without whitespace")
        if self.idempotencykey is not None and (
            not self.idempotencykey
            or self.idempotencykey != self.idempotencykey.strip()
            or len(self.idempotencykey) > 256
        ):
            raise ValueError("idempotencykey must be normalized and at most 256 characters")
        if not isinstance(self.data, Mapping):
            raise ValueError("data must be a JSON object")
        if len(self.data) > 64:
            raise ValueError("data has too many top-level fields")
        if _has_sensitive_key(self.data):
            raise ValueError("sensitive event fields are forbidden")
        try:
            encoded = json.dumps(
                dict(self.to_payload(include_frozen_data=False)),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError) as exc:
            raise ValueError("event data must be finite JSON values") from exc
        if len(encoded) > MAX_EVENT_BYTES:
            raise ValueError("event envelope exceeds the 1 MiB limit")
        object.__setattr__(self, "data", _freeze_json(json.loads(json.dumps(self.data, allow_nan=False))))

    def to_payload(self, *, include_frozen_data: bool = True) -> dict[str, object]:
        data = self.data if include_frozen_data else _thaw_json(self.data)
        result: dict[str, object] = {
            "specversion": self.specversion,
            "id": self.id,
            "source": self.source,
            "type": self.type,
            "time": self.time,
            "subject": self.subject,
            "datacontenttype": self.datacontenttype,
            "tenantid": self.tenantid,
            "executionid": self.executionid,
            "traceid": self.traceid,
            "correlationid": self.correlationid,
            "data": _thaw_json(data),
        }
        if self.dataschema is not None:
            result["dataschema"] = self.dataschema
        if self.idempotencykey is not None:
            result["idempotencykey"] = self.idempotencykey
        return result

    def to_json(self) -> str:
        return json.dumps(
            self.to_payload(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )

    @property
    def payload_digest(self) -> str:
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_payload(cls, payload: Mapping[str, object]) -> EventEnvelope:
        allowed = {
            "specversion", "id", "source", "type", "time", "subject", "datacontenttype",
            "tenantid", "executionid", "traceid", "correlationid", "data", "dataschema",
            "idempotencykey",
        }
        if set(payload) - allowed:
            raise ValueError("event envelope contains undeclared attributes")
        required = allowed - {"dataschema", "idempotencykey"}
        if not required.issubset(payload):
            raise ValueError("event envelope is missing required attributes")
        data = payload["data"]
        if not isinstance(data, Mapping):
            raise ValueError("data must be a JSON object")
        string_fields = (
            "specversion", "id", "source", "type", "time", "subject", "datacontenttype",
            "tenantid", "executionid", "traceid", "correlationid",
        )
        if any(not isinstance(payload[name], str) for name in string_fields):
            raise ValueError("event envelope attributes must use their declared types")
        for name in ("dataschema", "idempotencykey"):
            if name in payload and not isinstance(payload[name], str):
                raise ValueError(f"{name} must be a string when provided")
        return cls(
            specversion=payload["specversion"],
            id=payload["id"],
            source=payload["source"],
            type=payload["type"],
            time=payload["time"],
            subject=payload["subject"],
            datacontenttype=payload["datacontenttype"],
            tenantid=payload["tenantid"],
            executionid=payload["executionid"],
            traceid=payload["traceid"],
            correlationid=payload["correlationid"],
            data=data,
            dataschema=payload.get("dataschema"),
            idempotencykey=payload.get("idempotencykey"),
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> EventEnvelope:
        try:
            payload = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError) as exc:
            raise ValueError("event envelope must be valid JSON") from exc
        if not isinstance(payload, Mapping):
            raise ValueError("event envelope must be a JSON object")
        return cls.from_payload(payload)
