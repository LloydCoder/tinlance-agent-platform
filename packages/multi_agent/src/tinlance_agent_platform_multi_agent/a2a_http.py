"""Authenticated A2A 1.0 HTTP/JSON-RPC adapter over Platform dispatch.

This adapter owns protocol parsing only. Platform remains authoritative for identity,
policy, approvals, budgets, capabilities, and consequential execution.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlparse
from uuid import NAMESPACE_URL, UUID, uuid5

from .interoperability import A2A_PROTOCOL_VERSION, AgentCard, AgentCardSignatureVerifier

MAX_REQUEST_BYTES = 1_048_576
MAX_RESPONSE_BYTES = 1_048_576
MAX_PARTS = 64
MAX_TEXT_LENGTH = 16_384
_TRACEPARENT = re.compile(r"^00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$")


@dataclass(frozen=True, slots=True)
class A2APlatformRequest:
    tenant_id: str
    subject_id: str
    operation: str
    payload: dict[str, object]
    request_id: str
    trace_id: str | None = None
    idempotency_key: str | None = None
    authenticated_principal: object | None = None


class A2AAuthenticatedPrincipal(Protocol):
    tenant_id: str
    subject_id: str


class A2APrincipalResolver(Protocol):
    def resolve(self, bearer_token: str) -> A2AAuthenticatedPrincipal: ...


class A2APlatformResponse(Protocol):
    status: str
    payload: dict[str, object]


class A2APlatformDispatcher(Protocol):
    def dispatch(self, request: object) -> A2APlatformResponse: ...


class A2ARateLimiter(Protocol):
    def allow(self, tenant_id: str, subject_id: str) -> bool: ...


@dataclass(frozen=True, slots=True)
class A2AHTTPResponse:
    status_code: int
    headers: Mapping[str, str]
    body: bytes


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant is not allowed: {value}")


def _traceparent(value: str | None) -> str | None:
    if value is None:
        return None
    if not _TRACEPARENT.fullmatch(value):
        raise ValueError("traceparent must use W3C Trace Context version 00")
    if value[3:35] == "0" * 32 or value[36:52] == "0" * 16:
        raise ValueError("traceparent identifiers must not be all zero")
    return value


def _request_fingerprint(tenant_id: str, subject_id: str, request_id: str) -> str:
    source = f"{tenant_id}:{subject_id}:{request_id}".encode()
    return hashlib.sha256(source).hexdigest()[:32]


def _request_id(value: object) -> str:
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("JSON-RPC request id must be a string or integer")
    normalized = str(value)
    if not normalized or len(normalized) > 256 or normalized != normalized.strip():
        raise ValueError("JSON-RPC request id is invalid")
    if any(ord(char) < 0x21 or ord(char) > 0x7E for char in normalized):
        raise ValueError("JSON-RPC request id must contain printable ASCII")
    return normalized


def _validate_origin(origin: str | None, allowed_origins: frozenset[str]) -> None:
    if origin is None:
        return
    if origin == "null" or origin not in allowed_origins:
        raise PermissionError("A2A Origin is not allowed")
    parsed = urlparse(origin)
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.netloc
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise PermissionError("A2A Origin is invalid")


def _text_from_message(message: object) -> tuple[str, str | None]:
    if not isinstance(message, Mapping):
        raise ValueError("A2A message must be an object")
    if message.get("role") != "user":
        raise ValueError("A2A message/send accepts user messages only")
    message_id = message.get("messageId")
    if not isinstance(message_id, str) or not message_id or message_id != message_id.strip():
        raise ValueError("A2A messageId is required and must be normalized")
    context_id = message.get("contextId")
    if context_id is not None and (
        not isinstance(context_id, str) or not context_id or context_id != context_id.strip()
    ):
        raise ValueError("A2A contextId must be normalized when supplied")
    parts = message.get("parts")
    if not isinstance(parts, list) or not parts or len(parts) > MAX_PARTS:
        raise ValueError("A2A message requires a bounded non-empty parts array")
    texts: list[str] = []
    for part in parts:
        if not isinstance(part, Mapping) or part.get("kind") != "text":
            raise ValueError("this A2A endpoint currently accepts text parts only")
        text = part.get("text")
        if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT_LENGTH:
            raise ValueError("A2A text parts must be non-empty and bounded")
        texts.append(text)
    intent = "\n".join(texts)
    if len(intent) > MAX_TEXT_LENGTH:
        raise ValueError("combined A2A message exceeds the text safety limit")
    return intent, context_id


def _task_state(value: object) -> str:
    normalized = str(value).casefold().replace("-", "_")
    return {
        "requested": "submitted",
        "queued": "submitted",
        "accepted": "submitted",
        "waiting_approval": "input-required",
        "authorized": "working",
        "running": "working",
        "working": "working",
        "completed": "completed",
        "succeeded": "completed",
        "failed": "failed",
        "timed_out": "failed",
        "budget_exceeded": "failed",
        "cancelled": "canceled",
        "canceled": "canceled",
        "denied": "rejected",
        "rejected": "rejected",
        "outcome_unknown": "unknown",
    }.get(normalized, "unknown")


def _status_from_events(events: object) -> str:
    if not isinstance(events, list):
        return "working"
    for event in reversed(events):
        if not isinstance(event, Mapping):
            continue
        payload = event.get("payload")
        if isinstance(payload, Mapping):
            state = payload.get("state", payload.get("status"))
            if isinstance(state, str):
                mapped = _task_state(state)
                if mapped != "unknown":
                    return mapped
        event_type = event.get("event_type", event.get("type"))
        if isinstance(event_type, str):
            normalized = event_type.casefold()
            if "completed" in normalized or "succeeded" in normalized:
                return "completed"
            if "cancelled" in normalized or "canceled" in normalized:
                return "canceled"
            if "denied" in normalized or "rejected" in normalized:
                return "rejected"
            if "failed" in normalized or "timed_out" in normalized:
                return "failed"
            if "approval" in normalized and ("waiting" in normalized or "required" in normalized):
                return "input-required"
            if "started" in normalized or "running" in normalized:
                return "working"
    return "working"


class A2AProtocolService:
    """Authenticated A2A JSON-RPC entry point using Platform run operations.

    This first profile accepts text-only user messages and exposes message/send
    and tasks/get. Task IDs returned to remote peers are Platform run IDs, allowing
    subsequent task reads to re-enter Platform through runs.events.
    """

    def __init__(
        self,
        api: A2APlatformDispatcher,
        resolver: A2APrincipalResolver,
        rate_limiter: A2ARateLimiter,
        agent_card: AgentCard,
        card_verifier: AgentCardSignatureVerifier,
        *,
        allowed_origins: tuple[str, ...] = (),
    ) -> None:
        agent_card.verify_signature(card_verifier)
        origins = frozenset(allowed_origins)
        for origin in origins:
            parsed = urlparse(origin)
            if (
                origin == "null"
                or parsed.scheme not in {"https", "http"}
                or not parsed.netloc
                or parsed.path
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("allowed A2A origins must be normalized origins")
            if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError("cleartext A2A origins are allowed only for loopback development")
        self._api = api
        self._resolver = resolver
        self._rate_limiter = rate_limiter
        self._card = agent_card
        self._allowed_origins = origins

    def card_response(self) -> A2AHTTPResponse:
        encoded = json.dumps(
            self._card.as_payload(), separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        if len(encoded) > MAX_RESPONSE_BYTES:
            return self._http_error(500, "agent_card_too_large")
        return A2AHTTPResponse(
            200,
            {
                "Content-Type": "application/json",
                "Cache-Control": "public, max-age=60",
                "X-Content-Type-Options": "nosniff",
            },
            encoded,
        )

    def handle(self, headers: Mapping[str, str], raw_body: bytes) -> A2AHTTPResponse:
        normalized = {str(key).lower(): str(value) for key, value in headers.items()}
        request_id: object = None
        try:
            if len(raw_body) > MAX_REQUEST_BYTES:
                return self._http_error(413, "request_too_large")
            media_type = normalized.get("content-type", "").split(";", 1)[0].strip().lower()
            if media_type not in {"application/a2a+json", "application/json"}:
                return self._http_error(415, "a2a_json_required")
            if normalized.get("a2a-version") != A2A_PROTOCOL_VERSION:
                return self._http_error(400, "unsupported_a2a_version")
            _validate_origin(normalized.get("origin"), self._allowed_origins)
            token_header = normalized.get("authorization", "")
            if not token_header.startswith("Bearer ") or not token_header[7:].strip():
                return self._http_error(401, "unauthorized")
            try:
                principal = self._resolver.resolve(token_header[7:].strip())
            except PermissionError:
                return self._http_error(401, "unauthorized")
            if not self._rate_limiter.allow(principal.tenant_id, principal.subject_id):
                return self._http_error(429, "rate_limited")
            body = json.loads(
                raw_body.decode("utf-8"),
                object_pairs_hook=_unique_object,
                parse_constant=_reject_constant,
            )
            if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
                return self._http_error(400, "invalid_jsonrpc_request")
            request_id = body.get("id")
            normalized_id = _request_id(request_id)
            method = body.get("method")
            params = body.get("params", {})
            if not isinstance(params, dict):
                return self._rpc_error(request_id, -32602, "params must be an object")
            if method == "message/send":
                message = params.get("message")
                intent, context_id = _text_from_message(message)
                fingerprint = _request_fingerprint(
                    principal.tenant_id, principal.subject_id, normalized_id
                )
                supplied_key = normalized.get("idempotency-key")
                key = supplied_key or f"a2a-{fingerprint}"
                if (
                    len(key) < 16
                    or len(key) > 256
                    or not key.isascii()
                    or any(ord(char) < 33 or ord(char) > 126 for char in key)
                ):
                    return self._rpc_error(request_id, -32602, "invalid idempotency key")
                task_seed = supplied_key or normalized_id
                task_id = uuid5(
                    NAMESPACE_URL,
                    f"tinlance-a2a:{principal.tenant_id}:{principal.subject_id}:{task_seed}",
                )
                request = A2APlatformRequest(
                    principal.tenant_id,
                    principal.subject_id,
                    "runs.create",
                    {
                        "task_id": str(task_id),
                        "agent_id": str(self._card.agent_id),
                        "intent": intent,
                    },
                    f"a2a-{fingerprint}",
                    _traceparent(normalized.get("traceparent")),
                    key,
                    principal,
                )
                response = self._api.dispatch(request)
                if response.status.casefold() not in {"accepted", "ok", "success"}:
                    return self._rpc_error(request_id, -32603, "Platform did not accept the run")
                run_id = response.payload.get("run_id")
                state = response.payload.get("state", "requested")
                if not isinstance(run_id, str):
                    return self._rpc_error(request_id, -32603, "Platform returned an invalid run")
                try:
                    UUID(run_id)
                except ValueError:
                    return self._rpc_error(
                        request_id, -32603, "Platform returned an invalid run ID"
                    )
                task: dict[str, object] = {
                    "kind": "task",
                    "id": run_id,
                    "status": {"state": _task_state(state)},
                    "history": [dict(message)],
                }
                if context_id is not None:
                    task["contextId"] = context_id
                result: dict[str, object] = {"task": task}
            elif method == "tasks/get":
                history_length = params.get("historyLength", 0)
                if (
                    isinstance(history_length, bool)
                    or not isinstance(history_length, int)
                    or not 0 <= history_length <= 100
                ):
                    return self._rpc_error(
                        request_id, -32602, "historyLength must be an integer from 0 to 100"
                    )
                task_id_value = params.get("id")
                if not isinstance(task_id_value, str):
                    return self._rpc_error(request_id, -32602, "tasks/get requires a task id")
                try:
                    task_id = str(UUID(task_id_value))
                except ValueError:
                    return self._rpc_error(
                        request_id, -32602, "task id must be a Platform run UUID"
                    )
                request_fingerprint = _request_fingerprint(
                    principal.tenant_id, principal.subject_id, normalized_id
                )
                response = self._api.dispatch(
                    A2APlatformRequest(
                        principal.tenant_id,
                        principal.subject_id,
                        "runs.events",
                        {"run_id": task_id},
                        f"a2a-{request_fingerprint}",
                        _traceparent(normalized.get("traceparent")),
                        None,
                        principal,
                    )
                )
                if response.status.casefold() not in {"ok", "success"}:
                    return self._rpc_error(
                        request_id, -32603, "Platform could not retrieve task events"
                    )
                events = response.payload.get("events")
                task: dict[str, object] = {
                    "kind": "task",
                    "id": task_id,
                    "status": {"state": _status_from_events(events)},
                }
                if history_length > 0 and isinstance(events, list):
                    history = [
                        dict(event_payload["message"])
                        for event in events
                        if isinstance(event, Mapping)
                        and isinstance(event_payload := event.get("payload"), Mapping)
                        and isinstance(event_payload.get("message"), Mapping)
                    ]
                    if history:
                        task["history"] = history[-history_length:]
                result = task
            else:
                return self._rpc_error(request_id, -32601, "method not supported")
            return self._json_response(200, {"jsonrpc": "2.0", "id": request_id, "result": result})
        except PermissionError:
            return self._http_error(403, "forbidden")
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError, KeyError):
            return self._http_error(400, "invalid_request")
        except Exception:
            return self._http_error(500, "platform_error")

    @staticmethod
    def _json_response(status_code: int, body: Mapping[str, object]) -> A2AHTTPResponse:
        encoded = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(encoded) > MAX_RESPONSE_BYTES:
            return A2AProtocolService._http_error(500, "response_too_large")
        return A2AHTTPResponse(
            status_code,
            {
                "Content-Type": "application/a2a+json",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "A2A-Version": A2A_PROTOCOL_VERSION,
            },
            encoded,
        )

    @staticmethod
    def _http_error(status_code: int, code: str) -> A2AHTTPResponse:
        encoded = json.dumps({"error": code}, separators=(",", ":")).encode("utf-8")
        return A2AHTTPResponse(
            status_code,
            {
                "Content-Type": "application/json",
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
            },
            encoded,
        )

    @classmethod
    def _rpc_error(cls, request_id: object, code: int, message: str) -> A2AHTTPResponse:
        return cls._json_response(
            200,
            {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}},
        )
