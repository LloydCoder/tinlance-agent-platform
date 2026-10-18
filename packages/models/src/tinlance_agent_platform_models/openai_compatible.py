"""OpenAI-compatible chat-completions adapter for trusted Platform configuration.

The adapter is transport-only: route eligibility, authorization, budget reservation,
and tool authority remain in the Agent Platform. Credentials are injected and never
read from environment variables or included in exception messages.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Protocol
from urllib.parse import urlsplit

from .gateway import ModelRequest, ModelResponse

_RETRYABLE_STATUS = frozenset({408, 429, 500, 502, 503, 504})
MAX_REQUEST_BYTES = 1 * 1024 * 1024
DEFAULT_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class ModelProviderError(RuntimeError):
    """Sanitized, normalized provider failure without response-body or secret leakage."""

    def __init__(self, message: str, *, status_code: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status_code = status_code
        self.retryable = retryable


class ModelCredentialProvider(Protocol):
    def token(self) -> str: ...


@dataclass(frozen=True, slots=True)
class StaticModelCredential:
    """Caller-supplied credential; production callers should use a secret-manager adapter."""

    value: str = field(repr=False)

    def __post_init__(self) -> None:
        if (
            not self.value
            or self.value != self.value.strip()
            or any(character.isspace() for character in self.value)
            or any(character in self.value for character in "\r\n")
        ):
            raise ValueError("model credential must be a normalized bearer token")

    def token(self) -> str:
        return self.value


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ModelProviderError("provider redirects are disabled")


@dataclass(frozen=True, slots=True)
class OpenAICompatibleProvider:
    """Synchronous OpenAI-compatible chat-completions adapter.

    `endpoint` must be an explicitly configured full endpoint URL. Plain HTTP is
    allowed only for loopback test endpoints when allow_insecure_localhost=True.
    Requests do not forward tenant or agent identifiers to the provider.
    """

    endpoint: str
    credential_provider: ModelCredentialProvider = field(repr=False)
    timeout_seconds: float = 20.0
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    allow_insecure_localhost: bool = False

    def __post_init__(self) -> None:
        parsed = urlsplit(self.endpoint)
        if parsed.scheme not in {"https", "http"} or not parsed.netloc or not parsed.hostname:
            raise ValueError("provider endpoint must be an absolute HTTP(S) URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("provider endpoint must not embed credentials")
        if parsed.fragment:
            raise ValueError("provider endpoint must not contain a fragment")
        localhost = parsed.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme == "http" and not (self.allow_insecure_localhost and localhost):
            raise ValueError("HTTPS is required except for explicitly allowed loopback tests")
        if self.timeout_seconds <= 0 or self.max_response_bytes < 1:
            raise ValueError("provider timeout and response limit must be positive")

    def complete(self, request: ModelRequest) -> ModelResponse:
        try:
            token = self.credential_provider.token()
        except Exception as exc:
            raise ModelProviderError("provider credential retrieval failed") from exc
        if (
            not isinstance(token, str)
            or not token
            or token != token.strip()
            or any(character.isspace() for character in token)
        ):
            raise ModelProviderError("provider credential is invalid")

        payload = {
            "model": request.model,
            "messages": [
                {"role": message["role"], "content": message["content"]}
                for message in request.messages
            ],
            "max_tokens": request.max_output_tokens,
        }
        body = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(body) > MAX_REQUEST_BYTES:
            raise ValueError("serialized model request exceeds the configured request limit")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        }
        if request.traceparent is not None:
            headers["traceparent"] = request.traceparent
        http_request = urllib.request.Request(
            self.endpoint, data=body, headers=headers, method="POST"
        )
        opener = urllib.request.build_opener(_NoRedirectHandler())
        try:
            with opener.open(http_request, timeout=self.timeout_seconds) as response:
                status = getattr(response, "status", 200)
                content_type = (
                    response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                )
                if status < 200 or status >= 300:
                    raise ModelProviderError(
                        "provider returned an unsuccessful HTTP status",
                        status_code=status,
                        retryable=status in _RETRYABLE_STATUS,
                    )
                if content_type != "application/json":
                    raise ModelProviderError(
                        "provider returned an unsupported content type", status_code=status
                    )
                raw = response.read(self.max_response_bytes + 1)
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            raise ModelProviderError(
                "provider returned an unsuccessful HTTP status",
                status_code=status,
                retryable=status in _RETRYABLE_STATUS,
            ) from exc
        except urllib.error.URLError as exc:
            raise ModelProviderError("provider transport failed", retryable=True) from exc
        except TimeoutError as exc:
            raise ModelProviderError("provider request timed out", retryable=True) from exc

        if len(raw) > self.max_response_bytes:
            raise ModelProviderError("provider response exceeded the configured size limit")
        try:
            document = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ModelProviderError("provider returned invalid JSON") from exc
        if not isinstance(document, dict):
            raise ModelProviderError("provider response must be a JSON object")
        model = document.get("model")
        choices = document.get("choices")
        usage = document.get("usage", {})
        if not isinstance(model, str) or model != request.model:
            raise ModelProviderError("provider returned an unexpected model identifier")
        if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
            raise ModelProviderError("provider response is missing a valid choice")
        message = choices[0].get("message")
        if (
            not isinstance(message, dict)
            or not isinstance(message.get("content"), str)
            or not message["content"]
        ):
            raise ModelProviderError("provider response is missing text content")
        if not isinstance(usage, dict):
            raise ModelProviderError("provider usage must be an object")
        input_tokens = usage.get("prompt_tokens", 0)
        output_tokens = usage.get("completion_tokens", 0)
        if (
            type(input_tokens) is not int
            or type(output_tokens) is not int
            or input_tokens < 0
            or output_tokens < 0
        ):
            raise ModelProviderError("provider token usage is invalid")
        finish_reason = choices[0].get("finish_reason", "stop")
        if finish_reason is None:
            finish_reason = "stop"
        if not isinstance(finish_reason, str) or not finish_reason:
            raise ModelProviderError("provider finish reason is invalid")
        return ModelResponse(
            model=model,
            output=message["content"],
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            finish_reason=finish_reason,
        )
