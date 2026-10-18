import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tinlance_agent_platform_models.gateway import ModelRequest
from tinlance_agent_platform_models.openai_compatible import (
    ModelProviderError,
    OpenAICompatibleProvider,
    StaticModelCredential,
)


class Handler(BaseHTTPRequestHandler):
    response_status = 200
    response_document = {
        "model": "test-model",
        "choices": [{"message": {"content": "safe answer"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 4, "completion_tokens": 2},
    }
    last_headers = None
    last_body = None
    response_content_type = "application/json"
    response_raw = None
    response_delay = 0.0
    redirect_location = None

    def do_POST(self):
        Handler.last_headers = dict(self.headers.items())
        Handler.last_body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if Handler.response_delay:
            time.sleep(Handler.response_delay)
        raw = Handler.response_raw or json.dumps(Handler.response_document).encode()
        self.send_response(Handler.response_status)
        self.send_header("Content-Type", Handler.response_content_type)
        if Handler.redirect_location:
            self.send_header("Location", Handler.redirect_location)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *_args):
        pass


@pytest.fixture
def endpoint():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    Handler.response_status = 200
    Handler.response_document = {
        "model": "test-model",
        "choices": [{"message": {"content": "safe answer"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 4, "completion_tokens": 2},
    }
    Handler.last_headers = None
    Handler.last_body = None
    Handler.response_content_type = "application/json"
    Handler.response_raw = None
    Handler.response_delay = 0.0
    Handler.redirect_location = None
    yield f"http://127.0.0.1:{server.server_port}/v1/chat/completions"
    server.shutdown()
    thread.join(timeout=2)
    server.server_close()


def request(**overrides):
    values = {
        "tenant_id": "tenant-private",
        "agent_id": "agent-private",
        "model": "test-model",
        "messages": ({"role": "user", "content": "hello", "internal_note": "must-not-leak"},),
        "max_output_tokens": 32,
        "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
        "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
    }
    values.update(overrides)
    return ModelRequest(**values)


def provider(endpoint, **overrides):
    return OpenAICompatibleProvider(
        endpoint=endpoint,
        credential_provider=StaticModelCredential("test-secret"),
        allow_insecure_localhost=True,
        **overrides,
    )


def test_openai_compatible_provider_normalizes_response_and_minimizes_payload(endpoint):
    response = provider(endpoint).complete(request())
    assert response.output == "safe answer"
    assert response.input_tokens == 4
    assert response.output_tokens == 2
    assert response.finish_reason == "stop"
    body = json.loads(Handler.last_body)
    assert body["messages"] == [{"role": "user", "content": "hello"}]
    assert "tenant-private" not in Handler.last_body.decode()
    assert "agent-private" not in Handler.last_body.decode()
    assert "internal_note" not in Handler.last_body.decode()
    assert Handler.last_headers["Authorization"] == "Bearer test-secret"
    assert Handler.last_headers["traceparent"] == request().traceparent


def test_openai_compatible_provider_normalizes_retryable_http_errors(endpoint):
    Handler.response_status = 429
    with pytest.raises(ModelProviderError) as caught:
        provider(endpoint).complete(request())
    assert caught.value.status_code == 429
    assert caught.value.retryable
    assert "test-secret" not in str(caught.value)


def test_openai_compatible_provider_rejects_model_mismatch(endpoint):
    Handler.response_document = {
        "model": "other-model",
        "choices": [{"message": {"content": "answer"}}],
        "usage": {},
    }
    with pytest.raises(ModelProviderError, match="unexpected model"):
        provider(endpoint).complete(request())


def test_openai_compatible_provider_rejects_invalid_trace_id(endpoint):
    with pytest.raises(ValueError, match="trace_id"):
        request(trace_id="0" * 32)


def test_openai_compatible_provider_rejects_invalid_traceparent(endpoint):
    with pytest.raises(ValueError, match="traceparent"):
        request(traceparent="00-" + "0" * 32 + "-00f067aa0ba902b7-01")


def test_openai_compatible_provider_rejects_non_https_remote_endpoint():
    with pytest.raises(ValueError, match="HTTPS"):
        OpenAICompatibleProvider(
            "http://" + ".".join(("provider", "example")) + "/v1/chat/completions",
            StaticModelCredential("test-secret"),
        )


def test_openai_compatible_provider_rejects_embedded_credentials():
    with pytest.raises(ValueError, match="credentials"):
        OpenAICompatibleProvider(
            (
                "https://"
                + "user:password@"
                + ".".join(("provider", "example"))
                + "/v1/chat/completions"
            ),
            StaticModelCredential("test-secret"),
        )


def test_openai_compatible_provider_rejects_oversized_response(endpoint):
    with pytest.raises(ModelProviderError, match="size limit"):
        provider(endpoint, max_response_bytes=10).complete(request())


def test_openai_compatible_provider_rejects_invalid_json(endpoint):
    Handler.response_raw = b"not-json"
    with pytest.raises(ModelProviderError, match="invalid JSON"):
        provider(endpoint).complete(request())


def test_openai_compatible_provider_rejects_unsupported_content_type(endpoint):
    Handler.response_content_type = "text/plain"
    with pytest.raises(ModelProviderError, match="content type"):
        provider(endpoint).complete(request())


def test_openai_compatible_provider_does_not_follow_redirects(endpoint):
    Handler.response_status = 302
    Handler.redirect_location = "/redirect-target"
    with pytest.raises(ModelProviderError):
        provider(endpoint).complete(request())


def test_openai_compatible_provider_rejects_oversized_request(endpoint):
    from tinlance_agent_platform_models.openai_compatible import MAX_REQUEST_BYTES

    large_request = request(messages=({"role": "user", "content": "x" * (MAX_REQUEST_BYTES + 1)},))
    with pytest.raises(ValueError, match="request limit"):
        provider(endpoint).complete(large_request)
