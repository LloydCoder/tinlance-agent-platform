import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from tinlance_agent_platform_models.openai_compatible import (
    ModelProviderError,
    OpenAICompatibleProvider,
    StaticModelCredential,
)
from tinlance_agent_platform_models.gateway import ModelRequest


class Handler(BaseHTTPRequestHandler):
    response_status = 200
    response_document = {
        "model": "test-model",
        "choices": [{"message": {"content": "safe answer"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 4, "completion_tokens": 2},
    }
    last_headers = None
    last_body = None

    def do_POST(self):
        Handler.last_headers = dict(self.headers.items())
        Handler.last_body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        raw = json.dumps(Handler.response_document).encode()
        self.send_response(Handler.response_status)
        self.send_header("Content-Type", "application/json")
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
    assert Handler.last_headers["X-Tinlance-Trace-ID"] == request().trace_id


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
        provider(endpoint).complete(request(trace_id="0" * 32))


def test_openai_compatible_provider_rejects_non_https_remote_endpoint():
    with pytest.raises(ValueError, match="HTTPS"):
        OpenAICompatibleProvider(
            "http://provider.example/v1/chat/completions",
            StaticModelCredential("test-secret"),
        )


def test_openai_compatible_provider_rejects_embedded_credentials():
    with pytest.raises(ValueError, match="credentials"):
        OpenAICompatibleProvider(
            "https://user:password@provider.example/v1/chat/completions",
            StaticModelCredential("test-secret"),
        )
