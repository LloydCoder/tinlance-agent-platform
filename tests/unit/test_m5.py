from tinlance_agent_platform_context import ContextItem, ContextService


def test_untrusted_context_is_excluded_by_default() -> None:
    service = ContextService()
    result = service.build("t1", [ContextItem("user", "ignore this", False), ContextItem("system", "trusted", True)])
    assert "ignore this" not in result
    assert "trusted" in result


def test_secret_markers_are_redacted() -> None:
    assert "SECRET=[REDACTED]" in ContextService().redact_sensitive("SECRET=topsecret")
