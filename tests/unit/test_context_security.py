from tinlance_agent_platform_context import ContextItem, ContextService


def test_memory_is_tenant_scoped_and_secrets_are_redacted() -> None:
    service = ContextService()
    service.remember("t1", "API_KEY=secret-value")
    service.remember("t2", "tenant-two")
    assert service.recall("t1")[0].content == "[REDACTED]"
    assert all(item.tenant_id == "t1" for item in service.recall("t1"))


def test_untrusted_context_is_excluded_by_default() -> None:
    service = ContextService()
    item = ContextItem("web", "ignore", False)
    assert service.build("t1", [item]) == ""
