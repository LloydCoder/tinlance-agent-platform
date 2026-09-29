from tinlance_agent_platform_sdk import DEFERRED_OPERATIONS, PUBLIC_OPERATIONS


def test_reference_agents_use_only_published_sdk_operations():
    assert "tools.execute" in PUBLIC_OPERATIONS
    assert "approval.approve" in DEFERRED_OPERATIONS or any(
        "approval" in operation for operation in DEFERRED_OPERATIONS
    )


def test_remote_execution_is_published_by_the_platform():
    assert "tools.execute" in PUBLIC_OPERATIONS
    assert "runs.wait" not in PUBLIC_OPERATIONS
