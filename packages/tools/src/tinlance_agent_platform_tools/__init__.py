"""Tool capability boundary."""

from tinlance_agent_platform_contracts import ToolCall

from .gateway import ToolExecutionPermit, ToolGateway, ToolRegistration

__all__ = ["ToolCall", "ToolExecutionPermit", "ToolGateway", "ToolRegistration"]
