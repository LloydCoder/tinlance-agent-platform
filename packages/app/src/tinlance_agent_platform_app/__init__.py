"""Application composition layer for cross-package service adapters."""

from .extensions_platform_application import (
    ExtensionsAPIHandler,
    PlatformExtensionsApplication,
    create_extensions_platform_application,
)
from .twi_platform_application import (
    PlatformTWIApplication,
    create_twi_platform_application,
)
from .world_intelligence_api_handler import (
    WorldIntelligenceAPIHandler,
    WorldIntelligenceMCPDispatcher,
)

__all__ = [
    "ExtensionsAPIHandler",
    "PlatformExtensionsApplication",
    "create_extensions_platform_application",
    "PlatformTWIApplication",
    "create_twi_platform_application",
    "WorldIntelligenceAPIHandler",
    "WorldIntelligenceMCPDispatcher",
]
