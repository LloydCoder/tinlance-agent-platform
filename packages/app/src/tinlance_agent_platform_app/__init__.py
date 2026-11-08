"""Application composition layer for cross-package service adapters."""

from .extensions_platform_application import (
    ExtensionsAPIHandler,
    PlatformExtensionsApplication,
    compute_extensions_dead_letter_replay_intent_fingerprint,
    create_extensions_platform_application,
    extensions_dead_letter_replay_run_id,
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
    "compute_extensions_dead_letter_replay_intent_fingerprint",
    "create_extensions_platform_application",
    "extensions_dead_letter_replay_run_id",
    "PlatformTWIApplication",
    "create_twi_platform_application",
    "WorldIntelligenceAPIHandler",
    "WorldIntelligenceMCPDispatcher",
]
