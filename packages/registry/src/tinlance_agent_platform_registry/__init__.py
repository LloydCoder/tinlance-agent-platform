"""Governed resource registry contracts."""

from .governance import Compatibility, LifecycleAction, ResourceGovernance
from .resources import ResourceKind, ResourceRecord, ResourceState

__all__ = [
    "Compatibility",
    "LifecycleAction",
    "ResourceGovernance",
    "ResourceKind",
    "ResourceRecord",
    "ResourceState",
]
