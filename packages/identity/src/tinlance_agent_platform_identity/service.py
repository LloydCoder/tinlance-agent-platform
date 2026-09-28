"""Provider-neutral identity normalization and validation."""

import re
from dataclasses import replace

from tinlance_agent_platform_contracts import Principal

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")


def _normalize(value: str, field: str) -> str:
    normalized = value.strip()
    if not normalized or normalized != value or not _ID_RE.fullmatch(normalized):
        raise ValueError(f"invalid {field}")
    return normalized


def validate_principal(principal: Principal) -> Principal:
    subject_id = _normalize(principal.subject_id, "subject identifier")
    tenant_id = _normalize(principal.tenant_id, "tenant identifier")
    principal_type = _normalize(principal.principal_type, "principal type")
    if any(not scope or scope != scope.strip() for scope in principal.scopes):
        raise ValueError("principal scopes must be normalized")
    if any(not role or role != role.strip() for role in principal.roles):
        raise ValueError("principal roles must be normalized")
    return replace(
        principal,
        subject_id=subject_id,
        tenant_id=tenant_id,
        principal_type=principal_type,
    )
