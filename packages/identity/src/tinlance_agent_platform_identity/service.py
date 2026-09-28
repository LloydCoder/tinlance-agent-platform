"""Provider-neutral identity validation."""

from tinlance_agent_platform_contracts import Principal


def validate_principal(principal: Principal) -> Principal:
    if principal.tenant_id != principal.tenant_id.strip():
        raise ValueError("tenant identifier must be normalized")
    if principal.subject_id != principal.subject_id.strip():
        raise ValueError("subject identifier must be normalized")
    return principal
