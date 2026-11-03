"""Production composition for Platform-governed TWI HTTP operations."""

from __future__ import annotations

from dataclasses import dataclass

from tinlance_agent_platform_api.service import APIHandler, AgentPlatformAPI
from tinlance_agent_platform_identity.service_tokens import (
    KMSClient,
    KMSRS256Signer,
    PlatformServiceTokenIssuer,
)
from tinlance_agent_platform_mcp.gateway import ApprovalVerifier, MCPToolGateway
from tinlance_agent_platform_mcp.twi import (
    TWIHTTPClient,
    TWIHTTPTransport,
    register_twi_tools,
)

from .twi_api_handler import TWIAPIHandler

TWI_AUDIENCE = "tinlance-web-intelligence"
WORLD_INTELLIGENCE_AUDIENCE = "world-intelligence"
_PLATFORM_SERVICE_AUDIENCES = frozenset({TWI_AUDIENCE, WORLD_INTELLIGENCE_AUDIENCE})


@dataclass(frozen=True, slots=True)
class PlatformTWIApplication:
    """Composed Platform API, KMS signer and governed TWI gateway."""

    api: AgentPlatformAPI
    signer: KMSRS256Signer
    token_issuer: PlatformServiceTokenIssuer
    gateway: MCPToolGateway

    @property
    def jwks_provider(self) -> KMSRS256Signer:
        """Public-key provider to pass unchanged to the Platform HTTP server."""
        return self.signer


def create_twi_platform_application(
    *,
    delegate: APIHandler,
    approval_verifier: ApprovalVerifier,
    environment: str,
    kms_client: KMSClient,
    kms_key_id: str,
    issuer: str,
    client_id: str,
    twi_base_url: str,
    verification_key_ids: tuple[str, ...] = (),
    http_client: TWIHTTPClient | None = None,
    timeout_seconds: float = 5.0,
) -> PlatformTWIApplication:
    """Compose the TWI API adapter so every TWI operation crosses Platform policy.

    The delegate handles non-TWI Platform operations. The caller remains responsible for
    supplying a production principal resolver and serving the returned JWKS provider over
    HTTPS. Inbound authentication, tenant resolution and policy configuration are not inferred
    or created by this factory.
    """

    signer = KMSRS256Signer(
        kms_client=kms_client,
        key_id=kms_key_id,
        verification_key_ids=verification_key_ids,
    )
    token_issuer = PlatformServiceTokenIssuer(
        issuer=issuer,
        client_id=client_id,
        allowed_audiences=_PLATFORM_SERVICE_AUDIENCES,
        signer=signer,
    )
    transport = TWIHTTPTransport(
        base_url=twi_base_url,
        audience=TWI_AUDIENCE,
        token_issuer=token_issuer,
        http_client=http_client,
        timeout_seconds=timeout_seconds,
    )
    gateway = MCPToolGateway(transport)
    register_twi_tools(gateway)
    handler = TWIAPIHandler(
        delegate=delegate,
        gateway=gateway,
        approval_verifier=approval_verifier,
        environment=environment,
    )
    return PlatformTWIApplication(
        api=AgentPlatformAPI(handler),
        signer=signer,
        token_issuer=token_issuer,
        gateway=gateway,
    )
