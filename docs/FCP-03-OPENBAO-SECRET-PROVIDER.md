# FCP-03 OpenBao secret-provider adapter

**Status:** Provider adapter implemented; unit and live CI integration qualification pending. No production OpenBao deployment is claimed.

## Contract

The adapter implements the existing execution-scoped secret-provider interface and reads a version-pinned value from OpenBao KV v2:

`secret/data/tenants/{tenant_id}/{handle.name}?version={handle.version}`

The tenant prefix is added by the adapter. Tenant IDs and every path segment are validated; empty, dot, dot-dot, absolute, encoded and URL-injection paths are rejected. The response's KV metadata version must exactly match the handle version.

Only `ScopedSecretBroker` should be exposed to platform execution code. Keep the provider and its token callback in the trusted server-side dependency-injection boundary. The legacy unscoped `SecretBroker` remains fail-closed.

## Production configuration

- Use HTTPS with normal certificate validation. Configure `ca_bundle` only for a private CA; never disable certificate verification.
- Supply a short-lived workload token through `token_provider`. Prefer an authenticated workload identity such as JWT/OIDC or AppRole with short TTL and automatic renewal outside this adapter.
- Create least-privilege OpenBao policies scoped to one tenant path. Example for tenant `tenant-a`:

```hcl
path "secret/data/tenants/tenant-a/*" {
  capabilities = ["read"]
}
```

- Do not use an OpenBao root token in application workloads.
- The adapter sends the token in an unredirected `X-Vault-Token` header, requests `Cache-Control: no-store`, rejects redirected responses, caps response bytes, verifies the returned version, and does not include response bodies or tokens in errors.
- Plain HTTP is rejected except when `allow_insecure_loopback=True` and the endpoint is a loopback address. This flag exists for disposable local/CI development servers only.

Example:

```python
from tinlance_agent_platform_secrets import OpenBaoSecretProvider, ScopedSecretBroker

provider = OpenBaoSecretProvider(
    base_url="https://openbao.internal:8200",
    token_provider=workload_token_provider,
    mount="secret",
    ca_bundle="/etc/tinlance/pki/openbao-ca.pem",
)
broker = ScopedSecretBroker(provider)
```

## CI integration

The dedicated workflow starts the official OpenBao 2.7.2 container in disposable dev mode. The dev root token is used only by CI to seed two KV versions and create a tenant-A read-only policy token. Integration tests use that restricted token to verify exact version retrieval and tenant-B denial. The test-only HTTP endpoint is bound to loopback and is never a production configuration.

## Acceptance boundary

A green unit/integration workflow proves the adapter's behavior against the tested OpenBao version and a local dev server. It does not prove production cluster HA, seal/unseal recovery, audit-device delivery, workload identity federation, token renewal/revocation, backup/restore, TLS certificate operations, operator ownership or production tenant policy correctness. Those remain separate FCP-03 operational acceptance items.

References:
- [OpenBao KV v2](https://openbao.org/docs/secrets/kv/kv-v2/)
- [OpenBao HTTP API transport](https://openbao.org/docs/api-docs/)
- [OpenBao developer quick start](https://openbao.org/docs/get-started/developer-qs/)
