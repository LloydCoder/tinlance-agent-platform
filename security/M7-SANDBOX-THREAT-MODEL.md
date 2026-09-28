# M7 Sandbox Threat Model

## Abuse cases

- Workspace path traversal or symlink escape.
- Sensitive host path exposure.
- Network access used for exfiltration or SSRF.
- Arbitrary command execution outside the allowlist.
- Unbounded CPU, memory, disk, process count or output.
- Missing isolation provider silently degrading to host execution.

## Controls

Sandbox requests require normalized isolated workspaces and allowlisted commands/paths. Network is denied by default. Sensitive host paths are rejected. Bubblewrap is fail-closed when unavailable. Production supervisors must enforce resource limits independently of the request contract.

## Test obligations

Traversal, symlink, sensitive-path, network, command, provider-unavailable and resource-boundary cases must be negative tests.
