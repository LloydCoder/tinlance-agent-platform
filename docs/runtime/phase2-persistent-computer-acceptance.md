# Persistent Computer Phase 2 Acceptance Record

**Status as of 2026-11-08:** Phase 2 is not complete. W2, W3 and W4 implementation acceptance are complete at the repository ephemeral-CI feasibility level. W5 is the next serial phase. Production certification remains explicitly out of scope for these ephemeral CI artifacts.

This document is the implementation-side acceptance record. The canonical TSIC tracking issue is [tinlance-system-integration#102](https://github.com/LloydCoder/tinlance-system-integration/issues/102).

## 1. Merged baseline

| Change | State | Evidence |
|---|---|---|
| PR #185 — Firecracker W2 developer workspace | Merged | `c351b15e9c3ff7dfc200bcca017f8336dfb9c2cd` |
| PR #187 — reproducible W2 rootfs | Merged | `eed697eea29e6cfb5a55a8dd1674b5611d592535` |
| PR #190 — W2 developer workspace through Firecracker jailer | Merged; W2 acceptance passed | [PR #190](https://github.com/LloydCoder/tinlance-agent-platform/pull/190), merge `80578f79ca1abbd4a10c5d5965e719438478ffb1` |

PR #187 exact-head CI, CodeQL, Secret Scan, R10, TSIC conformance, Firecracker W2, gVisor W2, Kata W2 and Reference Agents workflows passed before merge.

## 2. Reproducible rootfs evidence

The Firecracker, gVisor and Kata W2 artifacts independently reported the same normalized rootfs tar SHA-256:

`5fe52e36993c349610d45abd968ac7522618e8d63abc5b7a3f48c24c99657cdf`

- Firecracker direct-VMM W2: 30 guest workload samples.
- gVisor W2: 30 workload samples.
- Kata W2: 30 workload samples.
- Package-manifest SHA-256 recorded in the guest evidence: `3901a70e7d468e7691397dff18b05e30e666e9ec9725f71fb09f305da8bc79d7`.
- The normalized archive contains 37,809 entries: 5,199 directories, 31,411 regular files and 1,199 symlinks.
- The inspected archive contained no traversal paths, unsafe relative symlink escapes, device nodes or FIFOs. Absolute guest symlinks are converted to in-root relative symlinks during Firecracker rootfs extraction.
- The rootfs normalizer rejects unsupported extended metadata rather than silently losing xattrs/ACLs.

**Important distinction:** the 30-sample Firecracker W2 artifact is a direct-VMM ephemeral workload. It records `jailer_executed=false`. It is not W2-through-jailer evidence and does not establish production certification.

## 3. W2 jailer acceptance — completed

PR #190 merged to `main` as `80578f79ca1abbd4a10c5d5965e719438478ffb1`. Exact-head CI, CodeQL, Secret Scan, R10, TSIC conformance, Reference Agents, direct W2, jailed W2, gVisor W2, Kata W2 and the independent rootfs rebuild gate passed. The subsequent post-merge mainline CI, CodeQL, Supply Chain Attestation, Secret Scan, Reference Agents and R10 workflows also passed.

### Independent artifact audit

The artifacts from workflow run [42355933920](https://github.com/LloydCoder/tinlance-agent-platform/actions/runs/42355933920) were downloaded and inspected independently.

| Evidence | Result |
|---|---|
| Direct Firecracker W2 | 30/30 developer-workspace runs passed; `jailer_executed=false` as expected for the direct-VMM cohort |
| Firecracker W2 through jailer | 3/3 jailed developer workspaces passed; `jailer_executed=true` |
| gVisor W2 | 30/30 workloads passed |
| Kata W2 | 30/30 workloads passed |
| Shared normalized rootfs | All three runtime reports reference SHA-256 `3d11116add5c77482c8041eb5fd1e6ba4bd5bdc0fc76d990da747c28ad389088` |
| Independent rootfs rebuild | Two no-cache linux/amd64 builds produced byte-identical normalized tar archives |
| Rootfs archive inspection | 37,823 entries: 5,206 directories, 31,418 regular files and 1,199 symlinks; no traversal paths, relative symlink escapes, device nodes, FIFOs or other special entries |
| Jailer process confinement | UID 999/GID 987, zero effective capabilities, `NoNewPrivs=1`, seccomp mode 2 on all five observed Firecracker threads, isolated PID/mount/network namespaces, loopback-only network and chroot identity |
| Jailer cgroups | W2: `cpu.max=200000 100000`, `memory.max=3221225472`, `pids.max=128` across all three runs |
| Guest boundary | Read-only rootfs, no guest network beyond loopback, non-root guest UID/GID 65532, bounded noexec/nosuid/nodev tmpfs, sensitive-file/device/socket denial, denied privilege escalation and mount operations |
| Workspace behavior | Git clone/edit, Python compile/unit tests, Node edit/build/tests and local-package `npm ci --offline`; package-manifest and npm-lock digests plus tool versions recorded |

The rootfs archive SHA-256 was recomputed from the downloaded tar and matched the recorded digest. The archive contained 158 absolute guest symlinks; these are guest-root paths and are converted to in-root relative symlinks by the extraction implementation. No relative symlink escaped the root. The normalizer rejects unsafe archive paths, links and special files; the independent rebuild report records `byte_identical=true`, matching primary/rebuild image provenance, and matching rootfs digests.

The direct Firecracker report and the jailed Firecracker report are distinct evidence cohorts. The direct-VMM report is not described as jailed execution. The jailed report independently records all three successful jailer executions and process/thread confinement evidence.

### Explicit production limitations

- Both the host and guest reports record `cpu_security_mitigations_ready=false`. The host reports an unavailable/sentinel microcode revision and vulnerable status for speculative-return-stack-overflow, speculative-store-bypass and TSA mitigations; SMT is active on the CI host. This is an explicit production side-channel/security sign-off blocker, not a failed W2 functional acceptance test. Production acceptance requires provider-attested physical host SKU/firmware/microcode, SMT policy, observed host vulnerability status, `cpu_security_mitigations_ready=true`, and independent reviewer approval.
- The jailed W2 artifact records `production_certification=false`. Ephemeral CI does not establish production host hardening, multi-tenant hostile isolation, bounded production serial logging, operational ownership or deployed infrastructure.
- The CI host probe's `seccomp_active=false` is a host fact. The jailed process evidence independently proves seccomp mode 2 on every observed Firecracker thread; these facts must not be conflated.
- The CA bootstrap installs pinned CA/OpenSSL packages from the signed Ubuntu archive over HTTP while preserving APT signature and package-hash verification, then uses the immutable Ubuntu snapshot over HTTPS with normal peer verification. HTTPS certificate verification is not disabled.

**W2 disposition:** W2 reproducible rootfs, independent-build reproducibility, direct multi-runtime developer-workspace execution and Firecracker jailer-path acceptance are complete for the repository's ephemeral feasibility scope. W2 is closed for this acceptance programme. Production CPU/microcode side-channel sign-off remains a separate production gate and is not implied by W2 closure.

## 4. W3 browser-environment acceptance — completed for ephemeral CI feasibility

PR #197 was merged to Platform `main` as `2c3903c4fee096aa285014d9dc8aa6b1e5f809ea`. All 12 required exact-head pull-request workflow runs passed before merge. Post-merge mainline CI, CodeQL (successful retry after a transient GitHub release-download HTTP 504), Secret Scan, Supply Chain Attestation, Reference Agents and R10 all completed successfully on the merge commit.

The W3 artifact `browser-w3-42459138846` (artifact SHA-256 `81ba33b45fbf7b3b7e21a1991ce7308e18301fed8375d9375029e1155e7101d5`) was downloaded and independently inspected. Its report records real Chromium 156.0.8078.4; browser UID 51000 and proxy UID 52000; separate tenant UID 53000; exactly one proxy link plus loopback; no IPv4 or IPv6 default route; host firewall proxy-only; direct public egress blocked; metadata IP and unallowlisted hostname denied; allowlisted HTTPS navigation succeeded; persistent profile across restart; workspace and tenant profile isolation; proxy-outage fail-closed behavior; Chromium sandbox enabled; renderer seccomp, `no_new_privs`, zero effective capabilities and user-namespace isolation; cleanup verified. The report and SBOM are included in the artifact. `production_certification=false` is explicit.

**W3 limitations retained:** the W3 harness ran the unprivileged egress proxy in the host network namespace. A compromised proxy could attempt host-local connections. W4 therefore moves the proxy into a dedicated egress-only network namespace and constrains outbound TCP/443 plus explicitly approved DNS forwarding. Production also requires a trusted supervisor, durable encrypted profile storage, process cgroups, operational audit and independent security review.

**W3 disposition:** accepted for ephemeral CI feasibility only; no production certification is implied.

## 5. W4 adversarial isolation — accepted for ephemeral CI feasibility

PR #200 adds the dedicated egress-only proxy namespace and concurrent tenant adversarial acceptance harness. The implementation separates browser and proxy network namespaces over a private veth pair, gives the proxy a separate host-facing uplink, and keeps the browser namespace without a default route. Proxy namespace nftables defaults to drop and permits only browser-side TCP/3128, established replies, public unicast TCP/443 and DNS to a dedicated host DNS relay. Private, shared-address, loopback, link-local, metadata, reserved and multicast ranges are blocked independently of application-layer DNS validation.

The host DNS relay binds only to the proxy-facing host veth address. Host INPUT permits only UDP/TCP 53 from the proxy uplink to that relay and blocks other host-local service access. The relay forwards to the host-configured resolver. The proxy resolver file is owned by the proxy UID/GID and mode 0600. Host forwarding/NAT is scoped to the proxy uplink; the harness inserts temporary source-IP/interface/TCP-443 and established-return rules in DOCKER-USER (or FORWARD when DOCKER-USER is absent), without changing the host's global FORWARD policy, and removes those exact rules during cleanup.

The W4 harness runs browser, proxy and tenant B workloads under distinct non-root identities and private PID, IPC and mount namespaces. It verifies browser direct-egress denial; proxy public HTTPS connectivity; host-local/private/metadata/non-HTTPS egress denial; browser/proxy namespace topology; profile persistence across restart; workspace and tenant profile isolation; concurrent tenant A/B isolation; foreign PID/IPC invisibility; mount, privilege-escalation and ptrace denial; and cleanup. Chromium 156.0.8078.4 ran with its sandbox enabled; renderer seccomp, no_new_privs, zero effective capabilities and isolated renderer user namespaces were verified.

### Independently inspected W4 evidence

Workflow run [42471763414](https://github.com/LloydCoder/tinlance-agent-platform/actions/runs/42471763414) completed successfully. Artifact browser-w4-42471763414 (SHA-256 5ceaf3bf575dd26387c26d0fcab3e7a70d3b462455847df47e0d9e0362696295) was downloaded and inspected. The report SHA-256 is c172d0d69c6727f8f859b25574d776c26bdcb1c468c2ae44d7cb7ccef1cf410d; the SBOM SHA-256 is eb8f71f38a0c072a96df5615d79237a31e7a02e79738b58dbc2b44c17581f6c6.

The report records:
- Browser UID 51000, proxy UID 52000 and tenant B UID 53000.
- Browser namespace with no default route; proxy namespace with only its browser-side and host-uplink links; IPv6 disabled.
- Browser direct public egress blocked; proxy public HTTPS and allowlisted CONNECT tunnel succeeded.
- Host-local services, private/metadata destinations and non-HTTPS ports blocked at independent network boundaries.
- Resolver file owned by proxy UID/GID with mode 0600; host DNS relay limited to the proxy-facing host address.
- Persistent browser profile across restart; workspace profile isolation; tenant profile-root reuse denied.
- Concurrent cross-tenant isolation; foreign host PID and IPC segment invisibility; ptrace, mount and privilege-escalation attempts denied.
- Chromium sandbox, renderer seccomp, no_new_privs, zero effective capabilities and renderer user-namespace isolation.
- Namespace/firewall/process cleanup verified.

The artifact explicitly records production_certification=false.

**W4 residual risk:** the network layer permits public unicast TCP/443 to any destination. The proxy's application allowlist enforces domain policy, but a compromised proxy could attempt TLS exfiltration to another public TCP/443 endpoint. DNS is restricted to the dedicated host relay and host resolver, but DNS query names are not independently allowlisted. Production must add destination-level egress enforcement independent of the proxy process and explicit DNS query policy.

**W4 disposition:** accepted for ephemeral CI adversarial feasibility only. This does not certify production readiness or complete Phase 2.

## 6. Remaining serial phases

| Phase | Required acceptance |
|---|---|
| W3 browser environment | Complete for ephemeral CI feasibility; production supervisor, encrypted durable profiles and independent review remain open |
| W4 adversarial isolation | Complete for ephemeral CI feasibility; public TCP/443 destination-level enforcement and DNS query policy remain production blockers |
| W5 eight-hour persistence | Genuine continuous 8-hour soak; restarts; lease expiry and revocation; quota enforcement; audit continuity; crash/recovery behavior |
| W6 snapshot/restore | Snapshot integrity and provenance; restore to clean host; storage reattachment; fencing; stale-worker revocation; credential refresh; replay prevention |
| Production economics | Repeated capacity and noisy-neighbor benchmarks; p50/p95/p99; CPU/memory/storage/network utilization; per-tenant unit economics; spend caps; teardown and cost reconciliation |
| Independent security review | Independent reviewer sign-off; threat model and residual-risk register; ADR-0004 go/no-go; documentation reconciliation; exact-head CI and post-merge mainline checks |

No phase may be skipped. A green unit suite, smoke test or individual runtime workflow does not certify the whole phase. Each phase requires implementation evidence, fully green required workflows, a forensic audit and reconciled documentation.

## 7. Upstream security references

- [Firecracker jailer documentation](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md) — trusted jailer inputs, chroot/mount/PID/network namespaces, UID/GID dropping, cgroups and `--netns`.
- [Firecracker seccomp documentation](https://github.com/firecracker-microvm/firecracker/blob/main/docs/seccomp.md) — default restrictive filters are loaded per thread.
- [Firecracker production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md) — host/guest kernel and microcode patching, default seccomp and bounded serial output.
- [gVisor security model](https://github.com/google/gvisor/blob/master/g3doc/architecture_guide/security.md) — host cgroups for resource exhaustion and container-level network policy.
- [Kata Containers quick start](https://kata-containers.github.io/kata-containers/quick-start-guide/) — per-workload guest kernel and the additional network/storage/control-plane isolation needed for multi-tenancy.
- [Linux no_new_privs documentation](https://docs.kernel.org/userspace-api/no_new_privs.html) — limits execve privilege gains but is not a replacement for other isolation controls.


## 8. W5 implementation in progress — durable workspace lease authority

Platform PR for W5 adds a tenant-scoped PostgreSQL workspace lease authority. It is deliberately separate from the process-local `WorkLeaseStore` reference implementation.

- `platform.workspace_leases` stores one current lease per tenant/workspace, its owner and worker identity, expiry, status, and monotonically increasing fencing token.
- `platform.workspace_lease_events` records acquisition, renewal, expiry, revocation and release as append-only audit facts.
- Both tables use forced row-level security and tenant-isolation policies.
- Database procedures serialize lease acquisition/renewal/revocation/release under row locks. An acquisition after expiry, revocation or release increments the fencing token; a stale token cannot renew, assert, revoke or release the new owner's lease.
- The Python `PostgresWorkspaceLeaseStore` adapter owns short tenant-scoped transactions and exposes acquire, renew, assert-active, revoke and release operations.
- SQL integration tests cover concurrent acquisition denial, renewal, explicit revocation, stale-worker fencing, release/reacquisition, expiry/reacquisition, audit continuity, append-only history and tenant-policy presence.

**Security boundary:** a lease assertion is a fencing decision, not proof that every external side effect is atomically fenced. The production supervisor must check the current fencing token at each consequential command boundary and terminate/reap the old worker on revocation or lease loss. This PR does not claim that the browser profile is yet durably encrypted or replicated.

### W5 soak gate — not yet accepted

A genuine continuous eight-hour run remains mandatory. The GitHub-hosted runner ceiling is six hours per job, so the soak must execute on a dedicated controlled persistent host or registered self-hosted runner. It must include real browser/profile persistence across process and supervisor restarts, lease renewal/expiry/revocation, stale-worker fencing, quota admission/overrun behavior, append-only audit continuity, crash/recovery and cleanup. Segmented hosted jobs or a synthetic clock do not count as an eight-hour soak.

The active AWS instances identified during the infrastructure audit are named `fusionops-production` and `tinlyt-api-production`; neither is an acceptable W5 test host and neither was modified. A separately tagged, least-privilege W5 host is required. Until the continuous soak artifact is independently inspected and exact-head W5 workflows plus post-merge mainline checks pass, W5 remains open.
