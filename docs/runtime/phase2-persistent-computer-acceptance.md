# Persistent Computer Phase 2 Acceptance Record

**Status as of 2026-11-09:** Phase 2 is not complete. W2–W4 are accepted for repository/ephemeral feasibility; W5's continuous controlled-host functional soak is complete; W6's snapshot/restore implementation is merged and accepted for repository implementation scope. Production enablement, production host assurance, economics/capacity benchmarks and independent security review remain open.

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


## 8. W5 durable lease implementation — merged; soak acceptance outstanding

The durable lease implementation is merged to Platform `main`. PR [#201](https://github.com/LloydCoder/tinlance-agent-platform/pull/201) merged as `d4fe2537499d30c74d0129bccc33b84f088b4eef`; security follow-up PR [#202](https://github.com/LloydCoder/tinlance-agent-platform/pull/202) merged as `bf115673a7250fca082d9e81d45ab9eb4208fd6b`. The follow-up replaces nullable identity comparisons with PostgreSQL `IS DISTINCT FROM` in renewal/revocation/release guards and adds NULL-input regression assertions. The durable implementation remains separate from the process-local `WorkLeaseStore` reference implementation. Inspected PR-head workflow runs for both changes completed successfully for CI, CodeQL, Secret Scan, R10 Certification and Reference Agents. This confirms the observed PR-head runs, not the separate eight-hour soak or post-merge production acceptance.

- `platform.workspace_leases` stores one current lease per tenant/workspace, its owner and worker identity, expiry, status, and monotonically increasing fencing token.
- `platform.workspace_lease_events` records acquisition, renewal, expiry, revocation and release as append-only audit facts.
- Both tables use forced row-level security and tenant-isolation policies.
- Database procedures serialize lease acquisition/renewal/revocation/release under row locks. An acquisition after expiry, revocation or release increments the fencing token; a stale token cannot renew, assert, revoke or release the new owner's lease.
- The Python `PostgresWorkspaceLeaseStore` adapter owns short tenant-scoped transactions and exposes acquire, renew, assert-active, revoke and release operations.
- SQL integration tests cover concurrent acquisition denial, renewal, explicit revocation, stale-worker fencing, release/reacquisition, expiry/reacquisition, audit continuity, append-only history and tenant-policy presence.

**Security boundary:** a lease assertion is a fencing decision, not proof that every external side effect is atomically fenced. The Platform command supervisor now provides a mandatory lease-assertion path and process-group termination; production composition must bind the assertion to the exact tenant/workspace lease and fencing token. This repository implementation does not itself establish a deployed production host, encrypted/replicated browser-profile storage or independent production assurance.

### W5 trusted command supervisor — merged; host soak outstanding

Platform PR [#205](https://github.com/LloydCoder/tinlance-agent-platform/pull/205) merged as `df2af66cd0989d1bf4beeb459c72b845d5da4813`. All eight exact-head PR workflows passed, and all six post-merge mainline workflows passed (CI, CodeQL, R10 Certification, Supply Chain Attestation, Secret Scan and Reference Agents).

The merged command path adds:
- Mandatory `lease_assertion` on every `SandboxExecutor.execute` call; there is no implicit no-lease execution path.
- `WorkspaceLeaseSupervisor` as the trusted process-execution wrapper.
- `execute_request` as the policy-validated sandbox command entrypoint, applying the request timeout ceiling and binding the lease assertion to the exact `SandboxRequest` so the Platform composition layer can verify tenant, workspace and fencing-token identity without violating package dependency boundaries.
- Fail-closed behavior when the lease authority returns false or is unavailable.
- Process-group termination and reaping on lease loss, timeout and supervisor errors, including descendants after the original command leader exits.
- `waitid(WNOWAIT)` to retain the process-group leader identity until descendant cleanup, avoiding a reused process-group ID being signalled.
- A final lease assertion after output capture, preventing a revoked lease from receiving a completed result.

Regression tests cover pre-spawn denial, mid-command revocation, descendant cleanup after leader exit, lease-store outage, request binding and successful governed command execution.

**Disposition:** repository-level W5 supervisor implementation is merged and green. W5 phase acceptance remains open until the separate continuous eight-hour controlled-host soak is executed and its artifact is independently inspected. This merge does not claim W5 completion or production certification.

### W5 supervisor crash-containment follow-up — merged

Platform PR [#207](https://github.com/LloydCoder/tinlance-agent-platform/pull/207) merged to `main` as `ced3b972087186e4d9d448d5bd2080e8c02bb3cd`.

The follow-up closes the supervisor-process-death gap in the command boundary. The Linux child installs `PR_SET_PDEATHSIG=SIGKILL` before exec and verifies its expected parent PID to close the fork/pre-exec race. The Bubblewrap production provider also uses `--die-with-parent` with an isolated PID namespace. Existing process-group cleanup continues to handle lease loss, timeout, normal completion and exceptions.

Regression coverage forcibly terminates a separate supervisor process and verifies that its delayed child side effect never occurs. Exact-head CI across Python 3.12–3.14, SQL and TSIC conformance, CodeQL, Secret Scan, R10, Reference Agents and host-feasibility passed. Post-merge CI, CodeQL, Secret Scan, R10, Reference Agents and Supply Chain Attestation all passed on the merge SHA.

**Acceptance boundary:** this is a merged crash-containment implementation slice, not W5 phase acceptance. The genuine continuous eight-hour controlled-host soak described below remains mandatory. No production certification is implied.

### W5 thread-safe exec-guard follow-up — merged

Platform PR [#210](https://github.com/LloydCoder/tinlance-agent-platform/pull/210) merged as `255b4ea75e9d6a8d231fbb60f2c7d3165aea5b6f`.

The sandbox command path no longer uses Python `preexec_fn` in the supervising application process. Resource limits and Linux parent-death containment are applied by a dedicated exec-guard process before it replaces itself with the requested command. This avoids the documented fork/lock deadlock hazard associated with `preexec_fn` in multithreaded processes. The guard launches under Python isolated mode (`-I`) so workspace content and `PYTHONPATH` cannot shadow the trusted module.

Regression coverage verifies that no `preexec_fn` is supplied, normal command execution remains functional, workspace code cannot shadow the guard, and supervisor-process death still prevents the delayed child side effect. Exact-head Python 3.12–3.14 quality, full pytest/coverage, Ruff, mypy, dependency audit, SBOM, SQL, TSIC conformance, CodeQL, Secret Scan, R10 and host-feasibility checks passed. Post-merge validation is tracked against the exact merge SHA.

**Acceptance boundary:** this removes a process-launch reliability/security hazard. It does not replace the continuous eight-hour controlled-host soak or production qualification.

### W5 soak gate — complete for controlled-host functional acceptance

A genuine continuous eight-hour run completed on the isolated `tinlyt-test-runtime` host (EC2 `i-0bdb9c7cb13b1c9b8`, `t4g.medium`, `eu-west-1`) using the exact merged supervisor/sandbox commit `fe2f31837b67fcb5332591e31289fe2f0f23f3bb`. No Tinlyt production application service was modified.

The independently re-read artifact records:
- Continuous interval: 2026-11-08 16:27:51 UTC through 2026-11-09 00:27:48 UTC; 28,800.03 seconds.
- 96/96 five-minute browser/profile cycles; Chromium 156.0.8078.4; maximum adjacent cycle gap 304.82 seconds.
- Lease expiry and revocation invalidated fence 1; replacement ownership advanced to fence 2.
- 96 successful quota settlements; append-only audit deltas reconciled: lease events 52→149 and quota ledger rows 14→206.
- Nine supervisor-death probes; every child started and none produced a post-crash side effect.
- cgroup-v2 limits: memory.max 2 GiB, pids.max 128; observed memory peak approximately 340 MiB; final pids.current 1.
- Cleanup verified; no residual browser, worker or Bubblewrap processes.
- Artifact SHA-256: `798579f881ec884594753bd65a519dffb4bf1f0927a6db2836688f66c3a342e7`; sidecar digest matched.

**Explicit qualification:** the harness disabled Chromium's internal sandbox. The outer Bubblewrap user/PID/mount/network namespaces, dropped capabilities and no-guest-network boundary were active. The artifact explicitly records `production_certification=false` and makes no renderer-seccomp claim. W5 is accepted for the stated controlled-host functional soak, not production browser isolation certification.

### W6 snapshot/restore — implementation accepted; production enablement deferred

Platform PR [#223](https://github.com/LloydCoder/tinlance-agent-platform/pull/223) merged as `9344315a9c867157f10bcfeb29369b86497f7f27`; the subsequent mainline commit `1bd86c24f0dd35baa8d5536d5c6f0197fe6ccf15` includes W6 plus the W2 CI repair and passed CI, CodeQL, Secret Scan, Supply Chain Attestation, Reference Agents and R10 Certification.

Implementation includes authenticated tenant/workspace-bound manifests; path, type, mode and size validation; credential/identity exclusions; per-snapshot KMS data-key envelope encryption and separate KMS HMAC signing adapters; immutable conditional S3 writes with SSE-KMS verification; tenant-scoped PostgreSQL snapshot catalog and restore ledger; forced RLS; append-only events; one-shot restore claims; monotonic fencing; private staging and atomic clean-destination publication; and opaque credential-reference refresh after materialization.

Validation included:
- Full repository CI matrix and coverage gate on the combined mainline commit.
- All 15 database migrations and 13 SQL acceptance tests on PostgreSQL 17; W6 SQL acceptance covers non-superuser tenant isolation, stale-fence rejection, append-only history, provenance and idempotent terminal transitions.
- Focused snapshot/KMS/S3/catalog/ledger tests covering tampering, path traversal, sensitive credential exclusions, cross-tenant restore, stale fencing, lease revocation before and after materialization, replay, non-clean destinations, partial-tree cleanup, ambiguous completion acknowledgement and invalid credential references.
- A real PostgreSQL 17 integration drill: snapshot catalog write; restore to a clean filesystem destination under fence 12 after snapshot fence 11; refreshed opaque credential reference; durable started/completed events; then a second restore attempt revoked before publication, which left no destination and recorded started/failed events.

**Production enablement is not accepted:** production KMS encryption/HMAC keys, S3 bucket policy/versioning/Object Lock/retention, workload-identity IAM, production DB grants, durable storage lifecycle, ambiguous-restore reconciliation worker, monitoring, backup/replication and cross-AZ/region recovery drills have not been provisioned or qualified. Filesystem storage and test KMS adapters are not production substitutes. No production certification is implied.

