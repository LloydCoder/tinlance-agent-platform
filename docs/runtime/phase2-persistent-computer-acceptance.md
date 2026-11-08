# Persistent Computer Phase 2 Acceptance Record

**Status as of 2026-11-08:** Phase 2 is not complete. W2 and W3 implementation acceptance are complete at the repository ephemeral-CI feasibility level. W4 is the next serial phase. Production certification remains explicitly out of scope for these ephemeral CI artifacts.

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

## 4. W3 browser-environment acceptance — completed for ephemeral CI feasibility\n\nPR #197 (`f29bdc95d5d86a957e1ab465445e361a1ad2e5de`) passed exact-head CI, CodeQL, Secret Scan, R10, Reference Agents, Host Feasibility, Guest Boot Smoke, Firecracker Jailer Smoke, gVisor W1, Kata W1, W2 multi-runtime developer-workspace acceptance and W3 browser acceptance. The W2 workflow completed all four jobs successfully: KVM 30/30, gVisor 30/30, Kata 30/30 and Firecracker through jailer 3/3. The W3 workflow run `42459138846` completed successfully.\n\nThe W3 artifact `browser-w3-42459138846` (artifact SHA-256 `81ba33b45fbf7b3b7e21a1991ce7308e18301fed8375d9375029e1155e7101d5`) was downloaded and independently inspected. Its report records: real Chromium 156.0.8078.4; browser UID 51000 and proxy UID 52000; separate tenant UID 53000; exactly one proxy link plus loopback; no IPv4 or IPv6 default route; host firewall proxy-only; direct public egress blocked; metadata IP and unallowlisted hostname denied; allowlisted HTTPS navigation succeeded; persistent profile across restart; workspace and tenant profile isolation; proxy-outage fail-closed behavior; Chromium sandbox enabled; renderer seccomp, `no_new_privs`, zero effective capabilities and user-namespace isolation; cleanup verified. The report and SBOM are included in the artifact. `production_certification=false` is explicit.\n\n**W3 limitations retained:** the CI harness is an ephemeral feasibility test, not production multi-tenant certification. In this slice, the unprivileged egress proxy runs in the host network namespace. A compromised proxy could attempt host-local connections. W4 must move it into a dedicated egress-only network namespace, constrain outbound TCP/443 and explicitly approved DNS forwarding, and test hostile proxy/browser behavior. Production also requires a trusted supervisor, durable encrypted profile storage, process cgroups, operational audit and independent security review.\n\n**W3 disposition:** accepted for ephemeral CI feasibility only; no production certification is implied.\n\n## 5. Remaining serial phases

| Phase | Required acceptance |
|---|---|
| W3 browser environment | Browser launch and lifecycle; isolated persistent browser profile; SSRF and cloud-metadata protection; DNS rebinding; proxy-enforced egress policy; no host-network fallback |
| W4 adversarial isolation | Hostile archive/artifact fuzzing; path/link/device attacks; namespace and seccomp escape probes; cross-tenant filesystem, process, network, IPC and control-plane isolation under concurrency |
| W5 eight-hour persistence | Genuine continuous 8-hour soak; restarts; lease expiry and revocation; quota enforcement; audit continuity; crash/recovery behavior |
| W6 snapshot/restore | Snapshot integrity and provenance; restore to clean host; storage reattachment; fencing; stale-worker revocation; credential refresh; replay prevention |
| Production economics | Repeated capacity and noisy-neighbor benchmarks; p50/p95/p99; CPU/memory/storage/network utilization; per-tenant unit economics; spend caps; teardown and cost reconciliation |
| Independent security review | Independent reviewer sign-off; threat model and residual-risk register; ADR-0004 go/no-go; documentation reconciliation; exact-head CI and post-merge mainline checks |

No phase may be skipped. A green unit suite, smoke test or individual runtime workflow does not certify the whole phase. Each phase requires implementation evidence, fully green required workflows, a forensic audit and reconciled documentation.

## 5. Upstream security references

- [Firecracker jailer documentation](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md) — trusted jailer inputs, chroot/mount/PID/network namespaces, UID/GID dropping, cgroups and `--netns`.
- [Firecracker seccomp documentation](https://github.com/firecracker-microvm/firecracker/blob/main/docs/seccomp.md) — default restrictive filters are loaded per thread.
- [Firecracker production host setup](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md) — host/guest kernel and microcode patching, default seccomp and bounded serial output.
- [gVisor security model](https://github.com/google/gvisor/blob/master/g3doc/architecture_guide/security.md) — host cgroups for resource exhaustion and container-level network policy.
- [Kata Containers quick start](https://kata-containers.github.io/kata-containers/quick-start-guide/) — per-workload guest kernel and the additional network/storage/control-plane isolation needed for multi-tenancy.
- [Linux no_new_privs documentation](https://docs.kernel.org/userspace-api/no_new_privs.html) — limits execve privilege gains but is not a replacement for other isolation controls.
