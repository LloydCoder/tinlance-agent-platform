# Persistent Computer Phase 2 Acceptance Record

**Status as of 2026-11-07:** Phase 2 is not complete. W2 reproducible-rootfs evidence is merged. W2 execution through the Firecracker jailer is implemented in PR #190 and remains gated on exact-head workflows and artifact review.

This document is the implementation-side acceptance record. The canonical TSIC tracking issue is [tinlance-system-integration#102](https://github.com/LloydCoder/tinlance-system-integration/issues/102).

## 1. Merged baseline

| Change | State | Evidence |
|---|---|---|
| PR #185 — Firecracker W2 developer workspace | Merged | `c351b15e9c3ff7dfc200bcca017f8336dfb9c2cd` |
| PR #187 — reproducible W2 rootfs | Merged | `eed697eea29e6cfb5a55a8dd1674b5611d592535` |
| PR #190 — W2 developer workspace through Firecracker jailer | Open; acceptance pending | [PR #190](https://github.com/LloydCoder/tinlance-agent-platform/pull/190) |

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

## 3. W2 jailer acceptance gate — PR #190

PR #190 extends the existing jailer runner with a W2 profile and adds a dedicated W2 job to the shared-rootfs workflow. The jailer job downloads the exact normalized rootfs artifact produced by the direct Firecracker W2 job in the same workflow run.

The W2 jailer job must pass all of the following for **3/3** executions:

1. Real W2 developer workspace operations: Git clone/edit, Python compile/unit tests, Node edit/build/unit tests, and local-package `npm ci --offline`; host-surface probes; guest readiness markers. No guest network is available.
2. Independent rootfs reproducibility: two `docker build --pull --no-cache` builds from identical pinned inputs must produce byte-identical normalized rootfs tar files. The normalizer excludes the volatile `var/cache/ldconfig/aux-cache` file, validates volatile entries before dropping them, and records both build digests in `w2-rootfs-reproducibility.json`.
3. Rootfs and guest boundary: read-only rootfs, no guest non-loopback NIC, non-root guest UID/GID, no sensitive host devices/sockets, denied privilege escalation and mount operations, read-only proc/sys and bounded tmpfs workspace.
4. Firecracker process identity: dedicated non-root UID/GID, chroot identity, dedicated cgroup v2, PID and mount namespace isolation, zero effective capabilities and `NoNewPrivs=1`.
5. Seccomp: filter mode 2 on the Firecracker process and every observed Firecracker thread.
6. Network namespace: jailer joins a dedicated root-owned namespace handle through the upstream `--netns` option; the workflow rejects symlink handles and verifies both the handle and parent directory are root-owned and not group/world writable. The Firecracker process namespace inode must differ from the host namespace and `/proc/<pid>/net/dev` must expose only `lo`.
7. Resource limits: W2 is 2 vCPU / 2,048 MiB; its jailer cgroup allows `memory.max=3221225472` (3 GiB including VMM overhead), `pids.max=128`, and `cpu.max=200000 100000`. The separate W1 regression retains `memory.max=805306368`, `pids.max=128`, and `cpu.max=100000 100000`.
8. Provenance: jailed W2 report rootfs SHA-256 must equal the exact `w2-rootfs.sha256` artifact; image ID and base-image digest must be content-addressed.
9. Provenance: both package-manifest and npm-lock digests must be 64-character lowercase SHA-256 values; Git/Python/Node/npm version markers must be non-empty.
10. All CI, CodeQL, Secret Scan, R10, TSIC conformance, W1 jailer regression, direct W2, gVisor W2 and Kata W2 workflows must be green.

The W1 jailer smoke is a separate regression check, not a substitute for W2 jailer evidence. Its inspected artifact showed 3/3 W1 boots, seccomp mode 2 across every observed Firecracker thread, no-new-privileges, zero effective capabilities, PID/mount namespace isolation, chroot identity and the configured cgroup limits.

### Explicit evidence limitations

- The W2 host probe reports `seccomp_active=false` for the runner host while `seccomp_filter_supported=true`. This must not be misreported as proof that the Firecracker process has no seccomp filter. The process-level W2 evidence must independently show seccomp mode 2 on every thread.
- W2 artifacts and this workflow are feasibility/acceptance evidence only. The report must retain `production_certification=false`.
- The acceptance harness retains serial-console output to collect guest markers. Production must bound or rate-limit guest-controlled serial output, or disable the serial device where operationally possible.
- The CA bootstrap installs pinned CA/OpenSSL packages from the signed Ubuntu archive over HTTP while preserving APT signature and package-hash verification, then uses the pinned Ubuntu snapshot over HTTPS with normal peer verification. It must not disable HTTPS certificate verification.

## 4. Remaining serial phases

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
