# Persistent Computer Runtime Evidence

## Purpose

This record consolidates the reproducible W1 feasibility evidence for the three sandbox/runtime candidates evaluated by the Platform repository. It is an engineering decision input, not a production isolation certification or a provider-selection approval.

## W1 workload contract

The current minimal W1 workload verifies the following properties inside the guest/container:

- one vCPU and a 512 MiB memory limit;
- no guest/container network interface beyond loopback, with network attachment disabled;
- read-only root filesystem, verified by attempting a write to `/etc` and requiring it to fail;
- a bounded 64 MiB `/tmp` tmpfs;
- a deterministic write/read operation in `/tmp/workload.txt`;
- a success marker emitted only after the checks complete.

For the Docker-based candidates, the shared command additionally applies `--cap-drop=ALL`, `--security-opt=no-new-privileges`, a 128 PID limit, and a 64 MiB `noexec,nosuid,nodev` tmpfs. The Firecracker guest uses a read-only root drive and its guest init enforces the no-NIC/read-only checks before emitting the W1 and ready markers.

## Recorded CI evidence

All evidence below was produced on ephemeral GitHub-hosted runners. The Ubuntu Docker candidates use the same immutable image digest:

`ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852`

| Candidate | Runtime / version | Samples | Median | p95 | p99 | Evidence |
|---|---|---:|---:|---:|---:|---|
| gVisor | runsc release-20261102.0 | 30 | 156.0 ms | 229.5 ms | 583.3 ms | PR #175 run 42181224429 |
| Firecracker | Firecracker 1.17.0 direct VMM | 30 | 1,061.9 ms | 1,066.3 ms | 1,071.4 ms | PR #174 run 42176782581 |
| Kata Containers | 4.3.1 runtime-rs + QEMU | 30 | 7,216.6 ms | 7,266.2 ms | 7,411.0 ms | PR #175 run 42181224432 |

Kata's smoke job also observed host kernel `7.0.0-1017-azure` and guest kernel `6.18.56`, confirming that this candidate launched a separate guest kernel in that run. The Kata static release archive was SHA-256 verified before installation.

The Firecracker jailer integration was separately exercised on an ephemeral KVM runner. The merged PR #176 run 42183744126 completed three jailed guest boots; the reported median was 1,075.5 ms and maximum 1,076.6 ms. The report includes host-observed process/cgroup evidence and guest isolation marker checks. This is a short smoke sample, not a statistically meaningful latency comparison.

## Interpretation and limitations

These measurements must **not** be presented as a controlled head-to-head performance benchmark:

1. The Firecracker guest uses a separately pinned guest kernel/rootfs asset set; gVisor and Kata use the same pinned Ubuntu OCI image.
2. The runtimes execute on separate ephemeral runner instances and host-kernel versions.
3. The measured boundaries are similar in intent (runtime start through successful W1 completion) but not identical in implementation: Firecracker times from immediately before the InstanceStart API request to guest readiness; Docker candidates time the `docker run` process through workload completion.
4. The 30-run sample is useful for a first p50/p95/p99 feasibility estimate, but there are no controlled warm/cold cohorts, repeated host classes, load interference controls, storage/network stress, or confidence intervals.
5. These tests prove only the properties directly asserted by the harness. They do not prove resistance to VM escape, host compromise, side channels, kernel vulnerabilities, cross-tenant attacks, or production control-plane misconfiguration.

The observed medians suggest a substantial startup-cost difference in this specific CI environment: gVisor was fastest, Firecracker was intermediate, and Kata/QEMU was slowest. That is a workload-specific observation, not a general performance ranking.

## Architecture decision

**No production runtime is selected by this evidence alone.** Keep the Platform sandbox contract provider-neutral and retain explicit runtime capabilities/profiles.

- Keep Firecracker as the primary microVM candidate for workloads requiring a separate guest kernel and stronger VM boundary, subject to production supervisor, jailer, seccomp, cgroup, filesystem, device and network-policy verification.
- Keep gVisor as a candidate for lower-startup-cost workloads where its userspace-kernel isolation model satisfies the threat model and workload compatibility requirements.
- Keep Kata as an alternative VM-backed OCI runtime where Kubernetes/containerd integration or compatibility benefits justify the additional startup and operational cost; benchmark other supported Kata configurations before ruling it out.

A production choice requires a controlled benchmark on the intended production host class and a threat-model-led isolation review. No candidate is certified for multi-tenant production from these CI runs.

## Remaining acceptance gates

The following work remains before persistent cloud computers can be considered production-ready:

- persistent workspace lifecycle: create, resume, suspend, snapshot, restore and destroy;
- tenant-bound storage encryption, key lifecycle, mount policy and cross-tenant isolation tests;
- explicit egress proxy and DNS policy with destination allowlists, private/link-local/metadata IP denial, redirect revalidation and DNS-rebinding resistance;
- supervisor-enforced CPU, memory, disk, I/O, PID, wall-clock and aggregate output quotas;
- host hardening, immutable runtime assets, jailer lifecycle ownership and cleanup/reconciliation after crashes;
- runtime image provenance, patch cadence, vulnerability response and guest-kernel update policy;
- concurrency/load testing, noisy-neighbor tests, host exhaustion and denial-of-service tests;
- durable lifecycle state, idempotent operations, leases, recovery drills, backup/restore and measured RTO/RPO;
- OpenTelemetry traces/metrics, tenant-safe logs, audit events, alerting and incident-response runbooks;
- independent security review and production-environment evidence.

## Traceability

- PR #172: gVisor W1 benchmark harness.
- PR #174: Firecracker/gVisor W1 workload alignment and Firecracker 30-sample report.
- PR #175: Kata QEMU W1 benchmark and shared runtime selection.
- PR #176: guest read-only/no-NIC marker verification through the Firecracker jailer.
- All four PRs were merged after their applicable repository checks passed. The post-merge mainline CI, CodeQL, R10 certification, Reference Agents, Secret Scan and Supply Chain Attestation checks for PR #176's merge commit passed.

This document is a snapshot of the evidence captured on 2026-11-06. Future benchmark runs must append new run IDs, exact source SHA, runtime/image digests, host class, measurement boundaries and artifact references rather than silently overwriting historical results.
