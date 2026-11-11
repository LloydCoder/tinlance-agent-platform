# FCP-03 — Zero-Cost, Provider-Neutral Completion Gate

**Status: NOT ACCEPTED.** This document reconciles the FCP programme's production-security/infrastructure phase with the repository's narrower AWS implementation slices. It is an acceptance-control document, not evidence that infrastructure has been deployed or independently assessed.

## Why this gate exists

FCP-03 is broader than the three AWS templates under `infra/aws/fcp03-*`. The repository's DNS, egress and durable-storage templates are useful provider-specific candidates, but their own READMEs say they have not been deployed. The FCP programme requires production security/infrastructure qualification: network enforcement, identity and revocation, isolated persistent-computer/runtime, durable storage and recovery, telemetry/operations, economics and independent assurance.

The user constraint for this programme is **USD 0 new AWS spend**. Promotional credits are not a hard spending limit and do not satisfy a zero-spend requirement. Therefore this track must not create AWS stacks, change shared VPCs, alter Tinlyt/FusionOps/ThreatFade resources, or run billable AWS tests.

## Evidence vocabulary

| State | Meaning |
|---|---|
| `IMPLEMENTED` | Code/configuration exists in the repository. |
| `CI_VERIFIED` | Exact commit has successful applicable CI checks. |
| `LOCAL_INTEGRATION_VERIFIED` | Reproducible integration test ran on an isolated local Linux environment. |
| `HOSTED_LINUX_INTEGRATION_VERIFIED` | Actual Linux network namespaces, DNS policy and nftables enforcement ran on an ephemeral hosted CI runner with captured counters/logs and cleanup assertions. |
| `HOSTED_SERVICE_INTEGRATION_VERIFIED` | A disposable real service/container ran on a hosted CI runner and its protocol/authorization behavior was exercised; this is not a production deployment. |
| `DEPLOYED_VERIFIED` | Deployed target infrastructure and runtime evidence are archived. |
| `INDEPENDENTLY_ASSURED` | A named independent assessor completed the defined scope and closed or accepted all findings. |
| `BLOCKED` | Required evidence cannot be obtained under the current constraints. |

Never promote one state to another by inference. A template, unit test, failed client request, green CI, or scheduled teardown is not proof of live enforcement.

## Current forensic status (2026-11-11)

| Workstream | Repository evidence | Acceptance state | Remaining proof |
|---|---|---|---|
| AWS DNS Firewall | DNS-only CloudFormation template, allow-then-NXDOMAIN policy, resolver query logging, fail-closed setting, probe tests | `IMPLEMENTED` / `CI_VERIFIED` | No live DNS Firewall association, resolver RCODE transcript or correlated Resolver query logs |
| AWS network egress | Isolated single-AZ Network Firewall/NAT topology, symmetric routes, NACL/SG constraints, DoH denylist, resolved-domain policy, flow/alert logs | `IMPLEMENTED` / `CI_VERIFIED` | No deployed path, packet/flow evidence, live bypass probes or production qualification |
| Provider-neutral Linux DNS/egress lab | dnsmasq policy, isolated worker/resolver namespaces, nftables default-deny, DNS UDP/TCP, NXDOMAIN, rebinding, metadata, DoT, QUIC, direct TCP/443, IPv4/IPv6 drop counters and TLS certificate/hostname validation | `IMPLEMENTED` / `CI_VERIFIED` / `HOSTED_LINUX_INTEGRATION_VERIFIED` (PR #288 merge `37fae92`; IPv6 evidence PR #289 merge `eb06de`) | No AWS Network Firewall/Route 53 Resolver or production-host acceptance; DoH endpoint test is TCP/443 reachability, not a full HTTP/2 DoH exchange |
| Durable identity/snapshots | KMS/DynamoDB/S3/Object Lock candidate and adapter contracts | `IMPLEMENTED` / `CI_VERIFIED` | No live IAM effective-permission, revocation propagation, replay-race, snapshot-integrity or restore evidence; deployment is billable and retention is irreversible |
| Sender-constrained identity | DPoP verification, `cnf.jkt` request binding and replay-cache implementation | `IMPLEMENTED` / `CI_VERIFIED` | Production issuer/JWKS, key custody, revocation feed, durable cache and end-to-end deployed tests |
| External secret provider | Tenant-scoped OpenBao KV v2 adapter; exact secret-version selection; token-header auth; redirect rejection; bounded responses; redacted failures; disposable OpenBao policy test proving cross-tenant denial | `IMPLEMENTED` / `CI_VERIFIED` / `HOSTED_SERVICE_INTEGRATION_VERIFIED` (PR #291 merge `d5993cfd`) | No production OpenBao endpoint, identity integration, TLS trust provisioning, token rotation/lease renewal, HA/seal recovery or operational alert evidence |
| Host/runtime isolation | Existing sandbox/runtime code and phase-2 evidence; PR #293 triggers W3 browser environment, W4 adversarial browser isolation, gVisor restricted-workload benchmark and Firecracker jailer/guest boot smoke on ephemeral runners | `IMPLEMENTED` / `CI_VERIFIED` / selected `HOSTED_SERVICE_INTEGRATION_VERIFIED` | Production host/firmware/attestation, sustained end-to-end persistent-computer qualification, production resource ceilings, independent escape assessment and operational isolation evidence |
| Persistence and DR | PostgreSQL outbox/snapshot-catalog/restore-ledger adapters now run against a real ephemeral PostgreSQL 17 service in CI (PR #293); tenant RLS under a non-login runtime role, claim/ack/release, redaction, tenant isolation, idempotency and restore transitions are exercised | `IMPLEMENTED` / `CI_VERIFIED` / `HOSTED_SERVICE_INTEGRATION_VERIFIED` | No production PostgreSQL deployment, independent backup system, encrypted backup/restore drill, measured RTO/RPO or operator-owned recovery |
| Telemetry and operations | Observability contracts and OpenTelemetry adapter tests | Partial repository evidence | Live collector/exporter, alert routing, verified recipients, SLO/error-budget measurements, incident runbook and on-call ownership |
| Cost and governance | Teardown validator and documented estimates | Partial repository evidence | Enforceable spend ceiling, verified Billing/Operations/Security contacts and evidence of an operational budget control |
| Independent assurance | M29 report contract | Contract only | Actual named independent assessor, scope, findings, evidence and disposition |

The initial FCP-03 infrastructure merge `dd4b53f057cc20eb4ad0d77b42980d028b31937f` had 14 successful reported mainline check-runs. The provider-neutral Linux lab was merged as PR #288 (`37fae92ad3743c8dd97bac466f162961c012e1b2`) with 20/20 check-runs successful, including its dedicated live Linux namespace/nftables/DNS/TLS workflow. IPv6 egress counter and evidence-boundary qualification was merged as PR #289 (`eb06debed84aa8d32c8315691e01f6e51e1ed1fc`).

The tenant-scoped OpenBao KV v2 adapter was merged as PR #291 (`d5993cfd6f03ac96058507c7cf7bc2f1e0014913`). Exact-head validation passed all seven workflow runs across six distinct workflows: CI on both push and pull-request events (Python 3.12/3.13/3.14, SQL and TSIC conformance), CodeQL, Secret Scan, R10 Certification, Reference Agents and the disposable OpenBao integration. All six post-merge mainline workflows also passed: CI, CodeQL, Secret Scan, R10 Certification, Reference Agents and Supply Chain Attestation. This is local integration evidence only; no production OpenBao service or AWS resources were deployed.

This CI evidence does not substitute for the separate AWS CloudFormation cfn-lint/Checkov gate or a deployed provider environment.

As of the 2026-11-10 and early 2026-11-11 audits, all five core Agent Systems default branches were unprotected, with no required status checks. That finding is superseded by the ruleset read-back recorded at the end of this document. Issue [#275](https://github.com/LloydCoder/tinlance-agent-platform/issues/275) remains open only for the independent approving-review residual.

Cross-repository sweep (2026-11-10): no open PRs remain in Agent Platform, Agent OS, Agent Platform SDK, TADL or TSIC. SDK CodeQL action updates were consolidated and merged in PR #70 (`95cc8ef81d35392624f2070bf3a5aad4525c23a2`); superseded PRs #66–#68 were closed. Remaining open issues are Platform #275 (branch protection) and TSIC #102 (phase acceptance tracker). Latest inspected `main` SHAs: Platform `d5993cfd6f03ac96058507c7cf7bc2f1e0014913`; Agent OS `62b05001121e3c8d3d144b61700b3204aa0d4428`; SDK `95cc8ef81d35392624f2070bf3a5aad4525c23a2`; TADL `409a0bda27ba3db48e696f665bda7d4e6355e4d3`; TSIC `09533756d7bcdf7fb6de0068bc578b9c205f3b6c`. These are repository-head references, not a claim that FCP-03 is accepted.

## Zero-cost, provider-neutral implementation path

Use the provider-neutral security contract as the acceptance authority. Keep `infra/aws/fcp03-*` as an optional AWS adapter; do not replace it with claims of AWS equivalence.

| Concern | Preferred free/open-source building blocks | Acceptance boundary |
|---|---|---|
| IaC/provider portability | OpenTofu; Ansible for host configuration | Core policy/tests contain no provider SDK or cloud-specific assumptions |
| DNS policy | Unbound with Response Policy Zones (RPZ), or CoreDNS with a reviewed policy plugin | Approved name resolves; unapproved name returns explicit policy response; query is logged and correlated |
| Host/network egress | Linux network namespaces + nftables; optionally Cilium for Kubernetes workloads | Deny by default; only approved destinations/protocols pass; direct resolver, DoT, DoH, QUIC, IPv6 and metadata bypasses tested independently |
| Policy-as-code | OPA + Conftest | Policies are versioned, unit-tested, fail closed and have explicit exemption expiry |
| Runtime isolation | Existing bubblewrap; gVisor or Firecracker where host prerequisites permit | Host boundary, process tree, filesystem, CPU/memory/PIDs, network and lifetime limits independently tested |
| Identity and secrets | Keycloak/OIDC test issuer; OpenBao for secret-management integration tests; local software keys for test-only | Signature, issuer/audience, DPoP, rotation, revocation, replay and secret-scope tests; no production credentials in CI |
| Durable stores | PostgreSQL; Redis only where its durability semantics are explicitly acceptable; MinIO for S3-compatible local integration | Tenant isolation, transaction/outbox, replay atomicity, backup/restore and measured recovery tests |
| Evidence and telemetry | OpenTelemetry Collector, Prometheus, Grafana, Loki; signed JSON evidence with Sigstore/cosign where applicable | Correlated trace/event/audit evidence; redact secrets and sensitive payloads |
| Supply chain | Syft + Grype, Trivy, pip-audit, CodeQL, Gitleaks/TruffleHog, cfn-lint, Checkov, zizmor | Pinned tool/action versions, SBOM, vulnerability/license results and reproducible CI artifacts |

These tools are free/open source, but they do not make compute, storage, electricity, bandwidth, or hosting free. Local integration tests can establish software behavior; they cannot prove a remote provider's managed firewall, IAM, KMS or production control plane.

Useful upstream references:
- OpenTofu: https://opentofu.org/docs/
- CoreDNS: https://coredns.io/
- CoreDNS policy plugin (external plugin; build and pin explicitly): https://github.com/coredns/policy
- Unbound: https://unbound.docs.nlnetlabs.nl/
- nftables: https://wiki.nftables.org/
- Cilium DNS-based egress policy: https://docs.cilium.io/en/stable/security/dns/
- Open Policy Agent: https://www.openpolicyagent.org/docs/
- Conftest: https://www.conftest.dev/
- OpenBao: https://openbao.org/docs/
- OpenTelemetry: https://opentelemetry.io/docs/
- Syft/Grype: https://oss.anchore.com/docs/

## Required local qualification sequence

1. **Freeze the shared environment.** No mutation of AWS, Tinlyt, FusionOps, ThreatFade, shared VPCs, production databases, or existing runtime hosts.
2. **Build an isolated Linux lab.** Use disposable network namespaces/containers, a dedicated bridge, Unbound or CoreDNS, nftables and test-only addresses. The lab must not share host routes or production credentials.
3. **Prove DNS policy separately from network isolation.** Query the policy resolver directly and assert explicit response codes; separately prove direct external-resolver traffic is blocked by the network layer. Correlate resolver logs and firewall counters.
4. **Prove protocol bypass resistance.** Test direct DNS, TCP/UDP 53, DoT/853, known and custom DoH, QUIC/UDP 443, IPv4/IPv6, DNS rebinding, direct-IP/SNI mismatch, metadata endpoints and local/VPC route bypasses. A timeout alone is inconclusive; require a matching rule counter, packet trace or flow record.
5. **Prove identity and revocation.** Exercise signed JWT/JWKS, issuer/audience, clock skew, DPoP `htm`/`htu`/`ath`, `cnf.jkt`, atomic replay rejection, expiry, revocation propagation and key rotation with real local adapters.
6. **Prove runtime/host isolation.** Run hostile child-process, filesystem, namespace, network, resource-exhaustion and supervisor-crash tests; record host kernel/runtime prerequisites and actual resource ceilings.
7. **Prove durability and recovery.** Run PostgreSQL/outbox crash/retry/duplicate-delivery tests, encrypted snapshot/restore, corruption detection, tenant isolation and measured RTO/RPO. MinIO is a local S3-compatible test target, not proof of AWS S3/KMS behavior.
8. **Prove operations.** Send traces, metrics and security events to a local OTel pipeline; verify redaction, correlation, alert evaluation, runbooks and incident-evidence export. A configured alert without a verified receiver is not an operational control.
9. **Run security and supply-chain gates.** Ruff, mypy, pytest, SQL/RLS tests, CodeQL, secret scanning, dependency audit, SBOM, IaC lint/policy and workflow lint. Preserve raw artifacts and exact commit SHAs.
10. **Independent assurance remains external.** A free tool cannot substitute for an independent assessor. Record this as blocked until an actual assessor completes the agreed scope.

## Exit criteria for FCP-03

FCP-03 can be accepted only when all of the following are true:

- [ ] Provider-neutral DNS and network policy contracts are executable and tested.
- [x] The declared local Linux lab cases pass on a hosted Linux runner with DNS query logs, nftables drop counters, TLS certificate/hostname validation and host-state cleanup evidence (PR #288).
- [x] Extend and retain IPv6 firewall drop-counter evidence (PR #289 merged as `eb06debed84aa8d32c8315691e01f6e51e1ed1fc`).
- [ ] Add a full HTTP/2 DoH protocol test if DoH protocol behavior, rather than default-deny destination reachability, is part of the acceptance scope.
- [ ] AWS adapter templates pass cfn-lint, Checkov and schema validation, without claiming live AWS acceptance.
- [ ] Production identity/JWKS/DPoP/revocation/key lifecycle are verified against real configured adapters.
- [ ] Production host/runtime isolation and persistent-computer controls pass adversarial tests.
- [x] Tenant-scoped OpenBao KV v2 adapter passes disposable hosted-service integration for version pinning and cross-tenant denial (PR #291); this does not establish production OpenBao deployment.
- [ ] Durable persistence, outbox, production secret-manager operations, backup/restore and measured RTO/RPO are verified.
- [ ] OTel pipeline, alert routing, SLOs, incident runbooks and operational ownership are verified.
- [ ] Cost controls, contacts and escalation are verifiably configured; no spend is incurred under the current zero-AWS-spend constraint.
- [ ] Exact commit has all applicable CI/workflow checks green and branch protection is enforced.
- [ ] Independent assurance is completed with no unresolved critical/high findings or explicitly accepted exceptions.

**Current result: NOT ACCEPTED.** The no-cost local work can close repository and local-integration evidence gaps, but production-provider evidence and independent assurance remain separate acceptance dependencies. Do not start FCP-04 until every exit criterion is closed or formally accepted by the programme owner.

## FCP-04 sequencing

FCP-04 is the agent-workforce runtime and autonomous-orchestration phase. It remains gated behind FCP-03 acceptance. Do not create FCP-04 implementation branches or represent preparatory work as phase commencement while FCP-03 is not accepted. The canonical M0–M29 repository roadmap is a separate taxonomy and must not be relabelled as FCP-00–FCP-10.


### 2026-11-11 forensic delta — PostgreSQL and runtime CI qualification

Agent Platform PR [#293](https://github.com/LloydCoder/tinlance-agent-platform/pull/293) merged as `fd5004a0077746d11884de51d55ed40fdab077ef` (head `42545ef37797abc0a3c4bd3e060177d708b1f19d`). The exact PR-head run set completed successfully, including CI, CodeQL, Secret Scan, Reference Agents, R10 Certification, persistent-computer W3 browser environment, W4 adversarial browser isolation, gVisor W1 restricted-workload benchmark, Firecracker jailer smoke and KVM guest-boot smoke. Mainline has 14 reported successful check-runs.

The PR adds live adapter integration tests against a disposable PostgreSQL 17 CI service for `PostgresOutboxPublisher`, `PostgresSnapshotCatalog` and `PostgresRestoreLedger`. Tests exercise tenant RLS using a non-login runtime role, outbox claim/ack/release, error redaction, cross-tenant isolation, snapshot catalog idempotency and restore transitions. This closes an adapter-to-real-PostgreSQL CI evidence gap. It does **not** establish a production database deployment, independent backup, encrypted restore, measured RTO/RPO or operational recovery ownership.

The additional runtime workflows establish bounded ephemeral-runner evidence only. They do not establish production host attestation, a sustained production persistent-computer service, multi-tenant noisy-neighbour isolation, provider-independent hardware assurance or an independent sandbox-escape assessment.

### Cross-repository live state (2026-11-11)

- Five core repositories were re-read: Agent Platform, Agent OS, Platform SDK, TADL/Agent Developer and TSIC. No open PRs were returned. The only open issues observed are Platform #275 (default-branch governance) and TSIC #102 (canonical FCP-03 production acceptance tracker).
- Latest observed main commits: Platform `fd5004a0077746d11884de51d55ed40fdab077ef`; Agent OS `62b05001121e3c8d3d144b61700b3204aa0d4428`; Platform SDK `95cc8ef81d35392624f2070bf3a5aad4525c23a2`; TADL `409a0bda27ba3db48e696f665bda7d4e6355e4d3`; TSIC `09533756d7bcdf7fb6de0068bc578b9c205f3b6c`.
- The latest SDK main check-run read included one queued `.github/dependabot.yml` check with no conclusion; all other reported checks were successful. Do not label that entire check-run set fully green until the queued check concludes or is confirmed non-blocking by the workflow owner.
- The 2026-11-11 morning read found all five default branches `protected: false`. That is historical. The later ruleset read-back in the section below supersedes it. Platform issue #275 remains open because approving review count is still 0.
- TSIC issue #102 remains the canonical programme tracker and records FCP-03 as active/incomplete. TADS remains adjacent to, not a substitute for, the five core conformance repositories.

**Updated disposition: FCP-03 remains NOT ACCEPTED.** PR #293 materially improves hosted-service and runtime CI evidence, and default-branch rulesets are now active, but production identity/key custody/revocation, deployed network enforcement or an approved equivalent target, production host isolation, backup/DR, operational alert ownership, independent approving review and independent assessment remain open. FCP-04 through FCP-10 remain gated.

### 2026-11-11 ruleset read-back

Owner administration created and read back ruleset `fcp03-default-branch` on the five core default branches:

| Repository | Ruleset ID | Required PR checks |
|---|---:|---:|
| Agent Platform | 27050541 | 13 |
| Agent OS | 27050544 | 7 |
| Platform SDK | 27050546 | 6 |
| TADL / Agent Developer | 27050548 | 5 |
| TSIC | 27050549 | 32 |

Enforcement is active. Bypass actors are empty. Deletion and non-fast-forward pushes are denied. Pull requests and conversation resolution are required. Status checks are strict. `GET /rules/branches/main` returned `deletion`, `non_fast_forward`, `pull_request` and `required_status_checks` on each repository, and `protected` read back `true`.

Checks were limited to workflows that run on every pull request. Path-filtered FCP-03 lab, OpenBao, CloudFormation and persistent-computer workflows are not required checks, because GitHub would block unrelated pull requests waiting for checks that never start. Push-only attestation workflows are likewise not PR-required.

Approving review count is 0. Each repository's only collaborator is `LloydCoder`. Raising the count without a second reviewer would be an unsatisfiable gate. That residual is not waived; it is the remaining reason issue #275 stays open.

Dependabot alerts and security updates were enabled. A simultaneous read returned 0 open alerts, which is not a zero-risk claim. Secret scanning and push protection were already on. Validity checks and non-provider patterns stayed disabled after the settings write and are not claimed as enabled.

No AWS credential was available and no AWS resource was created. This read-back is not FCP-03 acceptance.

