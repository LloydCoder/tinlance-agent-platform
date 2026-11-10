# FCP-03 Workstream B — near-zero-cost DNS Firewall lab

**Status:** deployment candidate only. **Not deployed.** Separate from the full Network Firewall lab (`fcp03-egress-lab`) and from Tinlyt/W5.

**Do not claim live DNS Firewall qualification until this stack is deployed and console/probe evidence is archived. Do not claim Network Firewall qualification from this lab.**

## Purpose

Advance FCP-03 Workstream B under the $0 Network Firewall expenditure constraint:

1. Route 53 Resolver DNS Firewall in strict allowlist + fail-closed mode (`FirewallFailOpen=DISABLED`).
2. Free Gateway VPC Endpoints for S3 and DynamoDB with **deny-all** endpoint policies (worker has no instance profile; endpoints are structural traffic-elimination paths only).
3. Worker Security Group and NACL that permit DNS **only** to the Amazon-provided VPC Resolver (`VpcResolverCidr` = VPC base+2, e.g. `10.43.0.2/32`), including full UDP/TCP return paths for DNS responses and VPC-local DHCP so a custom NACL does not break boot.
4. No Network Firewall, no NAT Gateway, no Internet Gateway, no public IPv4/IPv6, no instance profile, metadata endpoint disabled.
5. Bootstrap probes that require **explicit** success criteria:
   - Approved domain: `dig` against the VPC Resolver must return `NOERROR` with at least one A record → `PASS`; missing `dig`, timeout, or empty status → `INCONCLUSIVE_*`; other RCODE → `FAIL_*`.
   - Blocked domain: must return explicit `NXDOMAIN` → `PASS`; unexpected `NOERROR` → `FAIL_UNEXPECTED_RESOLUTION`; missing tool/timeout/other RCODE → `INCONCLUSIVE_*`.
   - External resolver (`8.8.8.8`): must be unreachable → `PASS`; reachable → `FAIL_REACHABLE`.
6. Automatic teardown via EventBridge Scheduler (this stack only).

## Cost model (indicative, eu-west-1 / similar)

| Component | Chargeable? | Indicative rate / note |
|-----------|-------------|------------------------|
| Network Firewall | **No** | Not created |
| NAT Gateway | **No** | Not created |
| Internet Gateway / EIP | **No** | Not created |
| Gateway Endpoints (S3, DynamoDB) | **No** | Free |
| EC2 `t4g.nano` On-Demand | **Yes** | ~$0.0042/hour (ARM) |
| EBS gp3 8 GiB (encrypted, DeleteOnTermination) | **Yes** | ~$0.08/month ≈ $0.00011/hour storage; negligible IOPS for smoke probes |
| Route 53 Resolver DNS Firewall domain lists | **Yes** | ~$0.0005 per domain-month |
| DNS Firewall query inspection | **Yes** | ~$0.60 per million queries (foundational rules; Advanced rules not used) |
| EventBridge Scheduler one-shot | **Usually free** | Free tier covers most single schedules; confirm account usage |
| Data transfer | **Minimal** | No public egress path for the worker |

A two-hour lab is typically **well under $0.02** in fixed EC2+EBS plus a few DNS query cents, but **is not $0**. Obtain explicit cost-gate approval before any `create-stack`. Automatic teardown is a guardrail, not a hard spend cap.

## Topology and DNS path

- VPC `10.43.0.0/16`, single AZ, private worker subnet only (no IGW, no NAT).
- Amazon Route 53 Resolver address: **VPC base+2** (`10.43.0.2`), parameterised as `VpcResolverCidr=10.43.0.2/32`.
- SG egress: UDP/TCP 53 **only** to `VpcResolverCidr` (not the whole VPC CIDR).
- NACL egress: UDP/TCP 53 to resolver; UDP 67–68 to VPC CIDR (DHCP); deny all other egress.
- NACL ingress: ephemeral (1024–65535) from resolver for DNS responses (UDP+TCP); UDP 67–68 from VPC CIDR (DHCP); deny all other ingress.
- DNS Firewall: ALLOW `ApprovedDomains` (priority 100), BLOCK `*` NXDOMAIN (priority 200), fail closed.
- Gateway Endpoints: deny-all policies. Worker has no IAM role; endpoints demonstrate path existence without granting S3/DynamoDB data-plane access.

### Why Gateway Endpoints with deny-all?

Gateway Endpoints remove the need for a NAT path for S3/DynamoDB when credentials exist. This worker **intentionally has no instance profile**, so endpoint policies are deny-all: they cannot be used as an exfiltration channel and document that traffic elimination is orthogonal to credential grant. Do not relax endpoint policies without adding a least-privilege instance profile and a separate acceptance test.

## Probe semantics (no false PASS)

| Marker | PASS only when | Otherwise |
|--------|----------------|-----------|
| `FCP03_TEST_DNS_APPROVED` | `dig @10.43.0.2` → `NOERROR` + ≥1 A record | `INCONCLUSIVE_MISSING_DIG`, `INCONCLUSIVE_RESOLVER_UNREACHABLE_OR_TIMEOUT`, `FAIL_STATUS_*` |
| `FCP03_TEST_DNS_BLOCKED` | `dig @10.43.0.2` → status `NXDOMAIN` | `FAIL_UNEXPECTED_RESOLUTION`, `INCONCLUSIVE_*` |
| `FCP03_TEST_EXTERNAL_RESOLVER` | `dig @8.8.8.8` does not succeed | `FAIL_REACHABLE`, `INCONCLUSIVE_MISSING_DIG` |

Absence of `dig`, resolver timeout, or ambiguous RCODE must **never** be reported as PASS for allow/block checks.

## Validation (repository only — no AWS mutation)

```bash
pytest -q tests/unit/test_fcp03_dns_firewall_lab_template.py

# Optional read-only (requires AWS credentials; creates no resources):
aws cloudformation validate-template \
  --region eu-west-1 \
  --template-body file://infra/aws/fcp03-dns-firewall-lab/template.json
```

## Deployment boundary

Do **not** run `create-stack` without owner-approved monetary ceiling, verified budget notifications, validated `TeardownAtUtc`, and unique stack name. After any approved run, verify `DELETE_COMPLETE`.

## Relationship to the full egress lab

| Aspect | This lab | Full `fcp03-egress-lab` |
|--------|----------|-------------------------|
| Network Firewall | No | Yes |
| NAT / IGW | No | Yes |
| DNS Firewall allowlist | Yes | Yes |
| DoH / SNI / resolved-IP inspection | No | Yes |
| Cost | Near-zero (EC2+EBS+DNS queries) | ~$0.44/hour baseline |
| Live qualification claim | DNS-layer only, after deploy + evidence | Network path after deploy + flow evidence |
