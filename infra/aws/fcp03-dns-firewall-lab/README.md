# FCP-03 Workstream B — near-zero-cost DNS Firewall lab

**Status:** deployment candidate only. **Not deployed.** Separate from the full Network Firewall lab (`fcp03-egress-lab`) and from Tinlyt/W5.

**Do not claim live DNS Firewall qualification until this stack is deployed and console/probe evidence is archived. Do not claim Network Firewall qualification from this lab.**

## Purpose

Advance FCP-03 Workstream B under the $0 Network Firewall expenditure constraint:

1. Route 53 Resolver DNS Firewall in strict allowlist + fail-closed mode (`FirewallFailOpen=DISABLED`).
2. Free Gateway VPC Endpoints for S3 and DynamoDB with **deny-all** endpoint policies (worker has no instance profile; endpoints are structural traffic-elimination paths only).
3. Worker Security Group and NACL that permit DNS **only** to the Amazon-provided VPC Resolver (`VpcResolverCidr` = VPC base+2, e.g. `10.43.0.2/32`), including full UDP/TCP return paths for DNS responses and VPC-local DHCP so a custom NACL does not break boot.
4. No Network Firewall, no NAT Gateway, no Internet Gateway, no public IPv4/IPv6, no instance profile, metadata endpoint disabled.
5. Bootstrap probes that require **explicit** success criteria (see Evidence interpretation).
6. Automatic teardown via EventBridge Scheduler (this stack only).

## Evidence interpretation (pre-merge checks 1–2)

### DNS Firewall enforcement (independent of connectivity)

`FCP03_TEST_DNS_APPROVED` and `FCP03_TEST_DNS_BLOCKED` query **only** `dig @10.43.0.2` (the VPC Route 53 Resolver). They do **not** use external resolvers.

| Marker | What it proves when PASS | What it does **not** prove |
|--------|--------------------------|----------------------------|
| `DNS_APPROVED` | Resolver returned `NOERROR` + ≥1 A for an allowlisted name — consistent with DNS Firewall ALLOW | Production multi-tenant policy isolation; live log correlation |
| `DNS_BLOCKED` | Resolver returned explicit **`NXDOMAIN`** for a non-allowlisted name — the RCODE is produced on the Resolver/DNS Firewall path, not by a missing route | That Network Firewall or SG blocked a packet; path isolation alone |

Because both probes talk to the same reachable Resolver address, a differential outcome (`NOERROR` vs `NXDOMAIN`) is evidence of **name-policy** behaviour on that path, not merely “DNS works” vs “DNS fails.” Timeout/empty status is `INCONCLUSIVE_*`, never PASS.

**Post-deploy acceptance** still requires archiving console markers **and** correlating with Resolver/DNS Firewall query logs (or equivalent) for the blocked name. Template-only review does not equal live qualification.

### Path isolation vs DNS Firewall (external resolver)

| Marker | What it proves when PASS | What it does **not** prove |
|--------|--------------------------|----------------------------|
| `EXTERNAL_RESOLVER` | Worker cannot complete `dig @8.8.8.8` (no usable path to a public resolver) | That DNS Firewall blocked a query — this lab has **no IGW/NAT**, so unreachability is expected from routing/SG/NACL alone |

Treat `EXTERNAL_RESOLVER=PASS` as **network-isolation** evidence only. Do not cite it as DNS Firewall enforcement.

## Cost model and cost gate (pre-merge check 4)

| Component | Chargeable? | Indicative rate / note |
|-----------|-------------|------------------------|
| Network Firewall | **No** | Not created |
| NAT Gateway | **No** | Not created |
| Internet Gateway / EIP | **No** | Not created |
| Gateway Endpoints (S3, DynamoDB) | **No** | Free |
| EC2 `t4g.nano` On-Demand | **Yes** | ~$0.0042/hour (ARM) |
| EBS gp3 8 GiB (encrypted, DeleteOnTermination) | **Yes** | ~$0.08/month ≈ $0.00011/hour storage |
| DNS Firewall domain lists | **Yes** | ~$0.0005 per domain-month |
| DNS Firewall query inspection | **Yes** | ~$0.60 per million queries |
| EventBridge Scheduler one-shot | **Usually free** | Confirm free-tier headroom |

**Maximum exposure example (before independent DELETE_COMPLETE):**

- Worst-case hold 24 hours if teardown fails: ~24 × $0.0042 ≈ **$0.10** EC2 + negligible EBS + DNS query cents.
- Intended 1–2 hour run: typically **< $0.02** fixed + query fees.

Still **not $0**. Before any `create-stack`: owner-approved ceiling, verified budget/alert recipient, validated `TeardownAtUtc`, and a plan to confirm `DELETE_COMPLETE` independently of Scheduler delivery.

## Topology and DNS path (pre-merge check 3)

- VPC `10.43.0.0/16`, single AZ, private worker subnet only (no IGW, no NAT).
- Resolver: **VPC base+2** (`10.43.0.2/32`) via `VpcResolverCidr`.
- SG egress: UDP/TCP 53 **only** to `VpcResolverCidr`.
- NACL egress: DHCP 67–68 to VPC CIDR (rule 90); DNS to resolver (100/110); deny rest (200).
- NACL ingress: DHCP from VPC; DNS responses ephemeral from resolver (UDP+TCP); deny rest.
- DNS Firewall: ALLOW `ApprovedDomains` (100), BLOCK `*` NXDOMAIN (200), association to VPC, `FirewallFailOpen=DISABLED`.
- Gateway Endpoints: deny-all policies.
- Teardown IAM: `cloudformation:DeleteStack` / `DescribeStacks` on **this stack ARN only**.

## Probe semantics (no false PASS)

| Marker | PASS only when | Otherwise |
|--------|----------------|-----------|
| `FCP03_TEST_DNS_APPROVED` | `dig @10.43.0.2` → `NOERROR` + ≥1 A | `INCONCLUSIVE_*` / `FAIL_STATUS_*` |
| `FCP03_TEST_DNS_BLOCKED` | `dig @10.43.0.2` → **`NXDOMAIN`** | `FAIL_UNEXPECTED_RESOLUTION` / `INCONCLUSIVE_*` |
| `FCP03_TEST_EXTERNAL_RESOLVER` | `dig @8.8.8.8` does not succeed | `FAIL_REACHABLE` / `INCONCLUSIVE_MISSING_DIG` |

## Validation (repository only — no AWS mutation)

```bash
pytest -q tests/unit/test_fcp03_dns_firewall_lab_template.py

# Optional read-only (creates no resources):
aws cloudformation validate-template \
  --region eu-west-1 \
  --template-body file://infra/aws/fcp03-dns-firewall-lab/template.json
```

## Deployment boundary

Do **not** run `create-stack` without cost-gate approval. After any approved run, verify `DELETE_COMPLETE`. PR merge and deployment authorization are separate decisions.

## What this does not close (FCP-03 acceptance matrix)

- Live Network Firewall qualification
- Network-layer SNI / resolved-IP enforcement
- DoH/DoT/QUIC deep inspection
- Production egress fail-closed qualification

## Relationship to the full egress lab

| Aspect | This lab | Full `fcp03-egress-lab` |
|--------|----------|-------------------------|
| Network Firewall | No | Yes |
| NAT / IGW | No | Yes |
| DNS Firewall allowlist | Yes | Yes |
| DoH / SNI / resolved-IP | No | Yes |
| Cost | Near-zero (EC2+EBS+DNS queries) | ~$0.44/hour baseline |
| Live claim | DNS-layer only, after deploy + RCODE + log correlation | Network path after deploy + flow evidence |
