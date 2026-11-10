# FCP-03 Workstream B — near-zero-cost DNS Firewall lab

**Status:** deployment candidate only. Not deployed. Separate from the full Network Firewall lab (`fcp03-egress-lab`) and from Tinlyt/W5.

## Purpose

Advance FCP-03 Workstream B under the $0 new AWS expenditure constraint by providing:

1. Route 53 Resolver DNS Firewall in strict allowlist + fail-closed mode.
2. Free Gateway VPC Endpoints for S3 and DynamoDB (traffic elimination).
3. Worker Security Group and NACL that permit DNS only to the VPC CIDR (Route 53 Resolver path) and deny all other egress.
4. No Network Firewall, no NAT Gateway, no public IPv4/IPv6 on the worker, no instance profile, metadata endpoint disabled.
5. Bounded bootstrap probes that emit structured markers to the EC2 console (`FCP03_TEST_DNS_APPROVED`, `FCP03_TEST_DNS_BLOCKED`, `FCP03_TEST_EXTERNAL_RESOLVER`).
6. Automatic teardown via EventBridge Scheduler (same pattern as the full lab).

This lab produces evidence for **DNS-layer** deny-by-default and external-resolver isolation. It does **not** replace live AWS Network Firewall qualification for SNI/resolved-IP validation, hardcoded-IP C2, or deep packet inspection.

## Cost model (indicative)

| Component | Cost |
|-----------|------|
| Network Firewall | **$0** (not created) |
| NAT Gateway | **$0** (not created) |
| Gateway Endpoints (S3, DynamoDB) | **$0** |
| DNS Firewall domain-list rules | ~$0.0005 per domain-month + query inspection (~$0.60 / million queries) |
| t4g.nano worker | ~$0.0042/hour On-Demand (ARM) |
| Public IPv4 | **$0** (none attached) |

A short run is effectively limited to EC2 + negligible DNS query charges. Still obtain explicit cost-gate approval before any `create-stack`.

## Topology

- Single VPC (`10.43.0.0/16`), single AZ, private worker subnet only.
- No Internet Gateway, no NAT, no public route.
- Worker SG: no ingress; egress UDP/TCP 53 only to VPC CIDR.
- Worker NACL: allow DNS to VPC CIDR; deny all other egress; limited ephemeral return.
- DNS Firewall: ALLOW `ApprovedDomains`, then BLOCK `*` with NXDOMAIN; `FirewallFailOpen=DISABLED`.
- Free S3 and DynamoDB Gateway Endpoints attached to the worker route table.
- Worker has no instance profile; `HttpEndpoint=disabled`; probes write to console only.

## Validation (read-only)

```bash
# Schema / unit tests
pytest -q tests/unit/test_fcp03_dns_firewall_lab_template.py

# Optional: CloudFormation ValidateTemplate (no resources created)
aws cloudformation validate-template \
  --region eu-west-1 \
  --template-body file://infra/aws/fcp03-dns-firewall-lab/template.json
```

## Deployment boundary

Do **not** run `create-stack` without:

1. Owner-approved bounded monetary ceiling.
2. Verified notification recipient for any budget alerts.
3. Validated `TeardownAtUtc` via `scripts/validate_fcp03_teardown_at.py`.
4. Confirmation that this stack name does not collide with an active lab.

After any approved run, verify `DELETE_COMPLETE`. Automatic teardown is a guardrail, not a hard spend cap.

## Relationship to the full egress lab

| Aspect | This lab (`fcp03-dns-firewall-lab`) | Full lab (`fcp03-egress-lab`) |
|--------|------------------------------------|------------------------------|
| Network Firewall | No | Yes |
| NAT Gateway | No | Yes |
| DNS Firewall allowlist | Yes | Yes |
| DoH/SNI deep inspection | No | Yes |
| Cost | Near-zero | ~$0.44/hour baseline |
| Produces DNS evidence | Yes | Yes |
| Produces Network Firewall flow evidence | No | Yes (when deployed) |

Use this lab to close DNS-layer acceptance items under the current financial constraint. Keep the full lab as the production Network Firewall qualification target when spend is authorized.
