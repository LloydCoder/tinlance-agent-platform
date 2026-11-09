# FCP-03 single-AZ disposable egress lab

This template is a **deployment candidate only**. It has not been deployed. It is intentionally separate from Tinlyt, FusionOps, ThreatFade, and the existing W5 runtime VPC.

## Why this is separate from the existing test host

The existing `tinlyt-test-runtime` is suitable as a controller and software-test runner, but its current subnet has a direct Internet Gateway default route and its security group allows unrestricted outbound IPv4. Changing those routes or rules would alter the W5 test host's network behavior. This lab therefore uses a dedicated VPC and keeps the existing host unchanged.

The existing host remains an out-of-band controller. The disposable worker deliberately has **no instance profile and no SSM agent-management dependency**: EC2 metadata endpoint access is disabled, and test progress is emitted to the EC2 system console. Retrieve the worker transcript with the account's read-only `ec2:GetConsoleOutput` API after the instance reaches running state. This avoids granting the worker AWS credentials merely to collect test evidence. The bootstrap selects the first entry in `ApprovedDomains` for its DNS and approved-HTTPS smoke probes, so the probe cannot silently target a domain omitted from the DNS/firewall allowlist. The direct-IP probe is explicitly marked inconclusive unless its failure is correlated with firewall flow evidence.

## Topology

- One VPC and one Availability Zone, with separate public-NAT, Network Firewall, and private-worker subnets.
- The worker has no public IPv4 address, no IPv6 address or route, no inbound security-group rules, no EC2 instance profile, and the metadata endpoint is disabled. The bootstrap executes bounded DNS/HTTPS/direct-IP smoke probes and emits structured markers to the EC2 system console; the controller retrieves them with `GetConsoleOutput`. This is an out-of-band evidence channel, not a worker AWS credential or management API.
- The worker's IPv4 default route targets the Network Firewall endpoint in the same AZ.
- The firewall subnet's default route targets the NAT Gateway; the NAT subnet routes the worker CIDR back through the same Network Firewall endpoint before the worker's return traffic reaches the private subnet. The NAT subnet alone routes general Internet traffic to the Internet Gateway.
- The worker security group permits TCP/443 egress for inspection and TCP/UDP 53 only to the VPC Resolver address. A dedicated subnet NACL allows DNS only to the resolver, denies all other VPC-CIDR egress before allowing inspected TCP/443, and allows only ephemeral return traffic inbound. This prevents local VPC destinations from bypassing the firewall through the VPC's more-specific local route. It does not permit UDP/443 (QUIC), TCP/853 (DoT), direct external DNS, or IPv6.
- Route 53 DNS Firewall allows the supplied domain list and then blocks the wildcard catch-all. DNS Firewall is configured fail-closed.
- Network Firewall uses strict stateful rule order, an allowlist over TLS SNI, HTTP Host, and `AWS_ROUTE_53_RESOLVED_DOMAIN`, policy-level Route 53 resolved-IP validation, and a strict drop default.
- Flow and alert logs are sent to a seven-day CloudWatch Logs group.

This is a single-AZ provider-level test topology. It does not, by itself, prove cross-AZ behavior, multi-tenant non-interference, failure injection, or production certification.

## Automatic teardown

`TeardownAtUtc` is required. Before deployment, validate it immediately before stack creation:

```bash
python scripts/validate_fcp03_teardown_at.py --teardown-at 2026-11-09T11:00:00
```

The validator requires a UTC timestamp 15 minutes to 2 hours in the future. EventBridge Scheduler then invokes CloudFormation `DeleteStack` on this stack only. The Scheduler role is scoped to this stack ARN and trusts only the exact schedule ARN and account. The schedule name is deliberately fixed, so only one lab stack may be active in the account at a time.

Automatic teardown is a guardrail, **not a hard spend cap**. A failed scheduler delivery or failed resource deletion can leave billable resources behind. Verify the stack reaches `DELETE_COMPLETE` after every run.

## Cost model

Indicative `eu-west-1` baseline, excluding variable query volume, data transfer, logs, EBS storage, and taxes:

| Component | Approximate hourly rate |
|---|---:|
| Network Firewall standard endpoint | $0.395 |
| NAT Gateway in the same-AZ Network Firewall path | $0.000 in AWS's bundled pricing example |
| Public IPv4 address for the NAT Gateway EIP | $0.005 |
| EC2 `t4g.medium` Linux On-Demand worker | $0.0368 |
| DNS Firewall Advanced association | $0.000 — this template uses foundational domain-list rules, not Advanced rules |
| **Baseline** | **$0.4368/hour** |

A two-hour run therefore has an indicative fixed baseline of about **$0.87**, before variable charges. Network Firewall data processing is approximately $0.065/GB. Standard DNS Firewall query inspection is $0.60 per million queries for the first billion, and customer-managed domain-list entries are $0.0005 per domain-month. AWS's Network Firewall pricing example waives NAT Gateway hourly and data-processing charges for traffic using the same-AZ Network Firewall + NAT path; confirm the actual billing line items after any approved run. This template does not enable TLS Advanced Inspection ($0.489 per endpoint-hour) or DNS Firewall Advanced rules ($0.16 per VPC association-hour).

Pricing sources: AWS Network Firewall [pricing](https://aws.amazon.com/network-firewall/pricing/), Route 53 [pricing](https://aws.amazon.com/route53/pricing/), VPC [pricing](https://aws.amazon.com/vpc/pricing/), and the connected account's AWS Price List API result for Linux `t4g.medium` in EU (Ireland), effective 2026-11-01.

The current estimated AWS credit balance is not a spend limit. This template does not create an AWS Budget or enforce a monetary hard stop. **Do not deploy until the owner has approved a monetary ceiling and notification recipient, the billing alert path has been verified, and the teardown procedure has been rehearsed.**

## Validation and deployment boundary

The template is JSON so it can be checked with standard tooling. CloudFormation `ValidateTemplate` succeeded in `eu-west-1`. In addition, the current regional CloudFormation resource-provider schemas for all 25 resource types and 42 resources were inspected recursively: zero unknown properties, missing required properties, or nested schema errors. These are read-only validation calls; no stack, change set, or billable resource was created.

This schema audit is stronger than JSON syntax validation, but it still does not prove runtime dependency ordering, IAM authorization at deployment, service quota availability, route convergence, endpoint readiness, or packet-level enforcement.

Run the focused regression suite with:

```bash
pytest -q \
  tests/unit/test_fcp03_aws_inventory.py \
  tests/unit/test_fcp03_egress_preflight.py \
  tests/unit/test_fcp03_cloudformation_template.py \
  tests/unit/test_fcp03_teardown_window.py
```

Example command after the cost gate is accepted:

```bash
aws cloudformation create-stack \
  --region eu-west-1 \
  --stack-name tinlance-fcp03-egress-lab \
  --template-body file://infra/aws/fcp03-egress-lab/template.json \
  --capabilities CAPABILITY_IAM \
  --parameters \
    ParameterKey=AvailabilityZone,ParameterValue=eu-west-1a \
    ParameterKey=ApprovedDomains,ParameterValue='example.com' \
    ParameterKey=TeardownAtUtc,ParameterValue='<validated-future-UTC-time>'
```

Do not run the example with its illustrative domain list or timestamp without validating the actual test plan. No create-stack, change-set execution, or infrastructure mutation is authorized by this repository change.


## Metadata-denial and worker evidence correction

The lab worker no longer receives `TinlytTestRuntimeSSMProfile` or any EC2 instance profile. `MetadataOptions.HttpEndpoint` is set to `disabled`, not merely IMDSv2-required. The worker runs a small bounded bootstrap probe and writes structured results to the EC2 system console. The operator/controller retrieves the output with read-only `ec2:GetConsoleOutput`; no credentials are injected into the worker. The probe is only a smoke test: full adversarial acceptance still requires independent packet/flow evidence and exact firewall/DNS policy inspection.
