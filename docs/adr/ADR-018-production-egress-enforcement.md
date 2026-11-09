# ADR-018 — Independent production egress and DNS enforcement

- **Status:** Proposed for FCP-03 implementation; not deployed or production-approved
- **Date:** 2026-11-09
- **Scope:** Tinlance Agent Platform production persistent-computer/browser egress
- **Supersedes:** No prior ADR; extends ADR-015

## Context

ADR-015 establishes a strong ephemeral W3/W4 browser boundary: browser namespaces have no direct route, a constrained HTTPS CONNECT proxy validates hostname allowlists and DNS answers, connects to pinned IP literals, and W4 adds a separate proxy namespace and host forwarding rules.

The production residual is explicit. The W4 network layer permits public unicast IPv4 TCP/443 to arbitrary destinations; hostname policy is enforced by the proxy application. A compromised proxy process could therefore bypass the application allowlist. DNS query names are not independently allowlisted. Application-level policy is not an independent enforcement point.

The 2026-11-09 read-only AWS inventory found:
- W5 test host security group has no ingress but permits all outbound protocols to `0.0.0.0/0`, and its subnet has a default route to an Internet Gateway.
- Tinlyt API production security group has no ingress but permits all outbound protocols to `0.0.0.0/0`.
- No S3 buckets were returned by the account-level inventory; no production snapshot store was identified.
- No AWS Budgets are configured.
- The W5 host's attached KMS key is the AWS-managed EBS default key, not a dedicated snapshot encryption or signing key.

No production resource was changed or provisioned during this audit.

## Decision

The production target is a layered, independently enforced egress path. The browser proxy remains useful for application-layer hostname authorization and TLS CONNECT handling, but it is no longer the only authority that constrains destination access.

### 1. Network path and fail-closed routing

- Place persistent-computer workers in private worker subnets with no direct Internet Gateway route.
- Route worker-subnet internet-bound traffic through dedicated AWS Network Firewall endpoints before any NAT/Internet egress.
- Use a separate firewall subnet per Availability Zone. Route firewall-approved outbound traffic through a controlled NAT gateway; do not create a bypass route from worker subnets to NAT or IGW.
- Permit only the required VPC-local, SSM, telemetry, DNS resolver and explicitly approved service paths. Use VPC endpoints for AWS control-plane services where supported; endpoint policies remain least-privilege.
- Block direct UDP/53, TCP/53 and TCP/853 from worker workloads. Permit DNS only through the configured Route 53 VPC Resolver path. Block UDP/443 (QUIC/HTTP3) for the browser workload unless a separately inspected and tested policy is approved.
- Route-table and firewall-policy changes must be staged and verified before worker placement. A missing, unhealthy or ambiguous firewall route must fail closed, not fall back to direct egress.
- Verify the complete bidirectional service chain, not only the worker's default route: worker subnet → same-AZ Network Firewall endpoint → NAT Gateway → internet, with return traffic from the NAT subnet routed back through that same firewall endpoint before reaching the worker subnet. Firewall and NAT route tables must be dedicated to their respective subnets; the NAT Gateway and firewall endpoint must be in the worker's AZ. Any missing, shared, inactive, ambiguous or unexpected route is a deployment failure.

AWS Network Firewall creates endpoints in dedicated firewall subnets and traffic is steered through them with VPC route tables. Firewall subnets must not also host workloads. See the AWS Network Firewall developer guide.

### 2. Destination-bound HTTPS policy

Use AWS Network Firewall stateful domain-list inspection as an independent network control:
- Use an allowlist rule group with HTTPS `TLS_SNI` inspection and the `AWS_ROUTE_53_RESOLVED_DOMAIN` target type together. For an allowlist containing both target types, AWS Network Firewall requires the SNI and the Route 53-resolved destination identity to match; include the protocol target type so unmatched traffic receives the generated default drop.
- **Required policy-level prerequisite:** configure `Route53ResolvedIPValidation` on the Network Firewall policy and reference the exact Route 53 Resolver DNS Firewall rule-group ID through `DNSFirewallRuleGroupId`. A stateful rule group using `AWS_ROUTE_53_RESOLVED_DOMAIN` is inactive without this policy-level setting; AWS reports `ROUTE53_RESOLVED_IP_VALIDATION_MISSING`. Treat any policy `Errors` entry or firewall attachment `ERROR` as a deployment failure, even if create/update APIs returned success.
- The referenced DNS Firewall rule group must be associated only with the worker VPC(s) in that single policy-isolation domain, and worker DNS must use those VPCs' Route 53 Resolver. Block direct external DNS, DoT and unapproved DoH so clients cannot create an alternate resolution path. A rule group with no DNS filtering rules can provide the resolution-validation association without DNS Firewall query-inspection charges, but it does not provide the separate DNS query allowlist; use a populated walled-garden group where query filtering is required.
- Resolved-IP records are Availability-Zone scoped. Deploy a firewall endpoint in every worker AZ and preserve same-AZ routing from each worker subnet to its corresponding endpoint. Cross-AZ routing to a different endpoint can be evaluated as unresolved and dropped; test AZ affinity and endpoint failover explicitly. Some AZs may not support the feature: observe `DnsAzUnavailableFlows` and require zero unsupported-AZ flows for the enforced worker scope. Resolved-domain stateful rules can drop their matching traffic in an unsupported AZ even when policy-level action is `ALERT`.
- Scope each DNS Firewall rule group referenced by `Route53ResolvedIPValidation` to one firewall deployment/policy-isolation domain. Every VPC associated with that group contributes DNS resolutions to one shared pool; an address resolved by any associated VPC is considered resolved for all of them. Never reuse the same rule group across unrelated tenant or firewall deployments. This shared resolution-pool behavior is a separate isolation risk from VPC-scoped DNS filtering and must be covered by cross-tenant non-interference tests.
- Configure policy-level validation in `ALERT` mode for an observation window of approximately 24 hours so client DNS caches can refresh. Enabling/disabling validation or changing the DNS Firewall rule-group ID may restart the stateful engine; schedule the change with connection-drain/stream-exception behavior explicitly tested. Verify resolver coverage, `route53_resolved_ip` flow-log fields, `DnsUnresolvedFlows`, `DnsResolutionErrorFlows` and `DnsAzUnavailableFlows`; investigate unexplained failures before promoting to `DROP` (or explicitly approved `REJECT`). Set DNS-expiry exception handling to `DROP` or `REJECT`; never silently `CONTINUE` expired destination resolutions in the enforced profile. Keep bypass destination ranges empty unless a narrow, documented, independently approved exception is unavoidable.
- If `SourceIPRanges` is configured, enumerate the exact worker source CIDRs. Do not set it to an empty list: an empty list disables policy-level source validation, whereas omitting it applies the check to the firewall VPC and attached VPC CIDRs.
- Add explicit stateful rules that deny non-approved TCP ports, all browser UDP egress, private/special-use destinations, metadata/link-local ranges, and traffic that does not match an approved HTTPS destination.
- Keep the application CONNECT proxy's exact/wildcard allowlist, DNS answer validation and IP pinning. The network firewall is defense in depth, not a replacement for the proxy.
- Preserve TLS end-to-end. Do not install interception certificates or disable browser certificate validation as a shortcut. Treat absent/hidden SNI (including ECH cases where inspection cannot establish the approved name) as deny, not as a reason to fall back to IP-only allow.

**Tenant-policy isolation is a release blocker.** Network Firewall domain-list rule groups and DNS Firewall associations are VPC-scoped. A shared VPC-wide allowlist must not silently union tenants' permissions. The production design must prove one of:
1. dedicated egress-policy VPC/resolver association per tenant or policy-isolation domain; or
2. a separately verified source-identity-aware policy architecture that demonstrably binds each worker's source identity to its own approved SNI and resolved-domain policy.

Do not claim per-tenant egress enforcement until cross-tenant allowlist non-interference is tested against the actual deployed AWS topology. If the selected architecture cannot prove that property, use isolated VPC policy domains even if the cost is higher; obtain a budget and capacity decision first.

### 3. DNS query policy

Associate Route 53 Resolver DNS Firewall rule groups with each worker policy VPC:
- Use an explicit allowlist for the approved domain set, followed by a terminal block rule for unmatched queries.
- Inspect the full CNAME/DNAME redirection chain; do not trust only the first queried name.
- Keep the VPC DNS Firewall failure mode closed.
- Enable DNS Firewall Advanced protections for DNS tunnelling and DGA detection where supported and validated.
- Enable Resolver query logging and alert on denied queries, anomalous volume, tunnelling detections, resolver bypass attempts and policy changes.
- Ensure workloads cannot reach arbitrary external resolvers, TCP/UDP 53, DoT/853 or unapproved DoH endpoints. Route 53 DNS Firewall only filters DNS queries that pass through the VPC Resolver; it is not an HTTPS/SSH egress firewall.

DNS policy must be derived from Platform-issued, tenant-scoped policy. Agents and browser tasks cannot mutate DNS Firewall rules, resolver configuration, security groups or route tables.

### 4. Policy distribution and lifecycle

- Platform remains the sole execution and policy authority.
- A narrowly privileged policy controller translates signed, versioned, tenant-scoped egress policy into infrastructure rule updates. The controller is not callable by an agent or browser process.
- Bind each policy version to tenant, workspace, run, approved domains, allowed ports, expiry, resolver-policy identity and evidence digest.
- Require explicit approval for policy expansion; policy contraction and revocation must be propagated before a new execution is admitted.
- Cache only immutable policy revisions with bounded TTL. Unknown, expired, stale or unverifiable revisions deny execution.
- Record policy version, rule-group version, firewall endpoint/route identity and decision evidence without logging URLs, query strings, cookies, authorization headers or secrets.
- Define a safe rollout protocol: publish version, validate generated rules, stage association/update, verify enforcement probes, then admit workers. On failure, retain the prior restrictive policy or deny new runs; never fall back to broad egress.

### 5. Required adversarial acceptance

The FCP-03 implementation must prove all of the following in an isolated disposable AWS test VPC before any production rollout:

1. Approved HTTPS destination succeeds only when both TLS SNI and the destination IP's Route 53 resolved-domain identity match.
2. Arbitrary public TCP/443 destination fails even when the application proxy process is bypassed or compromised.
3. Approved SNI sent to an unrelated public IP fails.
4. Unapproved SNI sent to an approved IP fails.
5. Direct IP literal, alternate DNS resolver, TCP/UDP 53, TCP/853, UDP/443/QUIC and unapproved DoH fail.
6. DNS allowlist blocks unapproved names, inspects CNAME/DNAME chains, and fails closed during DNS Firewall impairment.
7. DNS tunnelling/DGA test traffic is detected or blocked according to the configured Advanced rule policy.
8. Private, loopback, link-local, shared-address, reserved, multicast, IPv4-mapped IPv6, NAT64-embedded private IPv4 and cloud metadata destinations fail.
9. Cross-tenant policy non-interference: tenant A cannot use tenant B's allowlist, resolver policy or firewall state, including during concurrent policy updates and revocation.
10. Firewall endpoint/route failure, controller outage, stale policy, partial deployment and rollback all fail closed.
11. Logs contain sufficient policy/evidence attribution without sensitive browsing data.
12. All routes, firewall resources, resolver associations and test workloads are removed after the test; cleanup is verified.

Artifacts must include exact infrastructure template revision, region/AZ topology, route tables, firewall policy/rule-group revisions, the `Route53ResolvedIPValidation` configuration (DNS Firewall rule-group ID, action, expiry exception action, source ranges and bypass ranges), policy `Errors` and firewall attachment status, DNS Firewall rule-group and VPC association revisions, policy manifests, test vectors, observed packet/flow evidence (including resolved-IP validation fields and AZ), CloudWatch logs/metrics, teardown evidence and SHA-256 digests.

## Cost, deployment and safety gates

- **No AWS Network Firewall, NAT Gateway, Resolver endpoint, KMS key, S3 bucket or other paid production resource is provisioned by this ADR.**
- The account currently has zero AWS Budgets configured. Promotional-credit coverage and an approved monthly ceiling have not been verified. Cost Explorer estimates are not proof of credit coverage.
- Before provisioning the disposable test VPC, document the per-hour and data-processing costs, expected test duration, hard stop, teardown automation and cost alarm. Obtain verified credit/budget coverage and an explicit go/no-go.
- Do not repurpose FusionOps, ThreatFade or Tinlyt production instances. The existing Tinlyt W5 host is test-only and is not a production egress enforcement point.
- Production rollout requires separate change approval, canary scope, rollback plan, owner and on-call coverage.

## Residual risks and open decisions

- Per-tenant domain policy isolation across Network Firewall and DNS Firewall requires a proven topology; VPC-wide policy union is not acceptable.
- Network Firewall domain inspection depends on supported protocol visibility and correct routing. Encrypted ClientHello, nonstandard clients, alternate protocols and future protocol changes require explicit negative tests; do not assume SNI is always observable.
- DNS Firewall does not filter non-DNS application traffic. Network Firewall and route policy are required in addition.
- Provider-attested host SKU, firmware, microcode, SMT and CPU mitigation state remain separate production gates.
- Production cgroups, encrypted profile storage, dedicated KMS encryption/HMAC keys, S3 retention/Object Lock, workload identity, PostgreSQL least privilege, restore reconciliation, monitoring, backup and cross-AZ/region DR remain open.
- Independent security review and accountable residual-risk acceptance remain mandatory.

## References

- AWS Network Firewall stateful domain list rule groups: https://docs.aws.amazon.com/network-firewall/latest/developerguide/stateful-rule-groups-domain-names.html
- AWS Network Firewall architecture and VPC route steering: https://docs.aws.amazon.com/network-firewall/latest/developerguide/
- Route 53 Resolver DNS Firewall overview and limitations: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-overview.html
- Route 53 Resolver DNS Firewall walled-garden example: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-getting-started.html
- DNS Firewall fail-closed behavior: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-vpc-configuration.html
- DNS Firewall advanced protections and rule settings: https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-rule-settings.html
- ADR-015 browser workspace and egress: ./ADR-015-browser-workspace-and-egress.md
- ADR-017 durable workspace snapshots: ./ADR-017-durable-workspace-snapshots.md
