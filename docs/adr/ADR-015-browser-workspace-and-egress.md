# ADR-015 — Persistent browser workspace and enforced egress

**Status:** Accepted for W3 and W4 ephemeral CI feasibility; production deployment, destination-level egress enforcement and hostile multi-tenant certification remain open

**Date:** 2026-11-07

## Context

W3 adds browser execution to the persistent-computer workspace. A browser is an untrusted-content execution surface: page JavaScript, downloads, redirects, DNS behavior, WebRTC/QUIC and browser background services must not inherit host or tenant network authority.

A Chromium proxy flag alone is not a network boundary. Chromium has implicit proxy bypass rules for localhost and link-local addresses; these must be explicitly subtracted with `--proxy-bypass-list=<-loopback>`. A browser process must also have no direct route to external destinations, so proxy failure cannot become a direct-network fallback.

Domain allowlisting alone is insufficient for SSRF. DNS answers must be validated and the connection must use the exact validated IP address. A second DNS lookup between validation and connection creates a DNS-rebinding/TOCTOU bypass. Every new CONNECT (including a redirect destination) must repeat policy evaluation.

## Decision

### Browser process and profile

- Run Chromium as a dedicated non-root tenant OS identity. The trusted supervisor binds the manager to an explicit expected UID; UID mismatch fails before browser startup.
- Keep Chromium's sandbox enabled. Do not use `--no-sandbox`, `--ignore-certificate-errors`, `--disable-web-security`, or a direct-proxy fallback.
- Use Playwright's persistent browser context with a profile root dedicated to one tenant and a workspace-specific profile directory.
- Profile roots and workspace profiles are owned by the tenant UID and mode `0700`; marker files bind a profile root to one tenant; an exclusive `flock` lease prevents concurrent reuse.
- Disable downloads, service workers, extensions, sync, component updates, background networking and QUIC for this baseline. Browser navigation accepts credential-free HTTPS URLs only.
- Construct child environments from an explicit allowlist. Do not pass GitHub Actions, AWS, application secrets, ambient HTTP proxy variables or unrelated host environment. Only the browser child receives the Playwright browser-cache path; the proxy child does not.

### Network boundary

- Each browser workspace runs in a dedicated Linux network namespace.
- The namespace has loopback plus one veth to a host-side proxy endpoint, exactly one connected route to that proxy, no IPv4 or IPv6 default route, and no direct DNS route.
- Host nftables permits the workspace veth to reach only the proxy's TCP port and drops all other traffic arriving from that veth.
- The proxy binds to a specific private/loopback address, not a wildcard or public interface, and validates the client source network.
- The browser uses an explicit HTTP proxy endpoint expressed as a private IP literal. The Chromium implicit loopback/link-local bypass list is removed with `<-loopback>`. Destination hostnames are sent in HTTPS CONNECT requests to the proxy for resolution and IP pinning; the browser namespace has no default route or direct DNS route. QUIC and background networking are disabled.
- If the proxy is unreachable, browser navigation fails. There is no `direct://` proxy fallback and the namespace has no route for direct egress.

### Egress policy and SSRF defense

- HTTPS CONNECT only; TCP port 443 only. Plain HTTP and arbitrary ports are denied.
- Destination hostnames are IDNA-normalized and must match a per-workspace exact allowlist. Wildcard subdomains require an explicit `*.` rule.
- IP-literal destinations, localhost, link-local/special-use names and cloud metadata names are denied. The IPv4-mapped and deprecated IPv4-compatible IPv6 forms are rejected. For the RFC 6052 well-known NAT64 prefix (`64:ff9b::/96`), the embedded IPv4 address is independently validated; non-global embedded addresses are denied while public mappings remain usable.
- Resolve A and AAAA records with a bounded DNS lifetime. If any answer is non-global, private, loopback, link-local, multicast, reserved, unspecified or IPv4-mapped, reject the entire destination.
- Connect to a validated IP literal from the same DNS answer set; never resolve the hostname again for the socket connection.
- Every CONNECT is evaluated independently. Redirects therefore receive the same allowlist, DNS and IP-range checks as the initial request.
- TLS remains end-to-end between Chromium and the destination. The proxy does not intercept TLS or disable certificate verification.
- Bound concurrent connections, DNS/connect time, tunnel idle time, tunnel lifetime and bytes transferred per tunnel. Do not log URLs, headers, credentials or query strings.

## Threats addressed

- SSRF to RFC1918, loopback, link-local and cloud metadata addresses.
- DNS rebinding and DNS validation/connect TOCTOU.
- Redirect-based allowlist bypass.
- Browser implicit localhost/link-local proxy bypass.
- Direct egress if the proxy is unavailable.
- UDP/QUIC and direct DNS bypass from the browser namespace.
- Cross-workspace profile reuse, concurrent profile corruption and accidental tenant-root reuse.
- Browser execution as root or with Chromium sandbox disabled.

## Acceptance evidence

The W3 workflow must prove, on its exact PR head:

1. Unit tests for hostname normalization, exact/wildcard allowlists, private/special IP rejection, mixed public/private DNS answers, pinned-IP connection behavior and per-CONNECT redirect revalidation.
2. A real Chromium process running as a non-root tenant UID with the Chromium sandbox enabled.
3. A dedicated namespace with exactly one proxy veth, exactly one connected route to the proxy, no IPv4/IPv6 default route, and host firewall rules allowing only the proxy port.
4. Direct browser-namespace connection to a public IP fails.
5. The proxy denies a metadata IP and an unallowlisted hostname.
6. An allowlisted HTTPS page loads through the proxy.
7. Browser cookie/profile state persists across workspace restart but does not cross workspace boundaries; a tenant cannot reuse another tenant's profile root.
8. Browser navigation fails when the configured proxy endpoint is unavailable.
9. Namespace, veth, firewall table and proxy process cleanup is verified.
10. The artifact explicitly records `production_certification=false`.

## Limitations and follow-on phases

- W3 established the browser/proxy feasibility boundary; W4 now adds a dedicated proxy network namespace, host-local service isolation, interface-scoped forwarding and concurrent tenant adversarial probes. Both phases are accepted only at ephemeral-CI feasibility level, not as production hostile-browser certification.
- W4 still permits public unicast TCP/443 at the network layer; the proxy application allowlist is not an independent control against a compromised proxy process. Production needs a trusted egress enforcement point that binds approved names/policies to destination IPs, plus DNS query policy that prevents resolver abuse.
- Production requires a trusted supervisor that provisions distinct tenant UIDs, per-tenant profile mounts, isolated network namespaces, nftables and host-forwarding policy, durable encrypted profile storage, lifecycle recovery, process cgroups and operational audit.
- Eight-hour persistence, snapshot/restore, production economics and independent security review remain W5/W6 and final assurance work.
- The proxy's domain allowlist must be issued by Platform policy. A browser task cannot expand its own allowlist or mutate network policy.

## W4 adversarial egress boundary

W4 replaces the W3 host-network proxy placement with a dedicated proxy network namespace and a second tenant network boundary:

- The browser namespace connects directly to the proxy namespace over a private veth pair. Neither endpoint is present in the host network namespace. The browser namespace has no default route, IPv6 is disabled, and direct public egress is blocked.
- The proxy namespace has a second veth pair to the host, an explicit default route through that uplink, IPv6 disabled, and IP forwarding disabled. Its nftables input chain is default-deny and accepts only browser-side TCP/3128 plus established replies. Its output chain is default-deny and permits only public unicast TCP/443 plus UDP/TCP DNS to the dedicated host DNS relay.
- The host DNS relay binds only to the proxy-facing host veth address. Host INPUT allows only UDP/TCP 53 from the proxy uplink to that address and drops other proxy-to-host service traffic. The relay forwards to the host-configured resolver (127.0.0.53 in the inspected CI run). The proxy namespace resolver file is owned by the proxy UID/GID and mode 0600.
- Private, loopback, link-local, shared-address, reserved, multicast and metadata ranges are denied at the proxy namespace egress boundary, independently of the proxy application's DNS/IP validation.
- Host nftables scopes the forwarding/NAT path to the proxy uplink subnet. Where Docker's iptables backend enforces a host FORWARD policy of DROP, the harness inserts exact source-IP/interface/TCP-443 and established-return rules into DOCKER-USER (or the FORWARD chain when DOCKER-USER is absent), without changing the host's global forwarding policy. The exact rules are removed during cleanup. NAT applies only to the proxy uplink subnet.
- Browser, proxy and second-tenant workloads run under distinct non-root identities. The harness gives each workload private PID, IPC and mount namespaces; the browser mount namespace uses private propagation. Tenant B has no proxy route or uplink.
- The harness verifies browser direct egress denial; proxy public HTTPS connectivity; host-local service denial; private/metadata and non-HTTPS egress denial; profile and cross-tenant isolation; foreign PID/IPC invisibility; mount, privilege-escalation and ptrace denial; and full namespace/firewall cleanup.

**Residual egress risk:** the network layer permits public unicast IPv4 TCP/443 to any destination, not only the proxy's configured hostname allowlist. The proxy application enforces the domain policy, but a compromised proxy process could attempt TLS exfiltration to an arbitrary public TCP/443 endpoint. The host DNS relay is restricted to the proxy-facing veth and the configured host resolver, but DNS query names are not independently allowlisted; DNS tunnelling/abuse remains a production policy concern. Private/link-local/metadata destinations and non-HTTPS ports remain blocked. Production must add a trusted egress enforcement point that binds approved names/policies to destination IPs independently of the proxy process and apply explicit DNS query policy.

**W4 acceptance evidence (2026-11-08):** workflow run [42471763414](https://github.com/LloydCoder/tinlance-agent-platform/actions/runs/42471763414) completed successfully. The independently downloaded artifact browser-w4-42471763414 has SHA-256 5ceaf3bf575dd26387c26d0fcab3e7a70d3b462455847df47e0d9e0362696295; report SHA-256 c172d0d69c6727f8f859b25574d776c26bdcb1c468c2ae44d7cb7ccef1cf410d; SBOM SHA-256 eb8f71f38a0c072a96df5615d79237a31e7a02e79738b58dbc2b44c17581f6c6. The report records browser UID 51000, proxy UID 52000 and tenant B UID 53000; dedicated browser/proxy namespaces; direct browser egress blocked; proxy HTTPS connectivity; host-local/private/metadata/non-HTTPS egress denial; DNS relay and mode-0600 resolver ownership; Chromium 156.0.8078.4 with sandbox enabled, renderer seccomp, no_new_privs, zero effective capabilities and isolated renderer user namespaces; persistent profile across restart; workspace and tenant profile isolation; concurrent tenant A/B isolation; foreign PID/IPC invisibility; mount, privilege-escalation and ptrace denial; cleanup verified. Both report and SBOM were inspected. The report explicitly records production_certification=false.

**W4 disposition:** accepted for ephemeral CI adversarial feasibility only. This is not production certification. Production still requires a trusted supervisor, destination-level egress enforcement independent of the proxy, DNS query policy, durable encrypted profile storage, process cgroups, operational audit, provider-attested host security controls and independent review.

## References
- Linux network namespaces and veth pairs: https://man7.org/linux/man-pages/man7/network_namespaces.7.html
- util-linux `unshare` PID, IPC and mount namespace behavior: https://man7.org/linux/man-pages/man1/unshare.1.html
- Chromium Linux sandbox layers (namespaces and seccomp-BPF): https://chromium.googlesource.com/chromium/src/+/master/docs/linux/sandboxing.md
- Netfilter nftables rules and verdict semantics: https://netfilter.org/projects/nftables/manpage.html
- Docker's nftables guidance for interface-scoped forwarding restrictions: https://docs.docker.com/engine/network/firewall-nftables/
- Docker's iptables firewall guidance for the user-managed DOCKER-USER chain and host FORWARD policy: https://docs.docker.com/engine/network/firewall-iptables/
- Docker packet filtering/firewall behavior and the default DROP forwarding policy: https://docs.docker.com/engine/network/packet-filtering-firewalls/

- Chromium proxy behavior and implicit bypass rules: https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- RFC 6052 — IPv6 Addressing of IPv4/IPv6 Translators (defines the `64:ff9b::/96` well-known NAT64 prefix and IPv4-embedded address format): https://datatracker.ietf.org/doc/html/rfc6052
- Docker network isolation concepts (internal networks have no default gateway): https://docs.docker.com/compose/how-tos/networking/
- Playwright Docker guidance (official test image is not recommended for untrusted websites): https://playwright.dev/docs/docker
