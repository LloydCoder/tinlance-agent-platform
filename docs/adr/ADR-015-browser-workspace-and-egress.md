# ADR-015 — Persistent browser workspace and enforced egress

**Status:** Accepted for W3 ephemeral CI feasibility; production deployment and hostile multi-tenant certification remain open

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

- W3 CI demonstrates an ephemeral browser feasibility boundary with separate browser, proxy and second-tenant OS identities. It is not a production multi-tenant hostile-browser certification.
- The W3 harness currently runs the unprivileged egress proxy in the host network namespace. Browser workloads cannot route to host services, but a compromised proxy process could attempt host-local connections. W4 must move the proxy into a dedicated egress-only network namespace and enforce public TCP/443 plus explicitly approved DNS forwarding before production sign-off.
- Production requires a trusted supervisor that provisions distinct tenant UIDs, per-tenant profile mounts, isolated network namespaces, nftables policy, durable encrypted profile storage, lifecycle recovery and operational audit.
- Browser process cgroups, hostile multi-tenant adversarial isolation, eight-hour persistence, snapshot/restore and independent security review remain later acceptance work (W4–W6 and final assurance).
- The proxy's domain allowlist must be issued by Platform policy. A browser task cannot expand its own allowlist or mutate network policy.

## W4 adversarial egress boundary

W4 replaces the W3 host-network proxy placement with two independent links and a dedicated proxy network namespace:

- The browser namespace connects directly to the proxy namespace over a private veth pair. Neither endpoint is present in the host network namespace.
- The proxy namespace has a second veth pair to the host, an explicit default route through that uplink, IPv6 disabled, and IP forwarding disabled.
- The proxy namespace nftables input chain is default-deny and accepts only browser-side TCP/3128 plus established replies. Its output chain is default-deny and permits only public unicast TCP/443 plus UDP/TCP DNS to the explicitly configured resolver.
- Private, loopback, link-local, shared-address, reserved, multicast and metadata ranges are denied at the proxy namespace egress boundary, independently of the proxy application's DNS/IP validation.
- Host nftables drops packets from the proxy uplink addressed to host-local services. Host forwarding is default-deny and accepts only proxy-uplink public TCP/443, approved DNS, and established replies; NAT applies only to the proxy uplink subnet.
- Browser and proxy processes run under distinct non-root identities. The W4 harness gives both workloads private PID, IPC and mount namespaces; the browser mount namespace uses private propagation.
- The harness verifies the browser has no default route, the proxy has only the two expected connected routes and the approved host gateway, host-local listener access fails, private/metadata and non-HTTPS egress fail, direct browser public egress fails, and cross-tenant profile-root reuse is denied.

The W4 acceptance workflow is an ephemeral CI adversarial test, not a production certification. It includes a hostile rootfs archive corpus and concurrent tenant A/tenant B probes for filesystem, PID, IPC, mount and network isolation, plus mount/privilege/ptrace escape attempts. The workflow must retain raw JSON evidence and an SBOM, prove cleanup, and explicitly report `production_certification=false`. W4 remains unaccepted until every exact-head test passes and the artifact is independently inspected. Production still requires a trusted supervisor, durable encrypted profile storage, process cgroups, operational audit, provider-attested host security controls and independent review.

## References
- Linux network namespaces and veth pairs: https://man7.org/linux/man-pages/man7/network_namespaces.7.html
- util-linux `unshare` PID, IPC and mount namespace behavior: https://man7.org/linux/man-pages/man1/unshare.1.html
- Chromium Linux sandbox layers (namespaces and seccomp-BPF): https://chromium.googlesource.com/chromium/src/+/master/docs/linux/sandboxing.md
- Netfilter nftables rules and verdict semantics: https://netfilter.org/projects/nftables/manpage.html
- Docker's nftables guidance for interface-scoped forwarding restrictions: https://docs.docker.com/engine/network/firewall-nftables/

- Chromium proxy behavior and implicit bypass rules: https://chromium.googlesource.com/chromium/src/+/HEAD/net/docs/proxy.md
- OWASP SSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- RFC 6052 — IPv6 Addressing of IPv4/IPv6 Translators (defines the `64:ff9b::/96` well-known NAT64 prefix and IPv4-embedded address format): https://datatracker.ietf.org/doc/html/rfc6052
- Docker network isolation concepts (internal networks have no default gateway): https://docs.docker.com/compose/how-tos/networking/
- Playwright Docker guidance (official test image is not recommended for untrusted websites): https://playwright.dev/docs/docker
