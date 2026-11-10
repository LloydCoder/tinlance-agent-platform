#!/usr/bin/env bash
# FCP-03 provider-neutral Linux DNS + egress policy integration lab.
#
# Runs two disposable network namespaces joined by a private veth:
#   worker -> dedicated Unbound policy resolver + local HTTPS test endpoint
# No namespace has a default route, no forwarding is enabled, and no host
# firewall, route, Docker network, or existing service is modified.
#
# This proves local Linux kernel/DNS policy behavior only. It is NOT evidence
# of AWS Network Firewall, AWS Route 53 DNS Firewall, production deployment,
# multi-tenant isolation, or independent security assurance.

set -Eeuo pipefail

for command in ip nft sysctl unbound unbound-checkconf dig python3 sha256sum awk grep; do
  command -v "$command" >/dev/null 2>&1 || {
    printf 'missing required command: %s\n' "$command" >&2
    exit 2
  }
done

if [[ "$(id -u)" -ne 0 ]]; then
  echo "must run as root" >&2
  exit 2
fi

suffix="$$"
worker_ns="fcp03-w-${suffix}"
resolver_ns="fcp03-d-${suffix}"
worker_if="f3w${suffix}"
resolver_if="f3d${suffix}"
config_file="$(mktemp /tmp/fcp03-unbound.XXXXXX.conf)"
log_file="/tmp/fcp03-unbound-${suffix}.log"
stderr_file="$(mktemp /tmp/fcp03-unbound-stderr.XXXXXX.log)"
server_file="$(mktemp /tmp/fcp03-https.XXXXXX.py)"
resolver_pid=""
server_pid=""

baseline_host_rules="$(nft list ruleset | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter packets <n> bytes <n>/g' | sha256sum | awk '{print $1}')"
baseline_default_routes="$(ip route show default)"
baseline_docker=""
if command -v docker >/dev/null 2>&1; then
  baseline_docker="$(docker ps --no-trunc --format '{{.ID}} {{.Names}} {{.Status}}' | sort)"
fi

cleanup() {
  local status=$?
  set +e
  if [[ "$status" -ne 0 ]]; then
    echo "FCP03_LAB_FAILURE_STATUS=$status" >&2
    if [[ -f "$log_file" ]]; then
      echo "FCP03_UNBOUND_LOG_BEGIN" >&2
      tail -n 80 "$log_file" >&2
      echo "FCP03_UNBOUND_LOG_END" >&2
    fi
    if [[ -f "$stderr_file" ]]; then
      echo "FCP03_UNBOUND_STDERR_BEGIN" >&2
      tail -n 80 "$stderr_file" >&2
      echo "FCP03_UNBOUND_STDERR_END" >&2
    fi
    if ip netns list | grep -Fq "$worker_ns"; then
      echo "FCP03_WORKER_NFT_DIAGNOSTICS" >&2
      ip netns exec "$worker_ns" nft list ruleset >&2
      ip netns exec "$worker_ns" ip addr show >&2
      ip netns exec "$worker_ns" ip route show >&2
    fi
  fi
  if [[ -n "$resolver_pid" ]]; then
    kill "$resolver_pid" >/dev/null 2>&1
    wait "$resolver_pid" >/dev/null 2>&1
  fi
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1
    wait "$server_pid" >/dev/null 2>&1
  fi
  ip netns del "$worker_ns" >/dev/null 2>&1
  ip netns del "$resolver_ns" >/dev/null 2>&1
  ip link del "$worker_if" >/dev/null 2>&1
  rm -f "$config_file" "$log_file" "$stderr_file" "$server_file"
}
trap cleanup EXIT

ip netns add "$worker_ns"
ip netns add "$resolver_ns"
ip link add "$worker_if" type veth peer name "$resolver_if"
ip link set "$worker_if" netns "$worker_ns"
ip link set "$resolver_if" netns "$resolver_ns"

ip netns exec "$worker_ns" ip link set "$worker_if" name eth0
ip netns exec "$resolver_ns" ip link set "$resolver_if" name eth0
ip netns exec "$worker_ns" ip link set lo up
ip netns exec "$resolver_ns" ip link set lo up
ip netns exec "$worker_ns" ip addr add 10.203.0.2/24 dev eth0
ip netns exec "$resolver_ns" ip addr add 10.203.0.1/24 dev eth0
ip netns exec "$resolver_ns" ip addr add 10.203.0.10/32 dev eth0
ip netns exec "$worker_ns" ip link set eth0 up
ip netns exec "$resolver_ns" ip link set eth0 up
ip netns exec "$worker_ns" sysctl -q -w net.ipv4.ip_forward=0 >/dev/null
ip netns exec "$resolver_ns" sysctl -q -w net.ipv4.ip_forward=0 >/dev/null
ip netns exec "$worker_ns" ip route add default via 10.203.0.1 dev eth0 onlink
echo "FCP03_ISOLATED_DEFAULT_ROUTE=CONFIGURED"

# The worker default route terminates at the isolated resolver namespace.
# That namespace has forwarding disabled and no default route, so no packet
# can leave the two-namespace lab or reach the host/external network.
ip netns exec "$worker_ns" ip route show default | grep -Eq "^default via 10\\.203\\.0\\.1 dev eth0( |$)"
test -z "$(ip netns exec "$resolver_ns" ip route show default)"
test -z "$(ip netns exec "$worker_ns" ip -6 route show default)"
test -z "$(ip netns exec "$worker_ns" ip -6 addr show scope global)"

cat >"$config_file" <<'UNBOUND'
server:
  interface: 10.203.0.1
  port: 5353
  do-ip4: yes
  do-ip6: no
  do-udp: yes
  do-tcp: yes
  access-control: 10.203.0.2/32 allow
  username: "unbound"
  chroot: ""
  directory: "/tmp"
  logfile: "/tmp/fcp03-unbound-runtime.log"
  pidfile: "/tmp/fcp03-unbound-runtime.pid"
  verbosity: 2
  log-queries: yes
  log-replies: yes
  hide-identity: yes
  hide-version: yes
  harden-glue: yes
  harden-dnssec-stripped: yes
  local-zone: "allowed.test." redirect
  local-data: "allowed.test. 60 IN A 10.203.0.10"
  local-zone: "blocked.test." always_nxdomain
  local-zone: "rebind.test." redirect
  local-data: "rebind.test. 60 IN A 203.0.113.10"
  local-zone: "metadata.test." redirect
  local-data: "metadata.test. 60 IN A 169.254.169.254"
UNBOUND

# Use a namespace-specific runtime logfile to avoid touching host /tmp state.
sed -i "s|/tmp/fcp03-unbound-runtime.log|$log_file|; s|/tmp/fcp03-unbound-runtime.pid|/tmp/fcp03-unbound-${suffix}.pid|" "$config_file"
unbound-checkconf "$config_file"
ip netns exec "$resolver_ns" unbound -d -vv -c "$config_file" >"$stderr_file" 2>&1 &
resolver_pid="$!"

cat >"$server_file" <<'PY'
import socket
import threading

listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("10.203.0.10", 443))
listener.listen(8)

def serve():
    while True:
        conn, _ = listener.accept()
        with conn:
            conn.sendall(b"FCP03-LOCAL-HTTPS-OK")

threading.Thread(target=serve, daemon=True).start()
threading.Event().wait()
PY
ip netns exec "$resolver_ns" python3 "$server_file" >/dev/null 2>&1 &
server_pid="$!"

# Only the approved resolver and one resolved HTTPS destination are reachable.
# All other IPv4/IPv6 output is dropped and counted in the worker namespace.
ip netns exec "$worker_ns" nft -f - <<'NFT'
table inet fcp03 {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ip daddr 10.203.0.1 udp dport 5353 counter accept
    ip daddr 10.203.0.1 tcp dport 5353 counter accept
    ip daddr 10.203.0.10 tcp dport 443 counter accept
    counter drop
  }
}
NFT

# Wait for the local resolver and test endpoint without relying on outside DNS.
ready=0
for _ in $(seq 1 30); do
  if ip netns exec "$worker_ns" dig -p 5353 @10.203.0.1 allowed.test A +time=1 +tries=1 +short 2>/dev/null | grep -Fxq "10.203.0.10"; then
    ready=1
    break
  fi
  sleep 0.2
done
test "$ready" -eq 1
echo "FCP03_RESOLVER_READY=PASS"

# Positive DNS and HTTPS controls.
allowed_answer="$(ip netns exec "$worker_ns" dig @10.203.0.1 allowed.test A +time=1 +tries=1 +short)"
test "$allowed_answer" = "10.203.0.10"
echo "FCP03_ALLOWED_DNS_ANSWER=PASS"
https_marker="$(ip netns exec "$worker_ns" python3 - <<'PY'
import socket
with socket.create_connection(("10.203.0.10", 443), timeout=1) as conn:
    print(conn.recv(128).decode("ascii"))
PY
)"
test "$https_marker" = "FCP03-LOCAL-HTTPS-OK"
echo "FCP03_APPROVED_HTTPS_PROBE=PASS"

# DNS query policy is evaluated separately from packet-path policy.
blocked_dns="$(ip netns exec "$worker_ns" dig -p 5353 @10.203.0.1 blocked.test A +time=1 +tries=1 +noall +comments)"
grep -q "status: NXDOMAIN" <<<"$blocked_dns"
echo "FCP03_BLOCKED_DNS_NXDOMAIN=PASS"
rebind_answer="$(ip netns exec "$worker_ns" dig -p 5353 @10.203.0.1 rebind.test A +time=1 +tries=1 +short)"
test "$rebind_answer" = "203.0.113.10"
metadata_answer="$(ip netns exec "$worker_ns" dig -p 5353 @10.203.0.1 metadata.test A +time=1 +tries=1 +short)"
test "$metadata_answer" = "169.254.169.254"

# Packet-path negatives: a failed request is not enough by itself; the nftables
# drop counter must also increase. Each attempt is isolated and bounded.
ip netns exec "$worker_ns" python3 - <<'PY'
import socket

def blocked_tcp(address: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.35)
    try:
        sock.connect((address, port))
    except OSError:
        return
    finally:
        sock.close()
    raise SystemExit(f"unexpected TCP reachability: {address}:{port}")

def blocked_udp(address: str, port: int) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.35)
    try:
        sock.sendto(b"fcp03-policy-probe", (address, port))
        sock.recvfrom(128)
    except OSError:
        return
    finally:
        sock.close()
    raise SystemExit(f"unexpected UDP reachability: {address}:{port}")

blocked_tcp("203.0.113.10", 443)       # DNS rebinding destination
blocked_tcp("169.254.169.254", 80)     # metadata endpoint
blocked_tcp("1.1.1.1", 443)            # direct-IP HTTPS / DoH endpoint
blocked_tcp("1.1.1.1", 853)            # DNS-over-TLS
blocked_tcp("10.203.0.1", 443)         # resolver is DNS-only, not a proxy
blocked_udp("8.8.8.8", 53)             # alternate external DNS
blocked_udp("1.1.1.1", 443)            # QUIC / HTTP3
PY

# Direct DNS-over-TCP bypass must also fail; approved TCP/53 is resolver-only.
if ip netns exec "$worker_ns" dig @8.8.8.8 allowed.test A +tcp +time=1 +tries=1 >/dev/null 2>&1; then
  echo "unexpected direct DNS-over-TCP success" >&2
  exit 1
fi

# Verify the worker drop counter observed the denied destinations.
rules="$(ip netns exec "$worker_ns" nft list chain inet fcp03 output)"
printf '%s\n' "$rules"
drop_packets="$(grep -E 'counter packets [0-9]+ bytes [0-9]+ drop' <<<"$rules" | sed -E 's/.*counter packets ([0-9]+) bytes.*/\1/' | tail -n 1)"
if [[ -z "$drop_packets" || "$drop_packets" -lt 7 ]]; then
  echo "insufficient packet-drop counter evidence: ${drop_packets:-missing}" >&2
  exit 1
fi

# Confirm resolver query logs include the policy queries.
grep -q "allowed.test" "$log_file"
grep -q "blocked.test" "$log_file"
grep -q "rebind.test" "$log_file"
grep -q "metadata.test" "$log_file"

cleanup
trap - EXIT

after_host_rules="$(nft list ruleset | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter packets <n> bytes <n>/g' | sha256sum | awk '{print $1}')"
after_default_routes="$(ip route show default)"
if [[ "$baseline_host_rules" != "$after_host_rules" ]]; then
  echo "host nftables ruleset changed unexpectedly" >&2
  exit 1
fi
if [[ "$baseline_default_routes" != "$after_default_routes" ]]; then
  echo "host default routes changed unexpectedly" >&2
  exit 1
fi
if [[ -n "$baseline_docker" ]] && command -v docker >/dev/null 2>&1; then
  after_docker="$(docker ps --no-trunc --format '{{.ID}} {{.Names}} {{.Status}}' | sort)"
  if [[ "$baseline_docker" != "$after_docker" ]]; then
    echo "existing Docker container state changed unexpectedly" >&2
    exit 1
  fi
fi
if ip netns list | grep -Fq "$worker_ns" || ip netns list | grep -Fq "$resolver_ns"; then
  echo "temporary network namespace was not removed" >&2
  exit 1
fi
if ip link show "$worker_if" >/dev/null 2>&1 || ip link show "$resolver_if" >/dev/null 2>&1; then
  echo "temporary veth was not removed" >&2
  exit 1
fi

printf 'FCP03_LOCAL_DNS_ALLOW=PASS\n'
printf 'FCP03_LOCAL_DNS_BLOCK_NXDOMAIN=PASS\n'
printf 'FCP03_DNS_REBINDING_RESOLUTION=OBSERVED\n'
printf 'FCP03_DNS_QUERY_LOG_CORRELATION=PASS\n'
printf 'FCP03_APPROVED_HTTPS_DESTINATION=PASS\n'
printf 'FCP03_DIRECT_DNS_UDP_TCP_BYPASS=BLOCKED\n'
printf 'FCP03_DOH_DIRECT_IP_BYPASS=BLOCKED_BY_EGRESS_POLICY\n'
printf 'FCP03_DOT_853=BLOCKED\n'
printf 'FCP03_QUIC_UDP443=BLOCKED\n'
printf 'FCP03_METADATA_DESTINATION=BLOCKED\n'
printf 'FCP03_DNS_REBINDING_DESTINATION=BLOCKED\n'
printf 'FCP03_IPV6_DEFAULT_ROUTE=ABSENT\n'
printf 'FCP03_NFT_DROP_COUNTER_PACKETS=%s\n' "$drop_packets"
printf 'FCP03_HOST_FIREWALL_AND_ROUTES_UNCHANGED=PASS\n'
printf 'FCP03_EXISTING_DOCKER_STATE_UNCHANGED=PASS\n'
printf 'FCP03_TEMPORARY_RESOURCES_CLEANED=PASS\n'
printf 'FCP03_LINUX_DNS_EGRESS_INTEGRATION=PASS\n'
printf 'AWS_NETWORK_FIREWALL_ACCEPTANCE=NOT_TESTED\n'
printf 'PRODUCTION_ACCEPTANCE=NOT_TESTED\n'
