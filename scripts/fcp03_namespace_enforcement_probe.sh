#!/usr/bin/env bash
# FCP-03 local kernel egress-policy probe.
#
# Creates one disposable network namespace and a veth pair. The host-side veth
# forwarding flag is disabled, so this lab cannot forward traffic to the host's
# external network. The host firewall ruleset, routes, Docker network, and
# existing containers are not edited. All created objects are removed on exit.
#
# This validates Linux namespace/nftables policy mechanics only. It is NOT proof
# of AWS Network Firewall, Route 53 Resolver DNS Firewall, or cloud-path policy.

set -Eeuo pipefail

for command in ip nft sysctl python3 sha256sum awk grep sed docker; do
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
namespace="fcp03-${suffix}"
host_if="f3h${suffix}"
peer_if="f3n${suffix}"
server_file="$(mktemp /tmp/fcp03-probe-server.XXXXXX.py)"
server_pid=""

baseline_host_rules="$(nft list ruleset | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter packets <n> bytes <n>/g' | sha256sum | awk '{print $1}')"
baseline_docker="$(docker ps --no-trunc --format '{{.ID}} {{.Names}} {{.Status}}' | sort)"

cleanup() {
  set +e
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" >/dev/null 2>&1
    wait "$server_pid" >/dev/null 2>&1
  fi
  ip netns del "$namespace" >/dev/null 2>&1
  ip link del "$host_if" >/dev/null 2>&1
  rm -f "$server_file"
}
trap cleanup EXIT

cat >"$server_file" <<'PY'
import socketserver
import threading

class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"FCP03-LAB-OK")

class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request[1].sendto(b"FCP03-LAB-OK", self.client_address)

class ReusableTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

class ReusableUDPServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True

servers = [
    ReusableTCPServer(("198.18.0.1", 53), TCPHandler),
    ReusableUDPServer(("198.18.0.1", 53), UDPHandler),
    ReusableTCPServer(("198.18.0.1", 443), TCPHandler),
]
for server in servers:
    threading.Thread(target=server.serve_forever, daemon=True).start()
threading.Event().wait()
PY

ip netns add "$namespace"
ip link add "$host_if" type veth peer name "$peer_if"
ip link set "$peer_if" netns "$namespace"
ip addr add 198.18.0.1/30 dev "$host_if"
ip link set "$host_if" up
sysctl -q -w "net.ipv4.conf.${host_if}.forwarding=0" >/dev/null
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" ip addr add 198.18.0.2/30 dev "$peer_if"
ip netns exec "$namespace" ip link set "$peer_if" up
ip netns exec "$namespace" ip route add default via 198.18.0.1
ip netns exec "$namespace" sysctl -q -w net.ipv4.ip_forward=0 >/dev/null

ip netns exec "$namespace" nft -f - <<'NFT'
table inet fcp03 {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ip daddr 198.18.0.1 udp dport 53 counter accept
    ip daddr 198.18.0.1 tcp dport 53 counter accept
    ip daddr 198.18.0.1 tcp dport 443 counter accept
    counter drop
  }
}
NFT

python3 "$server_file" &
server_pid="$!"
sleep 1
kill -0 "$server_pid"

ip netns exec "$namespace" python3 - <<'PY'
import socket

def tcp_probe(address: str, port: int, expected: bool) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.7)
    try:
        sock.connect((address, port))
        payload = sock.recv(64)
        if not expected or b"FCP03-LAB-OK" not in payload:
            raise SystemExit(f"unexpected TCP result for {address}:{port}")
    except OSError:
        if expected:
            raise SystemExit(f"approved TCP destination failed: {address}:{port}")
    finally:
        sock.close()

def udp_probe(address: str, expected: bool) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.7)
    try:
        sock.sendto(b"fcp03-probe", (address, 53))
        payload, _ = sock.recvfrom(64)
        if not expected or b"FCP03-LAB-OK" not in payload:
            raise SystemExit(f"unexpected UDP DNS result for {address}:53")
    except OSError:
        if expected:
            raise SystemExit(f"approved UDP DNS destination failed: {address}:53")
    finally:
        sock.close()

tcp_probe("198.18.0.1", 53, True)
udp_probe("198.18.0.1", True)
tcp_probe("198.18.0.1", 443, True)
tcp_probe("8.8.8.8", 53, False)
tcp_probe("1.1.1.1", 443, False)
udp_probe("8.8.8.8", False)
print("APPROVED_TCP_DNS=PASS")
print("APPROVED_UDP_DNS=PASS")
print("APPROVED_HTTPS_ENDPOINT=PASS")
print("UNAPPROVED_DNS_BYPASS=BLOCKED")
print("DIRECT_IP_HTTPS_BYPASS=BLOCKED")
print("UNAPPROVED_UDP_DNS_BYPASS=BLOCKED")
PY

rules="$(ip netns exec "$namespace" nft list chain inet fcp03 output)"
printf '%s\n' "$rules"
if ! grep -Eq 'counter packets [1-9][0-9]* bytes [0-9]+ drop' <<<"$rules"; then
  echo "no denied-packet counter evidence was recorded" >&2
  exit 1
fi

cleanup
trap - EXIT

after_host_rules="$(nft list ruleset | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter packets <n> bytes <n>/g' | sha256sum | awk '{print $1}')"
after_docker="$(docker ps --no-trunc --format '{{.ID}} {{.Names}} {{.Status}}' | sort)"
if [[ "$baseline_host_rules" != "$after_host_rules" ]]; then
  echo "host nftables ruleset changed unexpectedly" >&2
  exit 1
fi
if [[ "$baseline_docker" != "$after_docker" ]]; then
  echo "existing Docker container state changed unexpectedly" >&2
  exit 1
fi
if ip netns list | grep -Fq "$namespace"; then
  echo "temporary network namespace was not removed" >&2
  exit 1
fi
if ip link show "$host_if" >/dev/null 2>&1; then
  echo "temporary host veth was not removed" >&2
  exit 1
fi

printf 'HOST_NFTABLES_UNCHANGED=PASS sha256=%s\n' "$after_host_rules"
printf 'EXISTING_DOCKER_CONTAINERS_UNCHANGED=PASS\n'
printf 'TEMP_NAMESPACE_AND_VETH_CLEANUP=PASS\n'
printf 'FCP03_LOCAL_KERNEL_POLICY_PROBE=PASS\n'
printf 'CLOUD_FIREWALL_ACCEPTANCE=NOT_TESTED\n'
