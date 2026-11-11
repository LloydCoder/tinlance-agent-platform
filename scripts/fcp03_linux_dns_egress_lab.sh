#!/usr/bin/env bash
# FCP-03 provider-neutral Linux DNS + egress policy integration lab.
#
# Runs two disposable network namespaces joined by a private veth:
#   worker -> dedicated dnsmasq policy resolver + local TCP/443 test endpoint
# The resolver namespace has no default route or forwarding. The worker's default route
# terminates at that sink. No host firewall, route, Docker network, or existing service is modified.
#
# This proves local Linux kernel/DNS policy behavior only. It is NOT evidence
# of AWS Network Firewall, AWS Route 53 DNS Firewall, production deployment,
# multi-tenant isolation, or independent security assurance.

set -Eeuo pipefail

for command in ip nft sysctl dnsmasq dig python3 sha256sum awk grep openssl; do
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
log_file="/tmp/fcp03-dnsmasq-${suffix}.log"
pid_file="/tmp/fcp03-dnsmasq-${suffix}.pid"
server_file="$(mktemp /tmp/fcp03-https.XXXXXX.py)"
ca_cert="$(mktemp /tmp/fcp03-ca.XXXXXX.crt)"
ca_key="$(mktemp /tmp/fcp03-ca.XXXXXX.key)"
server_key="$(mktemp /tmp/fcp03-server.XXXXXX.key)"
server_csr="$(mktemp /tmp/fcp03-server.XXXXXX.csr)"
server_cert="$(mktemp /tmp/fcp03-server.XXXXXX.crt)"
ext_file="$(mktemp /tmp/fcp03-server.XXXXXX.ext)"
resolver_pid=""
server_pid=""

baseline_host_rules="$(nft list ruleset | sed -E 's/counter packets [0-9]+ bytes [0-9]+/counter packets <n> bytes <n>/g' | sha256sum | awk '{print $1}')"
baseline_default_routes="$(ip route show default)"
baseline_ipv6_default_routes="$(ip -6 route show default)"
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
      echo "FCP03_DNSMASQ_LOG_BEGIN" >&2
      tail -n 80 "$log_file" >&2
      echo "FCP03_DNSMASQ_LOG_END" >&2
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
  rm -f "$log_file" "$pid_file" "$server_file" "$ca_cert" "$ca_key" "$server_key" "$server_csr" "$server_cert" "$ext_file" "${ca_cert}.srl"
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
ip netns exec "$worker_ns" ip -6 addr add 2001:db8:203::2/64 dev eth0
ip netns exec "$resolver_ns" ip -6 addr add 2001:db8:203::1/64 dev eth0
ip netns exec "$worker_ns" ip link set eth0 up
ip netns exec "$resolver_ns" ip link set eth0 up
ip netns exec "$worker_ns" sysctl -q -w net.ipv4.ip_forward=0 >/dev/null
ip netns exec "$resolver_ns" sysctl -q -w net.ipv4.ip_forward=0 >/dev/null
ip netns exec "$resolver_ns" sysctl -q -w net.ipv6.conf.all.forwarding=0 >/dev/null
ip netns exec "$worker_ns" ip route add default via 10.203.0.1 dev eth0 onlink
ip netns exec "$worker_ns" ip -6 route add default via 2001:db8:203::1 dev eth0
echo "FCP03_ISOLATED_DEFAULT_ROUTE=CONFIGURED"

# The worker default route terminates at the isolated resolver namespace.
# That namespace has forwarding disabled and no default route, so no packet
# can leave the two-namespace lab or reach the host/external network.
ip netns exec "$worker_ns" ip route show default | grep -Eq "^default via 10\\.203\\.0\\.1 dev eth0( |$)"
test -z "$(ip netns exec "$resolver_ns" ip route show default)"
ip netns exec "$worker_ns" ip -6 route show default | grep -Eq "^default via 2001:db8:203::1 dev eth0( |$)"
ip netns exec "$worker_ns" ip -6 addr show dev eth0 | grep -Fq "2001:db8:203::2/64"
test -z "$(ip netns exec "$resolver_ns" ip -6 route show default)"

ip netns exec "$resolver_ns" dnsmasq \
  --keep-in-foreground \
  --pid-file="$pid_file" \
  --no-resolv \
  --no-hosts \
  --no-poll \
  --bind-interfaces \
  --listen-address=10.203.0.1 \
  --port=53 \
  --user=nobody \
  --log-queries \
  --log-facility=- \
  --address=/allowed.test/10.203.0.10 \
  --address=/blocked.test/ \
  --address=/rebind.test/203.0.113.10 \
  --address=/metadata.test/169.254.169.254 >"$log_file" 2>&1 &
resolver_pid="$!"

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 -keyout "$ca_key" -out "$ca_cert" -subj "/CN=FCP03 Disposable Test CA" -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -keyout "$server_key" -out "$server_csr" \
  -subj "/CN=allowed.test" >/dev/null 2>&1
cat >"$ext_file" <<'CERT'
subjectAltName=DNS:allowed.test
extendedKeyUsage=serverAuth
keyUsage=digitalSignature,keyEncipherment
basicConstraints=CA:FALSE
CERT
openssl x509 -req -sha256 -days 1 -in "$server_csr" -CA "$ca_cert" -CAkey "$ca_key" \
  -CAcreateserial -out "$server_cert" -extfile "$ext_file" >/dev/null 2>&1

cat >"$server_file" <<'PY'
import os
import pwd
import socket
import ssl
import threading

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_2
context.load_cert_chain(os.environ["FCP03_SERVER_CERT"], os.environ["FCP03_SERVER_KEY"])
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("10.203.0.10", 443))
listener.listen(8)

nobody = pwd.getpwnam("nobody")
os.setgroups([])
os.setgid(nobody.pw_gid)
os.setuid(nobody.pw_uid)

def serve():
    while True:
        raw, _ = listener.accept()
        with context.wrap_socket(raw, server_side=True) as conn:
            conn.recv(1024)
            body = b"FCP03-LOCAL-HTTPS-OK"
            conn.sendall(
                b"HTTP/1.1 200 OK\r\n"
                + (b"Content-Length: %d\r\n" % len(body))
                + b"Connection: close\r\n\r\n"
                + body
            )

threading.Thread(target=serve, daemon=True).start()
threading.Event().wait()
PY
FCP03_SERVER_CERT="$server_cert" FCP03_SERVER_KEY="$server_key" \
  ip netns exec "$resolver_ns" python3 "$server_file" >/dev/null 2>&1 &
server_pid="$!"

# Only the approved resolver and one resolved HTTPS destination are reachable.
# All other IPv4/IPv6 output is dropped and counted in the worker namespace.
ip netns exec "$worker_ns" nft -f - <<'NFT'
table inet fcp03 {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ip daddr 10.203.0.1 udp dport 53 counter accept
    ip daddr 10.203.0.1 tcp dport 53 counter accept
    ip daddr 10.203.0.10 tcp dport 443 counter accept
    ip6 daddr ::/0 counter drop
    counter drop
  }
}
NFT

# Wait for the local resolver and test endpoint without relying on outside DNS.
ready=0
for _ in $(seq 1 30); do
  ready_answer="$(ip netns exec "$worker_ns" dig @10.203.0.1 allowed.test A +time=1 +tries=1 +short 2>/dev/null)"
  if [[ "$ready_answer" == "10.203.0.10" ]]; then
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
allowed_tcp_answer="$(ip netns exec "$worker_ns" dig @10.203.0.1 allowed.test A +tcp +time=1 +tries=1 +short)"
test "$allowed_tcp_answer" = "10.203.0.10"
echo "FCP03_ALLOWED_DNS_UDP_TCP=PASS"
https_marker="$(FCP03_CA_CERT="$ca_cert" ip netns exec "$worker_ns" python3 - <<'PY'
import os
import socket
import ssl

context = ssl.create_default_context(cafile=os.environ["FCP03_CA_CERT"])
with socket.create_connection(("10.203.0.10", 443), timeout=1) as raw:
    with context.wrap_socket(raw, server_hostname="allowed.test") as conn:
        conn.sendall(
            b"GET / HTTP/1.1\r\nHost: allowed.test\r\nConnection: close\r\n\r\n"
        )
        chunks = []
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
        response = b"".join(chunks)
        if b"FCP03-LOCAL-HTTPS-OK" not in response:
            raise SystemExit("local HTTPS response marker missing")
        print("FCP03-HTTPS-CERTIFICATE-AND-SNI-VERIFIED")
PY
)"
test "$https_marker" = "FCP03-HTTPS-CERTIFICATE-AND-SNI-VERIFIED"
echo "FCP03_APPROVED_HTTPS_TLS_HOSTNAME_VALIDATION=PASS"

# DNS query policy is evaluated separately from packet-path policy.
blocked_dns="$(ip netns exec "$worker_ns" dig @10.203.0.1 blocked.test A +time=1 +tries=1 +noall +comments)"
grep -q "status: NXDOMAIN" <<<"$blocked_dns"
echo "FCP03_BLOCKED_DNS_NXDOMAIN=PASS"
rebind_answer="$(ip netns exec "$worker_ns" dig @10.203.0.1 rebind.test A +time=1 +tries=1 +short)"
test "$rebind_answer" = "203.0.113.10"
metadata_answer="$(ip netns exec "$worker_ns" dig @10.203.0.1 metadata.test A +time=1 +tries=1 +short)"
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

sock6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
sock6.settimeout(0.35)
try:
    sock6.connect(("2606:4700:4700::1111", 443, 0, 0))
except OSError:
    pass
else:
    raise SystemExit("unexpected IPv6 egress to a public destination")
finally:
    sock6.close()
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
after_ipv6_default_routes="$(ip -6 route show default)"
ipv6_drop_packets="$(grep -E 'ip6 daddr ::/0 counter packets [0-9]+ bytes [0-9]+ drop' <<<"$rules" | awk '{for (i = 1; i <= NF; i++) if ($i == "packets") print $(i + 1)}' | tail -n 1)"
if [[ -z "$ipv6_drop_packets" || "$ipv6_drop_packets" -lt 1 ]]; then
  echo "IPv6 egress drop counter did not record a blocked packet" >&2
  exit 1
fi
if [[ "$baseline_host_rules" != "$after_host_rules" ]]; then
  echo "host nftables ruleset changed unexpectedly" >&2
  exit 1
fi
if [[ "$baseline_default_routes" != "$after_default_routes" ]]; then
  echo "host default routes changed unexpectedly" >&2
  exit 1
fi
if [[ "$baseline_ipv6_default_routes" != "$after_ipv6_default_routes" ]]; then
  echo "host IPv6 default routes changed unexpectedly" >&2
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
printf 'FCP03_APPROVED_HTTPS_TLS_HOSTNAME_VALIDATION=PASS\n'
printf 'FCP03_DIRECT_DNS_UDP_TCP_BYPASS=BLOCKED\n'
printf 'FCP03_DOH_ENDPOINT_IP_TCP443=BLOCKED\n'
printf 'FCP03_DOT_853=BLOCKED\n'
printf 'FCP03_QUIC_UDP443=BLOCKED\n'
printf 'FCP03_METADATA_DESTINATION=BLOCKED\n'
printf 'FCP03_DNS_REBINDING_DESTINATION=BLOCKED\n'
printf 'FCP03_IPV6_EGRESS=BLOCKED_BY_NFTABLES\n'
printf 'FCP03_IPV6_NFT_DROP_PACKETS=%s\n' "$ipv6_drop_packets"
printf 'FCP03_NFT_DROP_COUNTER_PACKETS=%s\n' "$drop_packets"
printf 'FCP03_HOST_FIREWALL_AND_ROUTES_UNCHANGED=PASS\n'
printf 'FCP03_EXISTING_DOCKER_STATE_UNCHANGED=PASS\n'
printf 'FCP03_TEMPORARY_RESOURCES_CLEANED=PASS\n'
printf 'FCP03_LINUX_DNS_EGRESS_INTEGRATION=PASS\n'
printf 'AWS_NETWORK_FIREWALL_ACCEPTANCE=NOT_TESTED\n'
printf 'PRODUCTION_ACCEPTANCE=NOT_TESTED\n'
