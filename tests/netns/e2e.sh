#!/usr/bin/env bash
# tests/netns/e2e.sh — End-to-end proof of the AkurAI VPN data plane.
#
# Stands up a relay and two nodes in isolated Linux network namespaces (the host
# stack is NEVER touched — `wlan0` is structurally safe), then pings node B from
# node A over the 100.88.0.0/16 overlay. The packets travel as end-to-end
# ChaCha20-Poly1305 ciphertext, hub-routed by akurai-relay (which holds no keys).
#
# Topology (underlay):
#   ns-relay 10.0.1.1 <--veth--> 10.0.1.2 ns-a   (overlay 100.88.0.2)
#   ns-relay 10.0.2.1 <--veth--> 10.0.2.2 ns-b   (overlay 100.88.0.3)
#
# Requires root (netns + TUN). Run: sudo tests/netns/e2e.sh
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE="${NODE_BIN:-$ROOT/target/debug/akurai-node}"
RELAY="${RELAY_BIN:-$ROOT/target/debug/akurai-relay}"
WORK="$(mktemp -d)"
A_HOME="$WORK/nodeA"
B_HOME="$WORK/nodeB"
CAP="$WORK/forward.pcap"
PORT=51820
RC=0

cleanup() {
  kill "${A_PID:-}" "${B_PID:-}" "${RELAY_PID:-}" "${TCPDUMP_PID:-}" 2>/dev/null
  for ns in akv-relay akv-a akv-b; do ip netns del "$ns" 2>/dev/null; done
  rm -rf "$WORK" /etc/netns/akv-a
}
trap cleanup EXIT

say() { printf '\n=== %s ===\n' "$*"; }

[ -x "$NODE" ] || { echo "missing $NODE (cargo build -p akurai-node)"; exit 1; }
[ -x "$RELAY" ] || { echo "missing $RELAY (cargo build -p akurai-relay)"; exit 1; }

say "1. generate node identities"
"$NODE" install --home "$A_HOME" >/dev/null
"$NODE" install --home "$B_HOME" >/dev/null
A_PUB="$(cat "$A_HOME/config/identity.pub")"
B_PUB="$(cat "$B_HOME/config/identity.pub")"
echo "A pub: $A_PUB"
echo "B pub: $B_PUB"

say "2. write peer maps (each node knows the other)"
echo "100.88.0.3 $B_PUB nodeb" > "$A_HOME/config/peers"
echo "100.88.0.2 $A_PUB nodea" > "$B_HOME/config/peers"

say "3. build namespaces + underlay"
ip netns add akv-relay
ip netns add akv-a
ip netns add akv-b
ip link add vrA type veth peer name vaR
ip link add vrB type veth peer name vbR
ip link set vrA netns akv-relay
ip link set vaR netns akv-a
ip link set vrB netns akv-relay
ip link set vbR netns akv-b
ip -n akv-relay addr add 10.0.1.1/24 dev vrA
ip -n akv-relay addr add 10.0.2.1/24 dev vrB
ip -n akv-relay link set vrA up
ip -n akv-relay link set vrB up
ip -n akv-relay link set lo up
ip -n akv-a addr add 10.0.1.2/24 dev vaR
ip -n akv-a link set vaR up
ip -n akv-a link set lo up
ip -n akv-b addr add 10.0.2.2/24 dev vbR
ip -n akv-b link set vbR up
ip -n akv-b link set lo up

say "4. start relay (ciphertext-only hub)"
ip netns exec akv-relay env RELAY_PORT=$PORT "$RELAY" serve &
RELAY_PID=$!
sleep 0.4

say "5. capture forwarded underlay traffic on the relay->B link"
ip netns exec akv-relay timeout 8 tcpdump -i vrB -w "$CAP" udp >/dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 0.3

say "6. start nodes (TUN + pump)"
ip netns exec akv-a "$NODE" tunnel --home "$A_HOME" \
  --overlay-ip 100.88.0.2 --relay 10.0.1.1:$PORT --peers "$A_HOME/config/peers" &
A_PID=$!
ip netns exec akv-b "$NODE" tunnel --home "$B_HOME" \
  --overlay-ip 100.88.0.3 --relay 10.0.2.1:$PORT --peers "$B_HOME/config/peers" &
B_PID=$!
sleep 1.5

say "7. interfaces inside the namespaces"
ip -n akv-a -br addr show akurai0 || true
ip -n akv-b -br addr show akurai0 || true
echo "ns-a routes:"; ip -n akv-a route

say "8. PING node B from node A over the overlay"
if ip netns exec akv-a ping -c 4 -W 2 100.88.0.3; then
  echo "OVERLAY_PING: PASS"
else
  echo "OVERLAY_PING: FAIL"
  RC=1
fi

say "9. confirm the forwarded payload is ciphertext (no plaintext ICMP)"
sleep 0.5
kill "$TCPDUMP_PID" 2>/dev/null
if command -v tcpdump >/dev/null; then
  # The inner ICMP payload bytes 'abcdefghijklmnop' (ping default) must NOT appear
  # in cleartext on the underlay; the relay only ever sees AkurAI frames.
  if tcpdump -r "$CAP" -A 2>/dev/null | grep -qa "abcdefghijklmnop"; then
    echo "CIPHERTEXT_CHECK: FAIL (plaintext ICMP visible on underlay)"
    RC=1
  else
    echo "CIPHERTEXT_CHECK: PASS (no plaintext payload on underlay)"
  fi
fi

say "9b. MagicDNS: resolve and ping node B by name (nodeb.akurai)"
# Per-netns resolv.conf via /etc/netns/<name>/ — ip-netns bind-mounts this over
# /etc INSIDE the namespace, so the HOST's /etc/resolv.conf is never touched.
mkdir -p /etc/netns/akv-a
printf 'nameserver 100.88.0.2\n' > /etc/netns/akv-a/resolv.conf
if ip netns exec akv-a ping -c 2 -W 2 nodeb.akurai >/dev/null 2>&1; then
  echo "MAGICDNS_CHECK: PASS (nodeb.akurai resolved + reachable)"
else
  echo "MAGICDNS_CHECK: FAIL"
  RC=1
fi

say "10. fail-closed: an un-mapped destination is dropped"
if ip netns exec akv-a ping -c 1 -W 2 100.88.0.9 >/dev/null 2>&1; then
  echo "FAILCLOSED_CHECK: FAIL (reached an un-mapped peer)"
  RC=1
else
  echo "FAILCLOSED_CHECK: PASS (no route/peer -> dropped)"
fi

exit $RC
