#!/usr/bin/env bash
# tests/netns/subnet.sh — MVP2 subnet-gateway proof.
#
# Node B is a subnet gateway advertising 192.168.50.0/24 (a LAN behind it). Node
# A — which has no link to that LAN — reaches a host on it (192.168.50.2) by
# tunnelling through B over the overlay. Proves: route_to() sends subnet traffic
# to the advertising gateway peer, and the gateway forwards it on.
#
# Topology:
#   relay 10.0.1.1 <-> 10.0.1.2 ns-a (100.88.0.2)
#   relay 10.0.2.1 <-> 10.0.2.2 ns-b (100.88.0.3, gateway) <-> 192.168.50.1
#                                                 192.168.50.2 ns-sub
# Run: sudo tests/netns/subnet.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE="${NODE_BIN:-$ROOT/target/debug/akurai-node}"
RELAY="${RELAY_BIN:-$ROOT/target/debug/akurai-relay}"
W="$(mktemp -d)"; A="$W/a"; B="$W/b"; PORT=51820; RC=0
cleanup(){ kill ${AP:-} ${BP:-} ${RP:-} 2>/dev/null
  for n in sg-relay sg-a sg-b sg-sub; do ip netns del $n 2>/dev/null; done
  rm -rf "$W"; }
trap cleanup EXIT
[ -x "$NODE" ] && [ -x "$RELAY" ] || { echo "build akurai-node + akurai-relay first"; exit 1; }

"$NODE" install --home "$A" >/dev/null; "$NODE" install --home "$B" >/dev/null
APUB="$(cat "$A/config/identity.pub")"; BPUB="$(cat "$B/config/identity.pub")"
# A routes 192.168.50.0/24 via gateway peer B (4th field).
echo "100.88.0.3 $BPUB b 192.168.50.0/24" > "$A/config/peers"
echo "100.88.0.2 $APUB a" > "$B/config/peers"

ip netns add sg-relay; ip netns add sg-a; ip netns add sg-b; ip netns add sg-sub
ip link add vrA type veth peer name vaR; ip link add vrB type veth peer name vbR
ip link add vbS type veth peer name vsB
ip link set vrA netns sg-relay; ip link set vaR netns sg-a
ip link set vrB netns sg-relay; ip link set vbR netns sg-b
ip link set vbS netns sg-b; ip link set vsB netns sg-sub
ip -n sg-relay addr add 10.0.1.1/24 dev vrA; ip -n sg-relay addr add 10.0.2.1/24 dev vrB
ip -n sg-relay link set vrA up; ip -n sg-relay link set vrB up; ip -n sg-relay link set lo up
ip -n sg-a addr add 10.0.1.2/24 dev vaR; ip -n sg-a link set vaR up; ip -n sg-a link set lo up
ip -n sg-b addr add 10.0.2.2/24 dev vbR; ip -n sg-b link set vbR up; ip -n sg-b link set lo up
# B's link to the subnet LAN, and the subnet host.
ip -n sg-b addr add 192.168.50.1/24 dev vbS; ip -n sg-b link set vbS up
ip -n sg-sub addr add 192.168.50.2/24 dev vsB; ip -n sg-sub link set vsB up; ip -n sg-sub link set lo up
# Subnet host routes the overlay back via the gateway (no NAT needed).
ip -n sg-sub route add 100.88.0.0/16 via 192.168.50.1

ip netns exec sg-relay env RELAY_PORT=$PORT "$RELAY" serve >/dev/null 2>&1 & RP=$!
sleep 0.4
ip netns exec sg-a "$NODE" tunnel --home "$A" --overlay-ip 100.88.0.2 \
  --relay 10.0.1.1:$PORT --peers "$A/config/peers" >/dev/null 2>&1 & AP=$!
ip netns exec sg-b "$NODE" tunnel --home "$B" --overlay-ip 100.88.0.3 \
  --relay 10.0.2.1:$PORT --peers "$B/config/peers" --advertise 192.168.50.0/24 >/dev/null 2>&1 & BP=$!
sleep 2

echo "=== ns-a routes (should include 192.168.50.0/24 dev akurai0) ==="
ip -n sg-a route | grep -E "akurai0|192.168.50"
echo "=== PING the subnet host 192.168.50.2 from node A (through gateway B) ==="
if ip netns exec sg-a ping -c 4 -W 2 192.168.50.2; then
  echo "SUBNET_GATEWAY: PASS"
else
  echo "SUBNET_GATEWAY: FAIL"; RC=1
fi
exit $RC
