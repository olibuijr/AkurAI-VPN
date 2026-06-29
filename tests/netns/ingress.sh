#!/usr/bin/env bash
# tests/netns/ingress.sh — MVP4 public ingress proof.
#
# Node B runs an internal service on its overlay IP (100.88.0.3:8000). Node A is
# on the overlay and runs akurai-ingress mapping a PUBLIC port (8080) to B's
# overlay service. A client hitting A's public port transparently reaches B's
# service over the encrypted mesh. (Tailscale Funnel/Serve equivalent.)
#
# Underlay: relay 10.0.1.1 <-> A 10.0.1.2 (100.88.0.2); relay 10.0.2.1 <-> B 10.0.2.2 (100.88.0.3)
# Run: sudo tests/netns/ingress.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE="${NODE_BIN:-$ROOT/target/debug/akurai-node}"
RELAY="${RELAY_BIN:-$ROOT/target/debug/akurai-relay}"
INGRESS="${INGRESS_BIN:-$ROOT/target/debug/akurai-ingress}"
W="$(mktemp -d)"; A="$W/a"; B="$W/b"; PORT=51820; RC=0
cleanup(){ kill ${AP:-} ${BP:-} ${RP:-} ${SVC:-} ${IGP:-} 2>/dev/null
  for n in ig-relay ig-a ig-b; do ip netns del $n 2>/dev/null; done; rm -rf "$W"; }
trap cleanup EXIT
for b in "$NODE" "$RELAY" "$INGRESS"; do [ -x "$b" ] || { echo "missing $b"; exit 1; }; done
command -v python3 >/dev/null || { echo "python3 needed for the internal service"; exit 1; }

"$NODE" install --home "$A" >/dev/null; "$NODE" install --home "$B" >/dev/null
echo "100.88.0.3 $(cat "$B/config/identity.pub") nodeb" > "$A/config/peers"
echo "100.88.0.2 $(cat "$A/config/identity.pub") nodea" > "$B/config/peers"

ip netns add ig-relay; ip netns add ig-a; ip netns add ig-b
ip link add vrA type veth peer name vaR; ip link set vrA netns ig-relay; ip link set vaR netns ig-a
ip link add vrB type veth peer name vbR; ip link set vrB netns ig-relay; ip link set vbR netns ig-b
ip -n ig-relay addr add 10.0.1.1/24 dev vrA; ip -n ig-relay addr add 10.0.2.1/24 dev vrB
ip -n ig-relay link set vrA up; ip -n ig-relay link set vrB up; ip -n ig-relay link set lo up
ip -n ig-a addr add 10.0.1.2/24 dev vaR; ip -n ig-a link set vaR up; ip -n ig-a link set lo up
ip -n ig-b addr add 10.0.2.2/24 dev vbR; ip -n ig-b link set vbR up; ip -n ig-b link set lo up

ip netns exec ig-relay env RELAY_PORT=$PORT "$RELAY" serve >/dev/null 2>&1 & RP=$!
sleep 0.4
ip netns exec ig-a "$NODE" tunnel --home "$A" --overlay-ip 100.88.0.2 --relay 10.0.1.1:$PORT --peers "$A/config/peers" >/dev/null 2>&1 & AP=$!
ip netns exec ig-b "$NODE" tunnel --home "$B" --overlay-ip 100.88.0.3 --relay 10.0.2.1:$PORT --peers "$B/config/peers" >/dev/null 2>&1 & BP=$!
sleep 2

echo "=== node B serves an internal HTTP service on its overlay IP 100.88.0.3:8000 ==="
echo "AKURAI-INGRESS-OK" > "$W/index.html"
ip netns exec ig-b sh -c "cd $W && python3 -m http.server 8000 --bind 100.88.0.3 >/dev/null 2>&1" & SVC=$!
sleep 1
echo "=== node A runs ingress: public 0.0.0.0:8080 -> overlay 100.88.0.3:8000 ==="
ip netns exec ig-a "$INGRESS" serve --map 8080:100.88.0.3:8000 >/dev/null 2>&1 & IGP=$!
sleep 1
echo "=== client hits A's PUBLIC port 8080 -> reaches B's internal service over the mesh ==="
BODY="$(ip netns exec ig-a curl -s --max-time 5 http://127.0.0.1:8080/ 2>/dev/null)"
echo "response: $BODY"
if echo "$BODY" | grep -q "AKURAI-INGRESS-OK"; then
  echo "PUBLIC_INGRESS: PASS (public port reached the internal overlay service)"
else
  echo "PUBLIC_INGRESS: FAIL"; RC=1
fi
exit $RC
