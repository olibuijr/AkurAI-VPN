#!/usr/bin/env bash
# tests/netns/direct.sh — MVP3 direct-path proof.
#
# Relay + node A + node B all share one underlay LAN (a bridge), so A and B are
# mutually routable. Handshakes go via the relay, which hands each end the
# other's observed address (PeerAddr); the nodes probe and confirm a DIRECT UDP
# path, and traffic then leaves the hub. Proves the relay-fallback→direct upgrade.
#
# Topology (all on 10.0.0.0/24 via bridge akvdbr in ns-net):
#   relay 10.0.0.1 : node A 10.0.0.2 (100.88.0.2) : node B 10.0.0.3 (100.88.0.3)
# Run: sudo tests/netns/direct.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE="${NODE_BIN:-$ROOT/target/debug/akurai-node}"
RELAY="${RELAY_BIN:-$ROOT/target/debug/akurai-relay}"
W="$(mktemp -d)"; A="$W/a"; B="$W/b"; PORT=51820; RC=0
ALOG="$W/a.log"; BLOG="$W/b.log"
cleanup(){ kill ${AP:-} ${BP:-} ${RP:-} 2>/dev/null
  for n in dn-relay dn-a dn-b dn-net; do ip netns del $n 2>/dev/null; done
  rm -rf "$W"; }
trap cleanup EXIT
[ -x "$NODE" ] && [ -x "$RELAY" ] || { echo "build akurai-node + akurai-relay first"; exit 1; }

"$NODE" install --home "$A" >/dev/null; "$NODE" install --home "$B" >/dev/null
echo "100.88.0.3 $(cat "$B/config/identity.pub") nodeb" > "$A/config/peers"
echo "100.88.0.2 $(cat "$A/config/identity.pub") nodea" > "$B/config/peers"

# One shared LAN: a bridge in ns-net, three veths into relay/a/b.
ip netns add dn-net; ip netns add dn-relay; ip netns add dn-a; ip netns add dn-b
ip -n dn-net link add br0 type bridge; ip -n dn-net link set br0 up
for pair in "relay:dn-relay:10.0.0.1" "a:dn-a:10.0.0.2" "b:dn-b:10.0.0.3"; do
  nm="${pair%%:*}"; rest="${pair#*:}"; ns="${rest%%:*}"; ip4="${rest##*:}"
  ip -n dn-net link add "h$nm" type veth peer name "n$nm"
  ip -n dn-net link set "h$nm" master br0; ip -n dn-net link set "h$nm" up
  ip -n dn-net link set "n$nm" netns "$ns"
  ip -n "$ns" addr add "$ip4/24" dev "n$nm"; ip -n "$ns" link set "n$nm" up; ip -n "$ns" link set lo up
done

ip netns exec dn-relay env RELAY_PORT=$PORT "$RELAY" serve >/dev/null 2>&1 & RP=$!
sleep 0.4
ip netns exec dn-a "$NODE" tunnel --home "$A" --overlay-ip 100.88.0.2 \
  --relay 10.0.0.1:$PORT --peers "$A/config/peers" >"$ALOG" 2>&1 & AP=$!
ip netns exec dn-b "$NODE" tunnel --home "$B" --overlay-ip 100.88.0.3 \
  --relay 10.0.0.1:$PORT --peers "$B/config/peers" >"$BLOG" 2>&1 & BP=$!
sleep 1

echo "=== ping (triggers handshake + direct-path discovery) ==="
ip netns exec dn-a ping -c 5 -W 2 100.88.0.3
PING_RC=$?
sleep 1
echo "=== node logs (look for 'direct path') ==="
grep -h "direct path" "$ALOG" "$BLOG" || true
if grep -q "direct path" "$ALOG" || grep -q "direct path" "$BLOG"; then
  echo "DIRECT_PATH: PASS (peers upgraded off the relay)"
else
  echo "DIRECT_PATH: FAIL (stayed on the relay)"; RC=1
fi
[ $PING_RC -eq 0 ] || { echo "PING failed"; RC=1; }
exit $RC
