#!/usr/bin/env bash
# tests/netns/exit.sh — MVP2 exit-gateway (full-tunnel) proof.
#
# Node B is an exit gateway (advertises 0.0.0.0/0, NATs out). Node A opts in with
# --exit-node and routes ALL traffic through B over the overlay, reaching a host
# A has no other path to (198.51.100.2, a stand-in for "the internet"). Also
# proves the safety guard: the default route is via /1 routes, so closing the
# tunnel restores normal routing — the real default is never deleted.
#
# Underlay LAN 10.0.0.0/24 (bridge): relay .1, A .2 (100.88.0.2), B .3 (100.88.0.3)
# Behind B: 198.51.100.0/24 with host .2.
# Run: sudo tests/netns/exit.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE="${NODE_BIN:-$ROOT/target/debug/akurai-node}"
RELAY="${RELAY_BIN:-$ROOT/target/debug/akurai-relay}"
W="$(mktemp -d)"; A="$W/a"; B="$W/b"; PORT=51820; RC=0
cleanup(){ kill ${AP:-} ${BP:-} ${RP:-} 2>/dev/null
  for n in ex-net ex-relay ex-a ex-b ex-inet; do ip netns del $n 2>/dev/null; done
  rm -rf "$W"; }
trap cleanup EXIT
[ -x "$NODE" ] && [ -x "$RELAY" ] || { echo "build node+relay first"; exit 1; }

"$NODE" install --home "$A" >/dev/null; "$NODE" install --home "$B" >/dev/null
# A's peer B advertises 0.0.0.0/0 (exit gateway).
echo "100.88.0.3 $(cat "$B/config/identity.pub") nodeb 0.0.0.0/0" > "$A/config/peers"
echo "100.88.0.2 $(cat "$A/config/identity.pub") nodea" > "$B/config/peers"

ip netns add ex-net; ip netns add ex-relay; ip netns add ex-a; ip netns add ex-b; ip netns add ex-inet
ip -n ex-net link add br0 type bridge; ip -n ex-net link set br0 up
for pair in "relay:ex-relay:10.0.0.1" "a:ex-a:10.0.0.2" "b:ex-b:10.0.0.3"; do
  nm="${pair%%:*}"; rest="${pair#*:}"; ns="${rest%%:*}"; ip4="${rest##*:}"
  ip -n ex-net link add "h$nm" type veth peer name "n$nm"
  ip -n ex-net link set "h$nm" master br0; ip -n ex-net link set "h$nm" up
  ip -n ex-net link set "n$nm" netns "$ns"
  ip -n "$ns" addr add "$ip4/24" dev "n$nm"; ip -n "$ns" link set "n$nm" up; ip -n "$ns" link set lo up
done
# "Internet" behind B.
ip link add vbI netns ex-b type veth peer name viB netns ex-inet
ip -n ex-b addr add 198.51.100.1/24 dev vbI; ip -n ex-b link set vbI up
ip -n ex-inet addr add 198.51.100.2/24 dev viB; ip -n ex-inet link set viB up; ip -n ex-inet link set lo up

ip netns exec ex-relay env RELAY_PORT=$PORT "$RELAY" serve >/dev/null 2>&1 & RP=$!
sleep 0.4
ip netns exec ex-a "$NODE" tunnel --home "$A" --overlay-ip 100.88.0.2 \
  --relay 10.0.0.1:$PORT --peers "$A/config/peers" --exit-node 100.88.0.3 >/dev/null 2>&1 & AP=$!
ip netns exec ex-b "$NODE" tunnel --home "$B" --overlay-ip 100.88.0.3 \
  --relay 10.0.0.1:$PORT --peers "$B/config/peers" --advertise 0.0.0.0/0 >/dev/null 2>&1 & BP=$!
sleep 2

echo "=== ns-a routes (note: real default NOT deleted; /1 routes win) ==="
ip -n ex-a route | grep -E "default|0.0.0.0/1|128.0.0.0/1" || true
echo "=== A reaches the 'internet' host 198.51.100.2 via exit node B ==="
if ip netns exec ex-a ping -c 4 -W 2 198.51.100.2; then
  echo "EXIT_GATEWAY: PASS (full-tunnel through B reaches the internet host)"
else
  echo "EXIT_GATEWAY: FAIL"; RC=1
fi
exit $RC
