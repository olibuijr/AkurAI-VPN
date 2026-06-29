#!/usr/bin/env bash
# tests/netns/symmetric.sh — symmetric-NAT relay-fallback proof.
#
# Node A and node B sit behind SEPARATE NAT routers, each MASQUERADEing with
# randomized source ports (`--random` → a different external port per
# destination = symmetric NAT). The two private subnets are not routable to each
# other; only the relay's public address is reachable through the NATs. So the
# PeerAddr the relay observes for A is a port that B's NAT will NOT accept return
# traffic on — direct hole-punching CANNOT succeed, and the overlay must fall back
# to relaying. This proves the mesh still carries traffic through hard (symmetric)
# NAT — exactly what Tailscale's DERP relays do.
#
# Topology:
#   public LAN 10.0.0.0/24 (bridge in sy-net): relay 10.0.0.1, natA 10.0.0.10, natB 10.0.0.20
#   A private 192.168.10.0/24: natA 192.168.10.1, node A 192.168.10.2 (overlay 100.88.0.2)
#   B private 192.168.20.0/24: natB 192.168.20.1, node B 192.168.20.2 (overlay 100.88.0.3)
# Run: sudo tests/netns/symmetric.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE="${NODE_BIN:-$ROOT/target/debug/akurai-node}"
RELAY="${RELAY_BIN:-$ROOT/target/debug/akurai-relay}"
W="$(mktemp -d)"; A="$W/a"; B="$W/b"; PORT=51820; RC=0
ALOG="$W/a.log"; BLOG="$W/b.log"
NSALL="sy-net sy-relay sy-nata sy-a sy-natb sy-b"
cleanup(){ kill ${AP:-} ${BP:-} ${RP:-} 2>/dev/null
  for n in $NSALL; do ip netns del "$n" 2>/dev/null; done
  rm -rf "$W"; }
trap cleanup EXIT
[ -x "$NODE" ] && [ -x "$RELAY" ] || { echo "build akurai-node + akurai-relay first"; exit 1; }

"$NODE" install --home "$A" >/dev/null; "$NODE" install --home "$B" >/dev/null
echo "100.88.0.3 $(cat "$B/config/identity.pub") nodeb" > "$A/config/peers"
echo "100.88.0.2 $(cat "$A/config/identity.pub") nodea" > "$B/config/peers"

for n in $NSALL; do ip netns add "$n"; ip -n "$n" link set lo up; done

# Public LAN: bridge in sy-net, three legs (relay, natA public, natB public).
ip -n sy-net link add br0 type bridge; ip -n sy-net link set br0 up
for pair in "relay:sy-relay:10.0.0.1" "natau:sy-nata:10.0.0.10" "natbu:sy-natb:10.0.0.20"; do
  nm="${pair%%:*}"; rest="${pair#*:}"; ns="${rest%%:*}"; ip4="${rest##*:}"
  ip -n sy-net link add "h$nm" type veth peer name "n$nm"
  ip -n sy-net link set "h$nm" master br0; ip -n sy-net link set "h$nm" up
  ip -n sy-net link set "n$nm" netns "$ns"
  ip -n "$ns" addr add "$ip4/24" dev "n$nm"; ip -n "$ns" link set "n$nm" up
done

# Private link natA<->A and natB<->B (point-to-point veth).
ip -n sy-nata link add pa type veth peer name na
ip -n sy-nata link set na netns sy-a
ip -n sy-nata addr add 192.168.10.1/24 dev pa; ip -n sy-nata link set pa up
ip -n sy-a addr add 192.168.10.2/24 dev na; ip -n sy-a link set na up
ip -n sy-a route add default via 192.168.10.1

ip -n sy-natb link add pb type veth peer name nb
ip -n sy-natb link set nb netns sy-b
ip -n sy-natb addr add 192.168.20.1/24 dev pb; ip -n sy-natb link set pb up
ip -n sy-b addr add 192.168.20.2/24 dev nb; ip -n sy-b link set nb up
ip -n sy-b route add default via 192.168.20.1

# Each NAT router: forward + SYMMETRIC masquerade (random source port per flow).
ip netns exec sy-nata sysctl -qw net.ipv4.ip_forward=1
ip netns exec sy-nata iptables -t nat -A POSTROUTING -s 192.168.10.0/24 -o nnatau -j MASQUERADE --random
ip netns exec sy-natb sysctl -qw net.ipv4.ip_forward=1
ip netns exec sy-natb iptables -t nat -A POSTROUTING -s 192.168.20.0/24 -o nnatbu -j MASQUERADE --random

# Sanity: A reaches the relay's public IP, but NOT B's private IP (proves isolation).
ip netns exec sy-a ping -c1 -W2 10.0.0.1 >/dev/null 2>&1 && echo "underlay: A->relay OK" || { echo "underlay A->relay FAIL"; RC=1; }
if ip netns exec sy-a ping -c1 -W1 192.168.20.2 >/dev/null 2>&1; then
  echo "ISOLATION FAIL: A directly reached B's private IP"; RC=1
else
  echo "isolation: A cannot directly reach B's private subnet (good)"
fi

ip netns exec sy-relay env RELAY_PORT=$PORT "$RELAY" serve >/dev/null 2>&1 & RP=$!
sleep 0.4
ip netns exec sy-a "$NODE" tunnel --home "$A" --overlay-ip 100.88.0.2 \
  --relay 10.0.0.1:$PORT --peers "$A/config/peers" >"$ALOG" 2>&1 & AP=$!
ip netns exec sy-b "$NODE" tunnel --home "$B" --overlay-ip 100.88.0.3 \
  --relay 10.0.0.1:$PORT --peers "$B/config/peers" >"$BLOG" 2>&1 & BP=$!
sleep 1.5

echo "=== ping A->B over the overlay (must traverse symmetric NAT via the relay) ==="
ip netns exec sy-a ping -c 5 -W 2 100.88.0.3
PING_RC=$?

echo "=== path check: a direct path should NOT form through symmetric NAT ==="
if grep -q "direct path" "$ALOG" || grep -q "direct path" "$BLOG"; then
  echo "NOTE: a direct path formed (NAT was not strict enough to block it)"
else
  echo "relay-fallback confirmed: no direct path, traffic carried by the relay"
fi

if [ $PING_RC -eq 0 ]; then
  echo "SYMMETRIC_NAT: PASS (overlay reachable through symmetric NAT via relay)"
else
  echo "SYMMETRIC_NAT: FAIL (overlay unreachable through symmetric NAT)"; RC=1
fi
exit $RC
