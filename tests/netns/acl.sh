#!/usr/bin/env bash
# tests/netns/acl.sh — MVP4 fine-grained ACL proof (fail-closed policy).
#
# One enforcing node A and two reachable peers B and C share an underlay LAN
# (a bridge), so all three are mutually routable and all are in A's peer map.
# A loads an ACL that permits only `tag:client -> tag:trusted`. B is tagged
# `server` (DENIED), C is tagged `trusted` (ALLOWED). The proof: A's ping to the
# DENIED peer FAILS (its packets are dropped in the data path before any
# handshake), while A's ping to the ALLOWED peer SUCCEEDS — even though BOTH
# peers are present in the peer map. B and C run with NO ACL file, so they keep
# today's allow-all behavior (needed for C's echo reply to come back).
#
# Topology (all on 10.0.0.0/24 via bridge br0 in dn-net):
#   relay 10.0.0.1 : A 10.0.0.2 (100.88.0.2, tag:client, ENFORCES)
#                  : B 10.0.0.3 (100.88.0.3, tag:server,  DENIED)
#                  : C 10.0.0.4 (100.88.0.4, tag:trusted, ALLOWED)
# Run: sudo tests/netns/acl.sh
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NODE="${NODE_BIN:-$ROOT/target/debug/akurai-node}"
RELAY="${RELAY_BIN:-$ROOT/target/debug/akurai-relay}"
W="$(mktemp -d)"; A="$W/a"; B="$W/b"; C="$W/c"; PORT=51820; RC=0
ALOG="$W/a.log"; BLOG="$W/b.log"; CLOG="$W/c.log"
cleanup(){ kill ${AP:-} ${BP:-} ${CP:-} ${RP:-} 2>/dev/null
  for n in dn-relay dn-a dn-b dn-c dn-net; do ip netns del $n 2>/dev/null; done
  rm -rf "$W"; }
trap cleanup EXIT
[ -x "$NODE" ] && [ -x "$RELAY" ] || { echo "build akurai-node + akurai-relay first"; exit 1; }

"$NODE" install --home "$A" >/dev/null
"$NODE" install --home "$B" >/dev/null
"$NODE" install --home "$C" >/dev/null

# A's peer map: BOTH peers are reachable at the network layer. The 4th field is
# `-` (no advertised subnet); the 5th field is the peer's ACL tag.
{
  echo "100.88.0.3 $(cat "$B/config/identity.pub") nodeb - tag:server"
  echo "100.88.0.4 $(cat "$C/config/identity.pub") nodec - tag:trusted"
} > "$A/config/peers"
# B and C only need to recognise A (for the inbound handshake / echo reply).
echo "100.88.0.2 $(cat "$A/config/identity.pub") nodea" > "$B/config/peers"
echo "100.88.0.2 $(cat "$A/config/identity.pub") nodea" > "$C/config/peers"

# A's ACL: permit ONLY client -> trusted. So A(client)->C(trusted) is allowed,
# A->B(server) is denied. (B and C have no ACL file -> allow all.)
echo "allow tag:client -> tag:trusted" > "$A/config/acl"

# One shared LAN: a bridge in dn-net, four veths into relay/a/b/c.
ip netns add dn-net; ip netns add dn-relay; ip netns add dn-a; ip netns add dn-b; ip netns add dn-c
ip -n dn-net link add br0 type bridge; ip -n dn-net link set br0 up
for pair in "relay:dn-relay:10.0.0.1" "a:dn-a:10.0.0.2" "b:dn-b:10.0.0.3" "c:dn-c:10.0.0.4"; do
  nm="${pair%%:*}"; rest="${pair#*:}"; ns="${rest%%:*}"; ip4="${rest##*:}"
  ip -n dn-net link add "h$nm" type veth peer name "n$nm"
  ip -n dn-net link set "h$nm" master br0; ip -n dn-net link set "h$nm" up
  ip -n dn-net link set "n$nm" netns "$ns"
  ip -n "$ns" addr add "$ip4/24" dev "n$nm"; ip -n "$ns" link set "n$nm" up; ip -n "$ns" link set lo up
done

ip netns exec dn-relay env RELAY_PORT=$PORT "$RELAY" serve >/dev/null 2>&1 & RP=$!
sleep 0.4
# A ENFORCES the ACL (--acl + --my-tags). B and C do not.
ip netns exec dn-a "$NODE" tunnel --home "$A" --overlay-ip 100.88.0.2 \
  --relay 10.0.0.1:$PORT --peers "$A/config/peers" \
  --acl "$A/config/acl" --my-tags tag:client >"$ALOG" 2>&1 & AP=$!
ip netns exec dn-b "$NODE" tunnel --home "$B" --overlay-ip 100.88.0.3 \
  --relay 10.0.0.1:$PORT --peers "$B/config/peers" >"$BLOG" 2>&1 & BP=$!
ip netns exec dn-c "$NODE" tunnel --home "$C" --overlay-ip 100.88.0.4 \
  --relay 10.0.0.1:$PORT --peers "$C/config/peers" >"$CLOG" 2>&1 & CP=$!
sleep 1

echo "=== ALLOWED: A -> C (tag:trusted) should SUCCEED ==="
ip netns exec dn-a ping -c 5 -W 2 100.88.0.4
ALLOW_RC=$?

echo "=== DENIED: A -> B (tag:server) should FAIL (dropped in data path) ==="
ip netns exec dn-a ping -c 3 -W 2 100.88.0.3
DENY_RC=$?

sleep 0.5
echo "=== A node log (expect 'acl: denied nodeb', NOT nodec) ==="
grep -h "acl:" "$ALOG" || echo "(no acl lines)"

# Assertions.
if [ $ALLOW_RC -eq 0 ]; then
  echo "ALLOW: PASS (A reached trusted peer C)"
else
  echo "ALLOW: FAIL (A could not reach the ALLOWED peer C)"; RC=1
fi
if [ $DENY_RC -ne 0 ]; then
  echo "DENY: PASS (A's traffic to the DENIED peer B was dropped)"
else
  echo "DENY: FAIL (A reached the DENIED peer B — ACL not enforced)"; RC=1
fi
if grep -q "acl: denied nodeb" "$ALOG"; then
  echo "OBSERVABILITY: PASS (one-time deny notice emitted for nodeb)"
else
  echo "OBSERVABILITY: FAIL (no 'acl: denied nodeb' notice)"; RC=1
fi
# The ALLOWED peer must never be logged as denied.
if grep -q "acl: denied nodec" "$ALOG"; then
  echo "OBSERVABILITY: FAIL (allowed peer nodec was wrongly denied)"; RC=1
fi

[ $RC -eq 0 ] && echo "ACL_ENFORCEMENT: PASS" || echo "ACL_ENFORCEMENT: FAIL"
exit $RC
