# AkurAI VPN — Linux netns end-to-end test plan

> End-to-end tests use Linux **network namespaces** to stand up a whole tiny
> overlay on one host: a control plane, two nodes, and a gateway. This is the
> plan; the harness is not implemented in 0.0.1 (there is no data plane yet —
> see `../../docs/protocol.md`).

## Namespaces

| Namespace | Role |
|-----------|------|
| `ns-control` | runs `akurai-control` (and `akurai-relay`, colocated in v1) |
| `ns-node-a` | runs `akurai-node`, enrolls, gets an overlay IP |
| `ns-node-b` | runs `akurai-node`, enrolls, gets an overlay IP |
| `ns-gateway` | runs `akurai-node` advertising a subnet / exit route |

Each namespace is wired to a shared bridge so the nodes can reach the control
plane; per-test `iptables`/`tc` rules simulate a blocked direct path to exercise
relay fallback.

## Test requirements (from the plan)

- [ ] Node enrollment succeeds.
- [ ] TUN route is installed (`akurai0`, `100.88.0.0/16`, `fd88::/48`).
- [ ] Node A can ping Node B over the overlay.
- [ ] ACL denial drops traffic.
- [ ] A subnet route appears only after admin approval.
- [ ] An exit route is opt-in only.
- [ ] Relay fallback works when the direct path is blocked.
- [ ] A node cannot advertise an unauthorized route (reject + audit).
- [ ] A DNS name (`*.oli.akurai`) resolves to the overlay IP.

## Sketch

```sh
# create namespaces
for ns in ns-control ns-node-a ns-node-b ns-gateway; do ip netns add "$ns"; done

# ... wire a bridge, veth pairs, addresses ...

# bring up the control plane, then enroll each node, then assert each
# requirement above. Teardown deletes the namespaces.
```

Running these requires root (namespace + TUN creation) and is gated behind a
feature/flag so the default `cargo test` stays unprivileged.
