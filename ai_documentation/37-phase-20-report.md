# Phase 20 completion report

Date: 2026-07-14

## Outcome

Phase 20 is complete. The internal `nodenet-linux-context` crate now turns its
immutable read-only snapshots into policy-aware, generation-bound egress plans.
It does not change either Node package's public API, add a runtime dependency,
or perform network configuration.

`RouteContext::resolve_route` issues a targeted `RTM_GETROUTE` with checked
destination and optional source, output interface, mark, UID, IP protocol, and
source/destination ports. Linux selects routing rules and ECMP. IPv4 requests
use `RTM_F_LOOKUP_TABLE` so policy-selected tables are retained; IPv6 omits the
IPv4-only flag. Results include the route type/table, interface identity,
preferred source, gateway/on-link next hop, route-or-interface MTU,
kernel-identified multipath choice, neighbor state/link address, disposition,
and the exact snapshot generation used for the join.

The pure `plan_route` layer classifies local/loopback, Ethernet or VLAN on-link
and gateway, and multicast plans. Blackhole, unreachable, prohibit, throw, and
interface-down results are explicit. Missing interfaces, ambiguous multipath,
non-Ethernet/tunnel link types, encapsulation, and missing IPv6 scope return
structured unsupported results rather than guessed link headers.

## Coherence and bounded driver

The route-netlink descriptor subscribes to link, address, route, rule, and
neighbor groups before the first dump. Notifications interleaved with dumps or
queries are bounded to 8,192 messages and 8 MiB, normalized, and published as
one atomic generation. A route query captures a generation, drains received
changes after its reply, and retries at most three times within its monotonic
deadline if publication advances that generation. It never relabels old route
data with a newer generation.

Kernel multicast changes may preserve the originating userspace request's
nonzero netlink sequence and header port. The decoder therefore authenticates
the recvmsg sender as the kernel and uses multicast group delivery to separate
notifications from the crate's unicast reply. Sequence/port checks remain strict
for those unicast replies.

Overflow, `ENOBUFS`, truncation, malformed state, interrupted streams, or
dangling references invalidate the current generation and trigger at most one
bounded full resync. Repeated failures use exponential backoff capped at five
seconds. Abandoned route requests also invalidate the context because a late
unicast reply could otherwise contaminate the next transaction.

`RouteContextDriver` provides the planned asynchronous integration seam without
an async dependency. One worker owns one context and serializes refresh/query
commands. Admission is capped at 1,024 pending operations, deadlines start when
the command is enqueued, cancellation is thread-safe, and result handles support
nonblocking polling or deadline-bounded waiting. Dropping the owner cancels its
active query and joins the single worker; no thread is created per operation.

## Safety and test evidence

All Phase 19 parse, size, count, depth, unknown-byte, descriptor, and immutable
publication bounds remain enforced. Notification replacement recomputes the
aggregate unknown-byte budget, including nested multipath diagnostics, without
double-charging replaced records. No new unsafe code was added.

Pure tests cover every named neighbor state, route-versus-interface MTU,
local/loopback/VLAN/multicast, four kernel unusable route types, interface-down,
unsupported hardware/link kind/encapsulation, selected and ambiguous multipath,
query validation, cancellation-before-I/O, single-reply decoding, multicast
origin identity, notification replacement/deletion, notification byte bounds,
and the pending-operation ceiling.

The disposable namespace oracle proves source-policy table selection with TCP
port selectors, gateway and missing-neighbor plans, VLAN on-link resolution,
blackhole/prohibit/unreachable results, kernel ECMP selection, unsupported dummy
links, address generation changes, concurrent mutation/query coherence, failed
neighbor reporting, and link-down classification. Ordinary live tests cover
IPv4/IPv6 loopback and the asynchronous owner.

The Phase 20 stress lane performs 1,024 generation-checked route queries and 32
context-driver create/query/drop cycles after warm-up, with no descriptor
increase and no more than 16 MiB RSS growth.

Canonical Phase 20 commands are:

```sh
cargo test -p nodenet-linux-context --locked
cargo clippy -p nodenet-linux-context --all-targets --locked -- -D warnings
npm run test:phase20:namespace
npm run test:phase20:stress
```

The full workspace gates also passed at completion. Native AArch64 execution
remains CI-owned and unverified locally, consistent with the repository support
note.

## Scope confirmation and next action

The context sends only GET/query requests and subscribes read-only. It never
creates, changes, or deletes a link, address, route, rule, neighbor, namespace,
firewall entry, qdisc, sysctl, or BPF object. No scanner scheduler, live probe
engine, N-API export, or public TypeScript API was added.

Phase 21 is next: the syscall-free deterministic scan scheduler can now consume
the completed protocol and context contracts.
