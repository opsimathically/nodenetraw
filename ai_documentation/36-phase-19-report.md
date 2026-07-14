# Phase 19 completion report

Date: 2026-07-14

## Outcome

Phase 19 is complete. The internal, non-published `nodenet-linux-context` crate
now owns a bounded, read-only Linux `NETLINK_ROUTE` snapshot boundary for the
future scanner. It is independent of N-API and does not change either Node
package's public API or release artifacts.

`RouteContext` owns one close-on-exec datagram descriptor bound to the network
namespace in which it is created. It records `SO_NETNS_COOKIE` when supported,
uses a kernel-assigned port, serializes snapshot calls through mutable access,
and never recreates its descriptor, calls `setns()`, invokes `ip`, or reads
procfs at runtime. Procfs and `ip -j` appear only in opt-in test oracles.

Each snapshot performs GET-only dumps for links, addresses, IPv4/IPv6 routes,
policy rules, and ARP/NDP neighbors. It normalizes interface identity, flags,
link type, MTU, hardware and permanent addresses, controller/link relations,
operational state, prefixes, route tables/types/scopes/protocols/priorities,
preferred sources, gateways, metrics, multipath next hops, rule selectors, and
neighbor state/link addresses. Unknown attributes are copied only within
per-attribute and aggregate diagnostic bounds.

## Completeness and safety boundary

One snapshot is published only after every multipart dump terminates and all
normalized interface references resolve. Records are sorted before publication,
the completeness field has no partial variant, and generation increments only
after successful completion. A failed attempt contributes no records to the next
attempt.

The driver verifies kernel sender port/group identity, request sequence and
header port, expected response type, `NLMSG_DONE` status, `NLMSG_ERROR`,
`NLM_F_DUMP_INTR`, `NLMSG_OVERRUN`, `ENOBUFS`, truncation, malformed lengths and
alignment, nested structure, missing termination, and link churn. Sequence-zero
notifications are counted separately and never enter a reply. Incomplete or
coherence failures retry the complete snapshot at most three times; other
malformed or resource-limit errors fail immediately. Every receive is bounded by
a two-second descriptor timeout.

The planned ceilings are independently enforced: a 1 MiB datagram, 65,536
messages per dump, 256 attributes per message, depth eight, 256-byte strings,
4,096 interfaces, 16,384 addresses, 65,536 routes, rules, or neighbors, and 64
multipath next hops. Diagnostic unknown attributes add a 4 KiB individual and 8
MiB snapshot aggregate bound. A defensive 64 MiB aggregate dump-byte ceiling and
256-byte retained link-layer-address ceiling prevent many individually valid
large records from accumulating excessive memory.

Project-owned unsafe code is limited to two small Linux socket-option adapters.
Their initialized pointer, size, lifetime, and descriptor assumptions have local
`SAFETY` comments. The rest of the crate denies warnings and uses safe Rust.

## Dependency review

D-033 exact-pins `netlink-packet-core` 0.8.1, `netlink-packet-route` 0.31.0, and
`netlink-sys` 0.8.8 with default features disabled. The selected versions are
MIT-licensed and support the repository MSRV. Their small locked transitive
addition is `bytes`, `log`, and `paste`; no async executor, Tokio, `rtnetlink`,
N-API, procfs parser, or subprocess dependency was introduced. `libc` remains
the existing exact-pinned Linux ABI dependency. RustSec reports no known
vulnerability; it does report the already-public unmaintained warning for the
transitive `paste` macro crate used by `netlink-packet-core`. The warning is
recorded rather than hidden, and the repository's existing advisory policy
allows non-vulnerability warnings while continuing to fail vulnerabilities.

## Verification evidence

The ordinary suite covers successful multipart assembly, sequence-zero
separation, error/ACK termination, interrupted dumps, overruns, wrong sequences,
non-kernel senders, missing terminators, malformed headers/attributes, attribute
count/string/depth ceilings, multipath structure/count, bounded unknown
preservation, oversized diagnostics, dangling interface references, live
unprivileged snapshots, deterministic ordering, generation reuse, and descriptor
stability.

`test:phase19:namespace` passed in a disposable namespace containing loopback,
veth, VLAN, IPv4/IPv6 addresses, table 100, blackhole/prohibit routes, IPv4/IPv6
rules, and permanent ARP/NDP entries. Link, address, route, and full neighbor
counts matched independent `ip -j` output, expected typed records were present,
and two unchanged snapshots were byte-for-value identical apart from generation.

`test:phase19:stress` completed 512 measured snapshots after warm-up without a
descriptor increase or more than the 8 MiB RSS allowance. A local
`strace -f -e sendto` capture showed only `RTM_GETLINK`, `RTM_GETADDR`,
`RTM_GETROUTE`, `RTM_GETRULE`, and `RTM_GETNEIGH`, each with exactly
`NLM_F_REQUEST|NLM_F_DUMP`; it showed no create, replace, set, or delete
request.

The completion verification commands are:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo check -p nodenet-linux-context --target x86_64-unknown-linux-gnu --locked
cargo check -p nodenet-linux-context --target aarch64-unknown-linux-gnu --locked
cargo audit --file Cargo.lock
npm run format:check
npm run lint
npm run typecheck
npm test
npm run hardening:verify
npm run test:phase19:namespace
npm run test:phase19:stress
```

Native AArch64 execution remains CI-owned and unverified locally, consistent
with the repository support note.

## Scope confirmation and next action

No route resolution, multicast subscription, notification application, active
neighbor discovery, route or namespace mutation, scheduler, scanner runtime,
N-API export, or public TypeScript API was added. Phase 20 is next: targeted
kernel route resolution and notification-coherent generation refresh over this
read-only descriptor foundation.
