# Planning index

Last updated: 2026-07-14

## Current state

Phases 0 through 15 are complete, with native AArch64 execution retained as a
publication gate. IPv4/IPv6 raw sockets and raw/cooked packet sockets now
include bounded `sendmsg`/`recvmsg`, typed ancillary data and flags, metadata
and error-queue options, device binding, AbortSignal cancellation, explicit
data/control truncation, fair reactor budgets, and bounded lossless completion
backpressure. Advanced typed and bounded opaque options, packet
membership/auxdata/statistics/fanout, and classic/eBPF attachment are included.
Rust owns descriptors, syscall buffers, readiness state, and pending native
operations. Bounded batch message I/O and receive-only TPACKET_V3 rings with
copied frame leases provide measured high-throughput paths without exposing mmap
storage.

The public TypeScript surface exports common Linux `IPPROTO_*` and `ETH_P_*`
constants for readable application code. Protocol fields remain numeric so
custom and less-common Linux identifiers continue to work without dependency or
registry coupling.

Phase 11 implements an optional typed `RawSocketEventEmitter` as a
zero-dependency TypeScript adapter over the existing promise API. It provides
explicit start, awaitable pause/detach, one receive per source, independent
normal/error-queue ownership, Node-standard listener behavior, and exactly-once
close without changing Rust or native ownership. Phases 12 through 14 add pure
bounded ICMPv4 checksum, Echo, diagnostic-error, Router Discovery, Timestamp,
and deprecated Address Mask codecs; structured validation; Linux raw-receive
extraction; quoted-packet correlation; RFC 1191 MTU; RFC 4884 extensions; and
one-operation helpers over the same socket API. Phase 15 adds deterministic
TTL-limited Echo probes, pure strong/weak response classification, and bounded
increasing-TTL orchestration with exact monotonic deadlines and cleanup-ordered
receive-lane ownership. The candidate is now the unpublished `0.1.0-rc.6`;
x86-64 ordinary, privileged routed-topology, stress, consumer, artifact, and
reproducibility gates pass.

The adversarial post-implementation audit found and corrected a stale same-turn
pump replacement race, non-abort error wins that could strand pause or detach
state, and hostile AbortSignal cleanup gaps. Expanded controller coverage and
genuine privileged regressions now protect those cases. See the Phase 11
implementation audit.

The post-Phase-10 release-readiness audit supersedes nonblocking N-API callback
delivery with bounded lossless backpressure, makes close wait for all admitted
operations, recovers malformed packet-ring blocks, validates returned batch and
packet addresses more defensively, and enforces the declared glibc baseline on
release artifacts. See D-026, D-027, and the audit report. AArch64 remains
explicitly untested.

Phases 12 through 15 passed their preimplementation protocol/API/safety review
and are implemented. The work composes over the existing promise and event
receive APIs; it does not add another native I/O engine or silently include the
distinct ICMPv6 protocol. See the capability plan, review, and Phase 12–15
reports for the frozen scope, wire-validation rules, safety bounds, and
implementation evidence. The post-implementation audit corrected four hostile
JavaScript boundary and callback-quiescence gaps and repeated all release gates.

The repository has been migrated without a public API change into the `nodenet`
monorepo. The root is a private npm workspace and virtual Cargo workspace;
`packages/nodenetraw` owns the existing Node package, `crates/nodenetraw-native`
owns its Rust addon, and `packages/nodenetscanner` is a private Phase 23 preview
with an initial Node API. The shared scanner foundations are internal Rust
crates. Root commands continue to provide the canonical build, test, hardening,
and release interface. See D-030 and the monorepo migration report.

Phases 16 through 24 are the accepted portable scanner evolution roadmap. Phases
16 through 22 are complete: the internal `nodenet-protocols` crate provides
project-owned checked types/errors, bounded strict and explicit ICMP-quote
inspection, transactional output, Ethernet/VLAN, ARP, IPv4, bounded IPv6
extension traversal and fragments, explicit upper-layer disposition, checked
frame templates, independent fixtures, fuzz targets, allocation baselines,
scanner-relevant TCP/UDP/ICMPv4/ICMPv6/NDP codecs, bounded quote decoding, and
session-keyed correlation with explicit protocol-specific evidence strength. The
internal `nodenet-linux-context` crate now supplies bounded, immutable,
generation-tagged link/address/route/rule/neighbor snapshots, policy-aware
kernel route resolution, notification-coherent refresh, and a bounded
asynchronous owner through read-only route netlink. The internal
`nodenetscanner-engine` adds compact checked target products, deterministic
seeded scheduling, exact virtual timing, fairness, evidence classification, late
grace, bounded lifecycle draining, and lossless result reservations.
`crates/nodenetscanner-native` and the private scanner package connect those
foundations to one bounded runtime per Node environment, ordinary Linux
packet/raw sockets, live ARP/NDP, ICMPv4/v6 Echo, TCP SYN and UDP probes, and a
pull-based TypeScript session API. Phase 23 freezes versioned compact result
batches, abortable waits, coalesced progress, and high/low-water backpressure;
the remaining portable roadmap completes release hardening. Phase 25 is an
evidence gate; conditional Phase 26 may add exactly one extreme backend only
when measurements justify it. `nodenetraw` remains policy-free, while
`nodenetscanner` owns its descriptors and native packet hot path without calling
the raw package through JavaScript. See D-031, D-032, the
[Phase 16 report](33-phase-16-report.md),
[Phase 18 report](35-phase-18-report.md), the
[Phase 19 report](36-phase-19-report.md), the
[Phase 20 report](37-phase-20-report.md), the
[Phase 21 report](38-phase-21-report.md), and the
[Phase 22 report](39-phase-22-report.md), the
[Phase 23 report](40-phase-23-report.md), plus the
[network and scanner evolution plan](31-network-and-scanner-evolution-plan.md).

The preimplementation review is closed. It corrected protocol-specific evidence
strength, IPv6/NDP validation, netlink generation races, namespace and
supported- link scope, native runtime/completion isolation, complete rate/result
reservation, packet-socket outgoing/VLAN behavior, pull/cancel/close semantics,
and the statistical/XDP ownership conditions for an extreme backend. See the
[network evolution plan review](32-network-evolution-plan-review.md).

## Documents

1. [Scope and requirements](01-scope-and-requirements.md)
2. [Architecture](02-architecture.md)
3. [Safety and security](03-safety-and-security.md)
4. [Roadmap](04-roadmap.md)
5. [Decision log](05-decision-log.md)
6. [Tooling and testing](06-tooling-and-testing.md)
7. [Phase 1 completion report](07-phase-1-report.md)
8. [Phase 2 completion report](08-phase-2-report.md)
9. [Phase 3 completion report](09-phase-3-report.md)
10. [Phase 4 completion report](10-phase-4-report.md)
11. [Full raw-networking capability plan](11-full-capability-plan.md)
12. [Phase 5 completion report](12-phase-5-report.md)
13. [Phase 6 completion report](13-phase-6-report.md)
14. [Phase 7 completion report](14-phase-7-report.md)
15. [Phase 8 completion report](15-phase-8-report.md)
16. [Phase 9 completion report](16-phase-9-report.md)
17. [Phase 10 completion report](17-phase-10-report.md)
18. [Release-readiness audit](18-release-readiness-audit.md)
19. [Phase 11 event-driven API plan](19-phase-11-event-api-plan.md)
20. [Phase 11 plan review](20-phase-11-plan-review.md)
21. [Phase 11 completion report](21-phase-11-report.md)
22. [Phase 11 implementation audit](22-phase-11-implementation-audit.md)
23. [ICMPv4 utilities and traceroute capability plan](23-icmp-and-traceroute-plan.md)
24. [ICMPv4 and traceroute plan review](24-icmp-plan-review.md)
25. [Phase 12 completion report](25-phase-12-report.md)
26. [Phase 13 completion report](26-phase-13-report.md)
27. [Phase 14 completion report](27-phase-14-report.md)
28. [Phase 15 completion report](28-phase-15-report.md)
29. [Phase 12–15 implementation audit](29-phase-12-15-implementation-audit.md)
30. [Monorepo migration report](30-monorepo-migration-report.md)
31. [Network and scanner evolution plan](31-network-and-scanner-evolution-plan.md)
32. [Network and scanner evolution plan review](32-network-evolution-plan-review.md)
33. [Phase 16 completion report](33-phase-16-report.md)
34. [Phase 17 completion report](34-phase-17-report.md)
35. [Phase 18 completion report](35-phase-18-report.md)
36. [Phase 19 completion report](36-phase-19-report.md)
37. [Phase 20 completion report](37-phase-20-report.md)
38. [Phase 21 completion report](38-phase-21-report.md)
39. [Phase 22 completion report](39-phase-22-report.md)

`AGENTS.md` is the compact operational context. These documents contain the
rationale and phase details. If they disagree, resolve the discrepancy and
update both rather than choosing silently.

## Confirmed constraints

- Linux-only implementation and public support policy.
- Node.js module with a TypeScript public environment.
- Rust native implementation connected through N-API.
- ESLint and Prettier enabled from project bootstrap.
- Minimize external Node packages and native dependencies.
- Memory safety, robust resource handling, and defensive boundary validation are
  primary requirements.
- Authentication and application-level authorization are not project goals.
- The target baseline is practical full Linux raw networking across IPv4, IPv6,
  and `AF_PACKET`, including message/control/error semantics, safe
  extensibility, filtering, measured high-throughput paths, and distribution.
- The accepted post-baseline protocol layer covers the enumerated ICMPv4 message
  families and bounded ICMP Echo traceroute while retaining the raw socket APIs
  as the I/O and ownership foundation.
- The accepted scanner roadmap keeps protocol codecs, read-only network context,
  scheduling, correlation, and packet I/O in non-published Rust crates linked
  into a separate scanner addon; JavaScript receives only control, progress,
  summaries, and bounded result batches.

## Accepted Phase 1 choices

- Node.js `>=26.0.0`, compiling against stable Node-API 10.
- Latest stable Rust, exactly pinned and intentionally updated on stable Rust
  releases; the initial pin is Rust 1.97.0 using Rust 2024 edition.
- npm with a committed `package-lock.json`.
- ESM-only public output, with an internal CommonJS native-addon loader where
  required by Node.
- napi-rs v3 with narrowly enabled features.
- Node's built-in test runner.
- Initial support for x86-64 and AArch64 glibc Linux, kernel 4.18+ and glibc
  2.28+; no initial musl support.
- Source builds during early development, with prebuilts deferred to the
  distribution phase.
- Nonblocking descriptors coordinated by a bounded, environment-scoped Linux
  `epoll`/`eventfd` reactor.
- IPv4 `AF_INET`/`SOCK_RAW` with an explicit protocol as the first socket slice.

## Planning maintenance

When work starts:

1. Mark the relevant roadmap phase in progress.
2. Resolve required decisions in the decision log.
3. Implement only the scoped phase.
4. Record the verification commands and results.
5. Update this page's current state and next action.

Phase 23 is complete. Phase 24 portable scanner release hardening is next.
Extreme backends remain in their owning later phases, and native AArch64
execution remains a publication gate for each architecture-specific public
artifact.
