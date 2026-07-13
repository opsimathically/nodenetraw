# Planning index

Last updated: 2026-07-13

## Current state

Phases 0 through 11 are complete, with native AArch64 execution retained as a
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
close without changing Rust or native ownership. The candidate is now the
unpublished `0.1.0-rc.2`; x86-64 ordinary, privileged, stress, consumer,
artifact, and reproducibility gates pass.

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

Phase 11 prepared the unpublished `0.1.0-rc.2` release candidate. No further
implementation phase is accepted yet. The next action is review of possible
post-baseline adapters or publication readiness; streams, async iteration, batch
events, packet-ring events, and `ref()`/`unref()` remain separate design
decisions. Native AArch64 execution remains a publication gate.
