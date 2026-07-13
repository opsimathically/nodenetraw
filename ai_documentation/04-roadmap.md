# Delivery roadmap

Each phase ends with a reviewable artifact and explicit verification. Later
phases may be refined, but their safety gates should not be removed silently.

## Phase 0 — Requirements and planning

Status: complete enough to proceed

Deliverables:

- project scope and non-goals;
- architectural ownership boundaries;
- initial safety threat model and invariants;
- tooling/test strategy;
- decision log and durable agent context.

Exit gate: documentation distinguishes confirmed requirements from pending
technical choices and identifies a bootstrap sequence.

## Phase 1 — Minimal environment bootstrap

Status: complete (2026-07-12)

Deliverables:

- encode the accepted Node.js 26+ and Rust 1.97.0 toolchain policy;
- configure npm, ESM output, and napi-rs v3 with Node-API 10;
- create minimal package, TypeScript, ESLint, and Prettier configuration;
- create the Rust native crate and reproducible development build path;
- add ignore/editor defaults and initial CI quality gates;
- expose one harmless native smoke-test operation to prove the toolchain only;
- document exact install, build, lint, format, typecheck, and test commands.

Exit gate: a clean checkout can install deterministically, compile the native
module, call the smoke-test export from Node, and pass all non-network quality
checks. No raw socket behavior is required.

Completion evidence: `npm run ci` passes formatting, linting, strict type
checking, Rust formatting, Clippy, Rust unit tests, native/TypeScript builds,
and ESM plus `require()` smoke tests. `npm run build:native:release` and
`npm pack --dry-run` also pass. See the [Phase 1 report](07-phase-1-report.md).

## Phase 2 — Socket core and lifecycle model

Status: complete (2026-07-12)

Deliverables:

- implement a Node-independent Rust descriptor/lifecycle core;
- define open/closing/closed behavior and operation leases;
- implement checked conversions and structured errors;
- isolate the first Linux syscall adapter;
- test creation failures, ownership, explicit/repeated close, and cleanup.

Exit gate: no successful privileged socket traffic is required, but all
lifecycle and failure behavior is testable and reviewed, including required
`unsafe` invariants.

Completion evidence: 17 Rust tests cover state, ownership, multiple leases,
idempotent close, drop cleanup, a 256-iteration acquire/close race, conversion
boundaries, error fields, atomic descriptor flags, deterministic syscall
failure, and capability-dependent raw creation. No project-owned `unsafe` was
required; the syscall adapter uses safe rustix APIs. See the
[Phase 2 report](08-phase-2-report.md).

## Phase 3 — First raw-socket API slice

Status: complete (2026-07-12)

Deliverables:

- select and document the initial address family and protocol scope;
- create raw sockets with atomic close-on-exec and appropriate nonblocking mode;
- expose asynchronous send and receive of byte buffers;
- implement stable Linux error mapping;
- add TypeScript types and public API documentation;
- add unprivileged negative tests and opt-in capability-gated integration tests.

Exit gate: the initial API works end-to-end on the supported Linux test matrix,
does not block the event loop, and passes lifecycle/race tests.

Completion evidence: `RawSocket` works end-to-end for ICMP loopback traffic in
an isolated user/network namespace. One bounded reactor per Node environment
handles nonblocking readiness, close cancellation, and Worker teardown. The
standard CI gate passes 21 Rust tests and 5 unprivileged Node tests; 2 opt-in
privileged tests cover successful traffic and queue backpressure/cancellation.
See the [Phase 3 report](09-phase-3-report.md).

## Phase 4 — Binding, metadata, and socket options

Status: complete (2026-07-12)

Delivered scope:

- bind/address support for the initial families;
- interface selection;
- typed common socket options;
- packet metadata and ancillary-data primitives;
- explicit truncation and partial-I/O semantics.

Exit gate: every added option has input validation, kernel-version behavior,
error mapping, and tests. Generic raw option escape hatches require a separate
safety/API review.

Completion evidence: bind and local-address queries, five typed socket options,
original packet length, explicit truncation, and safely parsed IPv4 header
metadata are serialized through the bounded reactor. Twenty-four Rust tests,
five ordinary Node tests, and three isolated capability-gated packet tests pass.
See the [Phase 4 report](10-phase-4-report.md).

## Phase 5 — Message I/O, ancillary data, cancellation, and fairness

Status: complete (2026-07-12)

Purpose: establish the family-neutral message substrate required by IPv6,
`AF_PACKET`, error queues, timestamps, and later batching. The exact contract is
frozen in [the full-capability plan](11-full-capability-plan.md).

Deliverables:

- add exact-pinned nix with only `socket`, `uio`, and `net` features for safe
  typed `sendmsg`/`recvmsg`, control-message, missing sockopt, and address
  support; retain rustix for owned fds, epoll, eventfd, and existing safe calls;
- introduce checked native message, address, flag, and control-message types;
- implement `sendMessage()` and `receiveMessage()` for IPv4 while retaining
  `send()` and `receive()` as compatibility conveniences;
- return original data length, data/control truncation, source address, message
  flags, typed known control messages, and bounded owned unknown receive control
  messages;
- support IPv4 packet info, received TTL/TOS, nanosecond software timestamps,
  receive-queue overflow counters, and IPv4 extended error-queue messages;
- add typed receive-metadata enablement, receive-errors, timestamp,
  queue-overflow, and `SO_BINDTODEVICE` configuration;
- add `AbortSignal` cancellation with exactly-once settlement and a native
  cancellation token/wakeup path that cannot be rejected by a full command queue
  and does not close the socket;
- impose a 32-operation total per-socket limit, readiness work/byte budgets, and
  a proven nonblocking completion-delivery bound so one busy socket or stalled
  JavaScript callback cannot block the environment reactor;
- add focused parser/serializer, cancellation-race, fairness, error-queue,
  truncation, Worker teardown, and isolated namespace tests.

Exit gate:

- all public inputs have JavaScript and Rust validation;
- every control/data allocation and queue has a documented maximum;
- close/cancel/readiness races settle each operation once;
- two continuously readable sockets both make bounded progress;
- no reactor thread blocks on Node completion delivery;
- legacy Phase 4 behavior remains covered;
- IPv4 packet-info, timestamp, error-queue, device-binding, and cancellation
  paths pass in isolated user/network namespaces.

Completion evidence: exact-pinned safe message adapters, typed message/control
APIs and options, native cancellation, byte/operation admission bounds, fair
reactor turns, separate error queues, and nonblocking completion delivery are
implemented. Twenty-nine Rust tests, five ordinary Node tests, and four isolated
namespace tests pass. See the [Phase 5 report](12-phase-5-report.md).

Post-Phase-10 audit note: D-026 supersedes the nonblocking callback mechanism.
The original 32-operation proof did not bound completions already queued for
JavaScript, so callback saturation could discard settlements. Delivery now uses
bounded lossless backpressure; active-loop fairness remains measured, while a
stalled JavaScript environment intentionally backpressures its reactor.

## Phase 6 — IPv6 raw sockets

Status: complete (2026-07-12)

Deliverables:

- add `AF_INET6`/`SOCK_RAW` creation with explicit protocol and discriminated
  family/address types, including scope id and flow info where Linux uses them;
- support IPv6 bind, optional connect/disconnect, send/receive messages, and
  source/local address queries without pretending IPv6 raw payload/header
  semantics match IPv4;
- add typed unicast hops, traffic class, packet info, hop limit, receive errors,
  path-MTU discovery, and applicable multicast options available through the
  accepted safe syscall dependencies;
- expose IPv6 packet-info, hop-limit, traffic-class, timestamp, and extended
  error control messages through the Phase 5 message model;
- test ICMPv6 loopback, link-local scope validation, truncation, cancellation,
  close races, and unsupported option/family combinations.

Exit gate: IPv4 and IPv6 share lifecycle/message infrastructure but retain
documented family-specific semantics; ICMPv6 succeeds in an isolated namespace;
no API fabricates an unavailable IPv6 header.

Completion evidence: IPv6 creation, scoped addresses, bind/local/connect,
message/control parity, safe typed options, cancellation, truncation, and ICMPv6
loopback are implemented. Thirty-one Rust tests, ordinary Node tests, and five
isolated namespace tests pass. See the [Phase 6 report](13-phase-6-report.md).

## Phase 7 — Linux packet sockets

Status: complete (2026-07-12)

Deliverables:

- add `AF_PACKET` `SOCK_RAW` and `SOCK_DGRAM` with checked EtherType and
  `sockaddr_ll` representations;
- support interface name/index lookup, bind, send/receive addresses, packet
  direction/type, hardware type/address, and link-layer protocol metadata;
- test on an isolated veth pair for Ethernet injection/capture, interface
  isolation, raw/cooked header semantics, truncation, and close/cancel races.

Exit gate: both packet socket modes operate end-to-end on a veth test topology;
link-layer addresses and metadata are never confused with IP addresses; no
packet-specific sockopt is emulated before the reviewed Phase 8 adapter exists.

Completion evidence: checked raw/cooked creation, `sockaddr_ll` bind/send,
interface lookup, link metadata, veth isolation, header semantics, truncation,
cancellation, and close are implemented. Thirty-three Rust tests, seven ordinary
Node tests, and six isolated namespace tests pass. See the
[Phase 7 report](14-phase-7-report.md).

## Phase 8 — Advanced configuration, errors, and filtering

Status: complete (2026-07-12)

Deliverables:

- expand typed IPv4/IPv6/common options for routing, PMTU, multicast,
  `IP_HDRINCL`, `IPV6_CHECKSUM`, freebind/transparent behavior, priority/mark,
  busy polling, device binding, error queues, and timestamping where applicable;
- add connected raw-socket operation and explicit disconnect semantics;
- add packet promiscuous/multicast/all-multicast membership with deterministic
  removal, `PACKET_AUXDATA`, statistics/loss/VLAN metadata, and bounded
  `PACKET_FANOUT` with explicit group ownership;
- provide classic BPF validation/attachment/detachment/locking and safe
  attachment of a duplicated compatible eBPF program fd; do not load programs;
- add a bounded low-level `getSocketOption`/`setSocketOption` byte interface for
  Linux options not yet modeled, with reserved dangerous cases rejected and all
  unsafe code isolated behind one reviewed adapter if safe crates are
  insufficient;
- provide an explicit close-on-exec duplicated-fd interoperability API only if
  ownership and caller-close responsibilities can be made unambiguous;
- build a kernel-version/capability/driver behavior matrix and test predictable
  `ENOPROTOOPT`, `EINVAL`, `EPERM`, and unsupported-library failures.

Exit gate: typed paths remain preferred, the low-level escape hatch is bounded
and cannot violate memory/fd ownership, filters have deterministic replacement
and cleanup, and unsupported features fail without corrupting socket state.

Completion evidence: advanced typed IPv4/IPv6/common options, IPv4 connected
operation, packet membership/auxdata/statistics/fanout, classic/eBPF attachment,
and a 4096-byte reserved-tuple-aware raw option adapter are implemented. Filter
replacement, lock behavior, caller-fd retention, VLAN auxdata, and namespace
traffic pass. Thirty-five Rust tests, seven ordinary Node tests, and six
isolated namespace tests pass. A general descriptor export was deliberately not
added. See the [Phase 8 report](15-phase-8-report.md).

## Phase 9 — Batching and high-throughput packet paths

Status: complete (2026-07-12)

Deliverables:

- add bounded `sendmmsg`/`recvmmsg` APIs with partial-success accounting and no
  dependence on the defective blocking `recvmmsg` timeout behavior;
- add per-environment performance and fairness benchmarks for copies,
  completions, batching, control parsing, and multiple hot sockets;
- implement `PACKET_MMAP` TPACKET_V3 receive rings with explicit copied frame
  leases, alignment validation, status transitions, bounded mapped memory, and
  close behavior; add transmit rings only if they outperform the safer measured
  `sendmmsg` path under a separately reviewed writable-frame contract;
- add packet fanout/ring stress tests and document driver/kernel limitations;
- evaluate AF_XDP only after packet rings, ownership, and benchmark goals are
  stable; it is not part of the initial release baseline.

Exit gate: batch and ring APIs demonstrate a measured benefit, cannot expose a
frame after lease release, remain fair under load, and pass long-running leak
and teardown stress tests.

Completion evidence: bounded `sendmmsg`/`recvmmsg` APIs and a receive-only
TPACKET_V3 ring are implemented through the fair reactor. Frame bytes never
alias mutable mmap storage and become inaccessible after lease release. A
release namespace benchmark measured a 2.81× batch-send speedup and 0.01 ms
two-hot-socket completion skew. Thirty-seven Rust tests, seven ordinary Node
tests, and six isolated namespace tests pass, including 16-frame ring stress,
cancellation, release invalidation, and close cleanup. A separate 256-cycle ring
teardown run retained the exact descriptor baseline with a 745,472-byte RSS
delta. TX mmap was evaluated and deferred because it needs a separate
writable-frame publication contract and has not demonstrated benefit over the
measured safe batch path. See the [Phase 9 report](16-phase-9-report.md).

## Phase 10 — Hardening, compatibility, and distribution

Status: implementation complete; AArch64 publication gate pending (2026-07-12)

Deliverables:

- fuzz every address, header, option, cmsg, batch, and ring parser/serializer;
- run native sanitizers, fd/memory leak tests, cancellation/close stress,
  syscall fault injection, and concurrency model tests where tools apply;
- test minimum/current supported Node releases and both x86-64/AArch64 glibc
  targets; document kernel- and hardware-dependent skips;
- complete dependency, license, advisory, and generated-artifact provenance
  review;
- benchmark release builds and freeze documented queue/allocation defaults;
- build reproducible npm-hosted prebuilt target packages without
  installation-time downloads, while retaining a documented source build;
- remove `private`, select the first semver version, publish a changelog and
  supported-feature table, and verify install/failure/capability guidance from a
  clean consumer project.

Exit gate: release artifacts are reproducible for the declared matrix, package
contents are intentional, all release-blocking safety gates pass, and the
published capability table distinguishes implemented, unsupported, privileged,
kernel-dependent, and hardware-dependent behavior.

Implementation evidence: hardening/release workflows, an independently locked
syscall-free fuzz target, ASan/TSan runs, advisory/license policy, frozen
limits, split target packages, provenance, clean-consumer testing, and
clean-build reproducibility are implemented. All local x86-64 gates pass. Native
AArch64 is a blocking CI/publication gate and has not been represented as
locally tested. See the [Phase 10 report](17-phase-10-report.md).

## Phase 11 — Event-driven receive adapter

Status: implementation complete (2026-07-13)

Purpose: add a familiar Node `EventEmitter` receive style as an optional,
zero-dependency TypeScript layer over the complete promise-oriented `RawSocket`
API. The exact contract is frozen in the
[Phase 11 plan](19-phase-11-event-api-plan.md).

Deliverables:

- export a typed `RawSocketEventEmitter` that wraps an open `RawSocket` and uses
  Node's built-in `node:events`;
- preserve every existing low-level method and avoid new Rust/N-API work unless
  a newly documented native requirement is proven;
- emit `message`, `error`, and exactly-once `close` events with explicit start,
  awaitable pause, resume, detach, and close lifecycle operations;
- keep one bounded `receiveMessage()` in flight per normal or error-queue event
  source, retain a fulfilled-but-undispatched result through lifecycle
  boundaries, and prohibit `peek` in an automatically rearmed loop;
- arbitrate normal/error receive lanes so direct, batch, ring, and event
  consumers cannot silently split the same traffic;
- make pending-operation finalizers composable before adding claims, and treat
  each packet-ring attempt/ring-frame receive as socket-wide relative to both
  event lanes;
- use transactional runtime-authenticated claims/observers, explicit
  detach/close lifetime rather than GC release, and terminalize the wrapped
  socket on reactor loss;
- document synchronous EventEmitter delivery, async-listener limitations, kernel
  buffering/drop behavior, and safe retained message ownership;
- add deterministic controller tests, unprivileged boundary/race tests, isolated
  multi-message family tests, Worker teardown, and long-running state stress;
- refresh the release candidate and provenance after the public API changes.

Exit gate: the promise API remains compatible; the event adapter has no
unbounded queue or runtime dependency; pause/detach/close have proven race
boundaries; conflicting receivers fail deterministically; repeated IPv4, IPv6,
packet, and error-queue events pass; and all ordinary, privileged, stress,
consumer, and release gates are recorded.

Implementation evidence: the native-free controller, composable pending
finalizers, runtime-authenticated lane claims, close observers, public typed
EventEmitter, declaration fixture, listener subprocess probes, genuine
multi-message namespace coverage, Worker teardown, and repeat-cycle fd/RSS
stress are implemented. No Rust, syscall, N-API, unsafe-code, or production
dependency change was required. See the [Phase 11 report](21-phase-11-report.md)
and the corrective [implementation audit](22-phase-11-implementation-audit.md).

## Cross-phase rule

Do not expand breadth while a known descriptor-lifetime, buffer-lifetime,
event-loop blocking, exactly-once settlement, fairness, panic-boundary, or
teardown correctness issue remains unresolved in the preceding slice. A phase
may be split into reviewable sub-slices, but its exit gate remains blocking for
dependent phases.
