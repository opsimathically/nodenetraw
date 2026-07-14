# Scope and requirements

## Product statement

The `nodenet` workspace develops independently scoped Linux-native Node.js
networking packages. `nodenetraw` provides applications with a memory-safe,
resource-safe bridge to raw packet networking. TypeScript defines its public
API; Rust owns descriptors, buffers, asynchronous state, and the Linux syscall
boundary through Node-API. `nodenetscanner` is reserved for the accepted future
scanner-specific control/results API and Rust data plane. Its public API has not
started, while the shared syscall-free `nodenet-protocols` codec/correlation
foundation and the read-only `nodenet-linux-context` snapshot, resolution, and
coherent-refresh crate are complete through Phase 20.

The target is practical full capability, not a permanently narrow convenience
wrapper. The library should eventually expose enough typed and bounded
primitives to build protocol implementations, packet capture/injection tools,
diagnostics, routers, and network test systems. It can support ordinary scanner
implementations directly, but scanner scheduling, policy, target generation, and
a high-rate native data plane belong to the separate scanner package.
Performance-sensitive code may be shared between native addons through internal
compile-time Rust crates rather than sending packet hot paths through
JavaScript. Completeness is measured against documented Linux socket
capabilities, not by mirroring every numeric constant into JavaScript.

## Capability baseline

The release-capable baseline must cover:

1. IPv4 `AF_INET`/`SOCK_RAW`, including kernel-built and user-supplied headers.
2. IPv6 `AF_INET6`/`SOCK_RAW`, including scoped addresses and IPv6-specific
   checksum, hop-limit, traffic-class, packet-info, and error semantics.
3. Linux `AF_PACKET` with `SOCK_RAW` and `SOCK_DGRAM`, link-layer addresses,
   interface binding, protocol selection, packet type, VLAN auxiliary data,
   membership, statistics, and fanout.
4. Message-oriented `sendmsg`/`recvmsg` I/O with bounded data and control
   buffers, typed flags, ancillary messages, explicit data/control truncation,
   error-queue access, and software/hardware timestamp representation.
5. Typed common socket options plus a deliberately bounded low-level extension
   mechanism for Linux options that are not yet modeled.
6. Explicit cancellation, close, backpressure, fairness, Worker-environment
   teardown, and stable Linux error reporting.
7. Safe packet filtering and high-throughput paths: classic/eBPF attachment,
   bounded batch I/O, and `PACKET_MMAP` rings where benchmarks justify them.
8. Source and prebuilt distribution for the declared x86-64/AArch64 glibc
   matrix, backed by stress, fuzz, sanitizer, leak, and privileged namespace
   tests.
9. Both explicit promise-oriented receives and an optional Node-style event
   adapter built over the same bounded message and ownership semantics.
10. A zero-dependency ICMPv4 utility layer for the accepted Echo, diagnostic,
    router-discovery, Timestamp, and legacy Address Mask formats, plus bounded
    increasing-TTL Echo traceroute support composed over the raw-socket APIs.

The separate scanner baseline must cover:

1. bounded Rust codecs for Ethernet/VLAN, ARP, IPv4/IPv6, TCP, UDP,
   ICMPv4/ICMPv6, and IPv6 Neighbor Discovery;
2. immutable, generation-tagged Linux link/address/route/rule/neighbor context
   obtained through read-only `NETLINK_ROUTE` operations;
3. compact IPv4/IPv6 target ranges and exclusions, explicit probes and ports,
   deterministic ordering, adaptive timing, fairness, retries, and strong
   response correlation without materializing the full Cartesian product;
4. a portable native scan engine for ARP/NDP link-neighbor, ICMP Echo, TCP SYN,
   and UDP probes whose descriptors and packet hot loop stay in Rust;
5. bounded lossless result batches and lifecycle/progress control across N-API;
6. independent hardening and release gates for the scanner package;
7. an optional higher-performance backend only after the portable package is
   release-capable and measurements satisfy the accepted improvement threshold.

The first portable scanner supports Ethernet II with up to two VLAN tags and
local/loopback IP routes. Other hardware types, tunnels, point-to-point links,
and kernel encapsulation routes fail explicitly until separately accepted. The
scanner is bound to the network namespace in which its descriptors are created;
changing namespaces with `setns()` is not an API. Scan observations are
unauthenticated wire evidence, with protocol-specific correlation strength, not
proof that an application connection can traverse local firewall or host-stack
policy.

The detailed capability matrix and sequencing live in
[the full-capability plan](11-full-capability-plan.md) for `nodenetraw` and the
[network and scanner evolution plan](31-network-and-scanner-evolution-plan.md)
for `nodenetscanner` and its internal Rust crates.

## Functional requirements

- Create, configure, bind, optionally connect, query, and close every supported
  socket family without exposing the owned descriptor accidentally.
- Send and receive arbitrary initialized bytes without unintended
  transformation, while documenting when Linux supplies or removes protocol
  headers.
- Represent every supported address family with a discriminated TypeScript type
  and a checked Rust counterpart; never infer a family from buffer layout.
- Expose per-message addresses, flags, original lengths, ancillary data, and
  extended errors with unknown-but-safe receive control messages preserved as
  bounded owned bytes.
- Allow operation-level cancellation through `AbortSignal` without double
  settlement or closing the socket.
- Provide both one-message primitives and separately bounded batch/streaming
  conveniences. Convenience APIs must be implementable in terms of documented
  lower-level semantics.
- Provide an event-driven receive convenience with explicit start,
  pause/detach/close behavior, deterministic receive ownership, and no unbounded
  adapter queue, while preserving the promise API.
- Provide bounded, owned ICMPv4 construction and structured parsing that keeps
  checksum, structural validity, and semantic policy distinct, plus one-message
  socket helpers that preserve existing receive-lane ownership.
- Provide traceroute probe construction, strong direct/quoted response
  correlation, destination detection, bounded timeouts, and cancellation without
  hiding an unbounded receive loop or global session state.
- Report unsupported family/option/control-message combinations explicitly.
- Preserve the Linux operation, errno number, conventional errno name, and
  useful contextual fields in stable errors.

## Quality requirements

- No memory corruption, use-after-free, double-close, stale-fd reuse, invalid
  N-API access, or panic crossing the native boundary.
- Deterministic explicit cleanup, with finalization only as a fallback.
- Bounded allocation and queueing for data, control messages, batches, rings,
  callbacks, and cancellation state.
- Fair reactor progress across sockets and command types under sustained load.
- Exactly-once completion when cancellation, readiness, close, and environment
  teardown race.
- Checked integer, address, header, cmsg, alignment, and kernel-length
  conversions at both JavaScript and Rust boundaries where applicable.
- Tests for malformed values, unknown control messages, truncation, partial
  batch results, queue saturation, cancellation, repeated close, permission
  failures, syscall failures, and lifecycle races.
- Strict formatting, linting, type checking, Clippy, and reproducible locked
  builds throughout implementation.

## Dependency requirements

The smallest dependency graph is not automatically the safest design. A
dependency is acceptable when it replaces substantial hand-written FFI or
alignment-sensitive parsing and is actively maintained, narrowly configured,
license-compatible, and locked exactly.

- Keep the public JavaScript runtime dependency count at zero unless a future
  requirement cannot reasonably be met with Node built-ins.
- Keep build, lint, formatting, test, and fuzz dependencies development-only.
- Disable unused Rust default features and record every direct native dependency
  in the decision log.
- Prefer maintained safe syscall abstractions over project-owned `unsafe`.
- Permit a small audited Linux FFI module only when safe crates cannot express a
  required capability; it needs an accepted design record and dedicated tests.

## Explicit non-goals

- Windows, macOS, non-Linux Unix, or a pure JavaScript fallback.
- Automatic privilege elevation or capability management.
- Authentication, authorization policy, firewall policy, or deciding which
  packets an application is allowed to create.
- High-level TCP, UDP, HTTP, DNS, routing-protocol, scanner-policy, or general
  packet-decoding APIs in `nodenetraw`. The implemented ICMPv4 diagnostics layer
  is the narrow raw-package exception; future scanner capabilities belong to
  `nodenetscanner`.
- Parsing arbitrary upper-layer protocols in the core package beyond the bounded
  IPv4/ICMP quote metadata required by accepted ICMP and traceroute utilities.
- Network configuration protocols such as rtnetlink, TUN/TAP management, or
  loading eBPF programs in `nodenetraw`. The scanner may use bounded read-only
  `NETLINK_ROUTE` queries and subscriptions internally, but route/link/address/
  neighbor mutation remains out of scope. Loading XDP is considered only by the
  conditional extreme-backend phase after a separate evidence decision.
- Claiming that every kernel-version-, driver-, or hardware-dependent feature is
  available merely because its constant compiled.

## Milestones

The first usable IPv4 milestone was completed in Phases 1 through 4. Phases 5
through 10 completed family-neutral message I/O, IPv6, `AF_PACKET`,
extensibility/filtering, measured performance paths, and release hardening.
Phase 11 completed the separately gated event-driven convenience layer over that
low-level baseline. Phases 12 through 14 implement the ICMPv4 checksum/codec
foundation, Echo utilities, diagnostic errors, quoted-datagram correlation, RFC
4884 extensions, Router Discovery, Timestamp, and deprecated Address Mask
formats. Phase 15 implements conventional bounded ICMP Echo traceroute over the
same socket and event-receive foundation.

Phases 16 through 18 completed the foundation, link/internet, transport/control,
and correlation portions of the internal protocol toolkit. Phases 19 and 20
completed the bounded read-only Linux snapshot, kernel route resolution, and
notification-coherent refresh. Phases 21 and 22 add the deterministic scheduler
and portable live scanner. Phases 23 and 24 freeze scanner batching and make its
first release candidate independently releasable. Phase 25 measures the portable
data plane and selects `no-go` or one justified backend; Phase 26 is conditional
on a positive decision. These phases do not expand `nodenetraw`'s public scope.

## Definition of project success

The raw package is successful when its capability baseline is implemented for
the declared Linux matrix. The scanner package is independently successful when
its portable baseline produces accurate, bounded results through a stable batch
API; unsupported combinations fail predictably; resource, memory, cancellation,
and teardown invariants hold under stress; and its artifacts are reproducible
and documented. An extreme backend is an optimization, not a condition of
scanner success. Breadth without those properties is not completion.
