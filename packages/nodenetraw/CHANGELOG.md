# Changelog

All notable changes use Semantic Versioning. This project is not yet stable;
release-candidate APIs may change before `0.1.0`.

## 0.1.0-rc.6 - 2026-07-13

- Add deterministic owned TTL-limited Echo probe construction and pure
  classification of direct Echo Replies and strongly or explicitly weakly
  correlated ICMPv4 diagnostics with monotonic `bigint` RTTs.
- Add bounded `traceIcmpRoute()` orchestration over a caller-owned dedicated
  ICMP socket, with per-message TTL, one internal normal-lane event claim,
  deterministic result ordering, compact retention, and no DNS or route policy.
- Bound hops, probes, active work, token/payload bytes, probe and overall
  deadlines, timers, and retained results; exact deadline equality is a timeout.
- Distinguish destination, unreachable, maximum-hop, overall-timeout, per-probe
  timeout, cancellation, send/receive failure, socket close, and callback
  failure while detaching before resolve or reject.
- Add fake-clock/fake-driver race coverage for loss, reordering, late and
  unrelated responses, weak historical quotes, cancellation, callback and detach
  failure, plus declaration and runtime-bound tests.
- Add a disposable source/router/destination namespace topology proving TTL 1
  intermediate discovery, TTL 2 destination detection, unreachable handling,
  silent probes, lane conflicts, and caller-socket reuse.
- Harden all ICMP byte boundaries against shadowed typed-array lengths and bound
  forged traceroute extension summaries to the RFC 4884 construction ceiling.
- Snapshot ICMP send destinations, flags, and control messages before Router
  Discovery policy checks so stateful getters cannot change the transmitted TTL,
  and stop progress callbacks after their first recorded failure.
- Keep conventional traceroute in strict TypeScript with zero runtime
  dependencies and no deprecated ICMP type-30, native I/O, hidden global state,
  DNS lookup, or retained raw-packet history.
- Move development into the private `nodenet` npm/Cargo monorepo while
  preserving the package API, version, zero-runtime-dependency contract,
  architecture packages, and staged-publication safeguards.

## 0.1.0-rc.5 - 2026-07-13

- Add canonical Router Solicitation and bounded Router Advertisement
  construction with checked lifetimes, up to 255 addresses, signed preference
  extremes, and standard two-word entries.
- Add compatible Router Discovery parsing that preserves reserved/trailing data,
  forward-compatible entry words, and the minimum preference's not-default
  meaning while retaining code-16 Mobile IP advertisements as unknown-code data.
- Enforce the correct Router Discovery multicast destination and per-message TTL
  1, while leaving interface choice, group membership, broadcast enablement,
  scheduling, and router selection explicit.
- Add Timestamp Request/Reply construction, semantic classification of all
  32-bit timestamp ranges, explicit parsed-request reply composition, and
  compatible preservation of noncanonical request/trailing fields.
- Add deprecated Address Mask Request/Reply construction, owned parsing,
  dotted-decimal/byte preservation, and non-mutating contiguous-prefix
  inspection without applying host configuration.
- Add independent wire, boundary, malformed, ownership, declaration, namespace
  multicast/broadcast, stress, consumer, artifact, and reproducibility coverage
  plus end-user examples.
- Keep Phase 14 in strict TypeScript with no runtime dependency, native I/O
  change, timer, hidden queue, automatic responder, or host configuration
  mutation.

## 0.1.0-rc.4 - 2026-07-13

- Add bounded ICMPv4 Destination Unreachable, Time Exceeded, Parameter Problem,
  and Redirect construction, parsing, validation, and named registered-code
  constants.
- Add checked owned quoted-IPv4 decoding with options, fragmentation, total
  length, header-checksum, leading-payload, and Echo Request evidence handling.
- Add weak/strong quoted Echo correlation and informational Destination
  Unreachable classification without automatic response or routing policy.
- Add RFC 1191 next-hop MTU handling and RFC 4884 compliant extension framing,
  128-byte padding, 576-byte construction ceiling, checksums, bounded unknown
  objects, and explicit legacy framing compatibility.
- Add independent golden, boundary, malformed, ownership, declaration, and
  privileged crafted-packet coverage plus promise/event documentation.
- Align source self-import, release manifests, target packages, and clean
  consumer checks with the scoped `@opsimathically/nodenetraw` package name.
- Keep Phase 13 in strict TypeScript with no runtime dependency, native-code
  change, hidden receive loop, automatic ICMP response, or route mutation.

## 0.1.0-rc.3 - 2026-07-13

- Add zero-dependency, non-mutating RFC 1071 Internet-checksum helpers and a
  bounded ICMPv4 codec foundation.
- Add canonical Echo Request/Reply construction plus structured compatible or
  canonical parsing and validation with explicit checksum policies.
- Preserve unknown ICMP types/codes as owned bytes and distinguish malformed,
  incomplete, invalid-checksum, and non-canonical input.
- Add checked Linux IPv4 raw-receive extraction that cross-validates header
  bytes, native metadata, source address, truncation, fragmentation, and both
  IPv4 and ICMP checksums.
- Add authenticated one-operation ICMP send/receive helpers, per-message TTL,
  strong Echo Reply correlation, and a readonly captured `RawSocket.protocol`.
- Add deterministic golden, boundary, arbitrary-byte, declaration, ownership,
  and privileged promise/event loopback coverage plus end-user examples.
- Keep all Phase 12 protocol logic in strict TypeScript with no runtime
  dependency, Rust change, native I/O engine, or hidden receive queue.

## 0.1.0-rc.2 - 2026-07-13

- Add the typed, zero-runtime-dependency `RawSocketEventEmitter` adapter with
  explicit start, awaitable pause/detach, resume, shared-socket close, and
  exactly-once close events.
- Keep event reception bounded to one `receiveMessage()` per source and retain
  fulfilled messages across pause, detach, and close dispatch boundaries.
- Add independent normal/error-queue receive claims and deterministic
  `ERR_RECEIVER_ACTIVE` conflicts for direct, batch, event, and packet-ring
  consumers.
- Make pending-operation cleanup composable and idempotent so AbortSignal
  listeners, direct-receive counts, and provisional ring claims settle in a
  fixed order on every completion path.
- Add native-free state-machine, listener-exception, fairness, declaration, and
  lifecycle tests plus privileged repeated IPv4, IPv6, packet, error-queue, and
  Worker coverage.
- Document synchronous listener semantics, async rejection behavior, kernel
  buffering, explicit adapter lifetime, and promise-versus-event API selection.
- Correct same-turn pump replacement and non-abort pause/detach race handling;
  harden genuine AbortSignal getter/listener failures so pending claims and
  finalizers cannot be stranded.

## 0.1.0-rc.1 - 2026-07-12

- Add Linux IPv4, IPv6, and raw/cooked packet sockets through Node-API 10.
- Add bounded asynchronous byte, message, ancillary, batch, error-queue, and
  receive-only TPACKET_V3 ring operations.
- Add typed and bounded socket options, packet membership/fanout/statistics,
  classic BPF validation, and compatible eBPF attachment.
- Add deterministic cancellation, idempotent close, bounded fair reactor work,
  copied ring-frame leases, and stable structured Linux errors.
- Add x86-64/AArch64 glibc package layouts, clean-consumer and reproducibility
  checks, fuzz targets, sanitizer/advisory workflows, and release provenance.
- Make bounded Node completion delivery lossless under callback saturation and
  make close wait for every admitted native operation to settle.
- Recover safely from malformed packet-ring blocks and reject truncated or
  oversized kernel link-address metadata.
- Enforce release ELF architecture and glibc compatibility; optimized GNU
  artifacts now use napi-rs's pinned compatibility cross toolchain.
- Reject IP-only disconnect semantics on packet sockets at both public and
  native boundaries.
- Make `sudo npm run test:privileged` build as the invoking repository owner and
  elevate only an isolated network-namespace test process.
- Export a focused zero-dependency set of Linux `IPPROTO_*` and `ETH_P_*`
  constants and use them throughout the public examples.

Nothing has been published by the Phase 10 or Phase 11 implementation itself.
