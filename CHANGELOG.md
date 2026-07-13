# Changelog

All notable changes use Semantic Versioning. This project is not yet stable;
release-candidate APIs may change before `0.1.0`.

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
