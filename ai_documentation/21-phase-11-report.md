# Phase 11 implementation report

Status: implementation complete on x86-64; AArch64 remains untested

Completed: 2026-07-13

## Outcome

Phase 11 adds the optional typed `RawSocketEventEmitter` without replacing or
changing the low-level promise API. It is a TypeScript adapter over the existing
bounded `receiveMessage()` operation and Node's built-in `node:events`; no Rust,
syscall, N-API, unsafe-code, or production dependency change was required.

The unpublished package candidate is now `0.1.0-rc.2`. Nothing was published.
The later adversarial implementation review found and corrected three race and
boundary-cleanup gaps; its superseding health evidence is recorded in
`22-phase-11-implementation-audit.md`.

## Implemented surface

The root package now exports:

- `RawSocketEventEmitter`;
- `RawSocketEventEmitterOptions`;
- `RawSocketEventEmitterStatus`;
- `RawSocketEventMap`;
- the `invalidState` and `receiverActive` `RawSocketErrorKind` values, with
  stable `ERR_INVALID_STATE` and `ERR_RECEIVER_ACTIVE` codes.

Construction wraps one successfully opened `RawSocket`, snapshots bounded data
and control capacities, optionally selects the Linux error-queue lane, and does
not consume a packet until explicit `start()`. The adapter exposes synchronous
`start()`/`resume()`, awaitable `pause()`/`detach()`/`close()`, readonly socket
identity and status, and Node-standard `message`, `error`, and `close` events.

## Controller and lifecycle

`src/internal/event-controller.ts` is native-free and generic over an injected
receive driver. Its generation-checked microtask scheduler admits at most one
receive per source. A turn includes admission, settlement, a
fulfilled-but-undispatched message or error, synchronous EventEmitter dispatch,
and final bookkeeping. Rearming occurs only after the dispatch turn completes.

Pause, detach, close, and external close abort an outstanding receive but wait
for cancellation or a winning result. A winning message is dispatched before a
quiescence boundary resolves. Close has precedence over detach, which has
precedence over pause; cached lifecycle promise identity and exactly-once claim,
observer, and close-event cleanup are preserved through reentrant listeners and
listener exceptions.

Nonterminal receive failures pause before emitting `error` and do not retry.
Reactor loss terminalizes the raw socket, emits the receive error when the
environment can still observe it, then emits `close`. Listener throws and async
listener rejections retain Node's ordinary uncaught, unhandled-rejection, and
`captureRejections` channels.

## Ownership and cleanup

A successful-open-only module-private `WeakMap` authenticates wrapped sockets
and provides class-created claimed-receive closures without exposing a token or
driver type. `SocketState` now owns:

- independent normal and error-queue event claims;
- pending direct-receive counts by lane;
- distinct provisional tokens for simultaneous packet-ring configuration;
- pending ring-frame counts and active-ring state;
- strongly retained close observers.

Duplicate or conflicting direct, batch, event, and ring consumers fail
deterministically. Idle and paused sources retain ownership. `detach()` releases
one live lane only after quiescence; socket close releases all claims. Two event
sources may use the independent normal and error-queue lanes, while closing
either closes their shared raw socket and drives each adapter terminal.

The former single pending-operation cleanup callback is replaced by ordered,
composable, idempotent internal finalizers. Central settlement deletes the
pending entry, runs every finalizer with fault isolation, and only then settles
the public continuation. Existing AbortSignal listeners, receive counters, ring
tokens, close cancellation, rejected submission, and environment teardown
therefore share one cleanup rule.

## Bounds and memory safety

Each source retains at most one bounded receive promise, one AbortController,
and one initialized JavaScript-owned `ReceivedMessage` during synchronous
dispatch. There is no adapter message queue, `peek`, configurable concurrency,
borrowed ring memory, or awaited listener work. Retaining a message is explicit
application memory. Pause stops userspace rearming but not Linux ingress or
kernel-buffer drops.

The existing Rust descriptor, buffer, reactor, and N-API ownership model is
unchanged. Phase 11 adds no native allocation or unsafe block.

## Tests added

- Native-free controller tests cover one-operation rearming, stale scheduling,
  fulfilled-before-boundary delivery, method/status contracts, promise identity,
  reentrant resume/detach/close, external close, terminal errors, and two hot
  sources over 2,000 turns.
- Isolated child processes cover synchronous message-listener throws, missing
  `error` listeners, default async rejection, and process-wide rejection capture
  without corrupting the main test runner.
- EventEmitter probes cover listener ordering/removal, meta-events,
  `errorMonitor`, and synthetic-event lifecycle isolation.
- A no-emit consumer fixture checks known event payloads, `unknown` error
  narrowing, inherited custom events, readonly options/socket identity, and
  absence of public claim/driver types.
- Privileged namespace tests cover repeated IPv4, IPv6, and raw/cooked packet
  events; pause/resume/detach/close; normal/error-queue coexistence; direct and
  ring conflicts; simultaneous ring tokens; external/shared close; retained idle
  claims; and cooperative/forced Worker teardown.
- `sudo npm run test:phase11:stress` performs 256 real socket cycles with four
  start/pause/resume transitions each, alternating detach/reattach and close,
  exact descriptor-baseline recovery, and a 32 MiB RSS-growth ceiling.

## Verification record

The following passed locally on x86-64 Linux with Node 26 and Rust 1.97.0:

- `npm run ci`: the complete unprivileged gate passed; the post-implementation
  audit expanded this to 36 ordinary Node tests with 11 privileged tests visibly
  skipped;
- `npm test`: ordinary build, consumer declaration fixture, and Node tests;
- `npm run lint`, `npm run typecheck`, and `npm run format:check`;
- `npm run rust:fmt`, `npm run rust:clippy`, and `npm run rust:test`: 38 Rust
  tests passed;
- `npm run hardening:verify`: zero production npm vulnerabilities and 50
  reviewed Rust packages;
- isolated privileged Node 26 Docker network namespace with only
  `CAP_NET_ADMIN`/`CAP_NET_RAW`: 11 of 11 privileged tests passed;
- Phase 9 ring stress: 256 cycles, descriptors 21 before/after; the latest audit
  run measured an RSS delta of 917,504 bytes;
- Phase 11 event stress: 256 sockets, 256 same-turn cycles, and 1,024 active
  lifecycle cycles, descriptors 21 before/after; the latest audit run measured
  an RSS delta of 8,257,536 bytes;
- `npm run release:consumer-test`: optimized assembly, package install with
  scripts disabled, ESM, synchronous `require(esm)`, event export, and internal
  subpath rejection passed;
- `npm run release:verify-artifact`: x86-64 ELF and glibc ceiling passed, with
  the highest required glibc symbol version at 2.16;
- `npm run release:reproducibility`: two clean optimized builds matched SHA-256
  `e17cc1e114519c5aef618134f3548d9bf5c75e60df7021bd087203d27b0c77c0`.

The privileged command could not be invoked through `sudo` by this automated
session because it cannot provide the user's password. The same built package
and test file were run as root in an isolated Node 26 Docker network namespace;
the host network namespace was not modified. The repository's normal
`sudo npm run test:privileged` and `sudo npm run test:phase11:stress` commands
retain the owner-safe build path for human use.

## Remaining publication gate

Native AArch64 execution remains untested and is still a publication gate. No
cross-build or emulation result is represented as native ARM64 verification.
Streams, async iteration, batch events, packet-ring events, configurable
concurrency, and `ref()`/`unref()` remain separate follow-up decisions rather
than Phase 11 omissions.
