# Phase 11 implementation audit

Status: complete; identified defects corrected and regression-tested

Completed: 2026-07-13

## Objective

This post-implementation audit adversarially reviewed Phase 11 against the
frozen API, lifecycle, ownership, listener, memory, test, and release contract.
It inspected the native-free controller, RawSocket integration, pending
finalizers, lane/ring arbitration, declarations, package exports, privileged
behavior, stress results, and human/agent documentation.

The review did not assume that the initial green suite proved every race. It
reconstructed same-turn scheduling and every receive-settlement winner across
pause, detach, close, and external close, then added deterministic tests for the
gaps it found.

## Corrected findings

### A11-1 — A stale scheduled pump could strand same-turn resume

Severity: correctness; high

The first controller used one boolean to represent a queued pump. In the
sequence `start()` → `pause()` → `resume()` before the original pump microtask
ran, `pause()` established its boundary synchronously, but `resume()` saw the
old boolean and did not queue a replacement. The stale task later cleared the
boolean and exited because its generation was invalid, leaving status `running`
with no receive admitted or scheduled.

Correction: queued pumps now carry unique identity tokens. Invalidating a pump
clears its token, allowing immediate replacement. A stale task can detect that
it no longer owns the scheduling slot and cannot clear or interfere with the
replacement. Deterministic controller, genuine privileged socket, and repeated
stress cases now cover the same-turn sequence.

### A11-2 — Non-abort receive failures could overwrite quiescence state

Severity: lifecycle/ownership; high

When cancellation lost to a real receive error during `pause()` or `detach()`,
the first implementation unconditionally installed a new paused boundary. During
pause this replaced and stranded the Promise already returned to the caller.
During detach it changed `detaching` to `paused`, so the detach Promise could
resolve and release its claim while the public status and observer cleanup
remained wrong.

Correction: a pause/error race preserves the existing pause deferred and sets
the public error state before dispatch. A detach/error race retains `detaching`,
dispatches the failure, and completes detach only after that turn. Tests prove
promise identity, event-before-boundary ordering, final `detached` status, and
exactly-once claim/observer release.

### A11-3 — Hostile AbortSignal methods could bypass finalizer cleanup

Severity: defensive boundary/resource safety; medium

The public validator previously accepted an arbitrary AbortSignal-shaped object.
If its `aborted` getter or `addEventListener()` threw after a direct receive
count and pending operation were reserved, the Promise executor could reject
while leaving the pending entry and lane count retained.

Correction: public methods now require a genuine Node `AbortSignal`. Signal
state and listener registration are nevertheless treated as untrusted because a
genuine instance can be proxied or have instance methods overridden. Any
getter/registration failure removes a partially registered listener, centrally
settles all pending finalizers, and rejects with a structured boundary error.
Abort-listener removal remains finalizer-isolated. Privileged tests override
real signal getters and methods, then prove that a new event source can attach
immediately, demonstrating that no pending count or listener cleanup was
stranded.

## Additional test strengthening

The audit added or expanded coverage for:

- fulfilled receive wins before detach and external-close boundaries;
- same-turn `start`/`pause`/`resume` replacement;
- non-abort errors winning pause, detach, and close races;
- direct close-driver throws and claim/observer cleanup faults;
- socket-closed receives and close-outcome-only external termination;
- all transient-state method errors and cached Promise identity, including close
  reentrancy from the close listener;
- listenerless message consumption and continued rearming;
- thrown message, error, and close listeners, monitor-only `error`, default
  rejections, and process-wide `captureRejections` in isolated subprocesses;
- direct normal/error-queue lane independence in both directions;
- malformed-argument and already-aborted precedence while an event claim owns
  the lane;
- public synthetic-close isolation and subsequent library close delivery;
- synchronous detach claim release outside a dispatch turn;
- hostile option getters and real AbortSignal getter/registration/removal
  failures;
- ordered repeated packet-event delivery;
- capability-available execution of all ordinary public boundary tests;
- 256 repeated same-turn scheduling cycles in the event fd/RSS stress gate.

The native-free controller/finalizer suite now measures 98.20% aggregate line,
92.59% branch, and 100% function coverage with Node's built-in coverage. The
remaining controller lines are defensive impossible-state guards and the
secondary scheduler fallback behind the already-tested identity check; they are
not omitted functional paths.

## Final verification

The audited implementation passes on x86-64 Linux with Node 26.4.0, npm 11.17.0,
and Rust 1.97.0:

- `npm run ci`: formatting, strict lint, TypeScript, Rust formatting/Clippy, 38
  Rust tests, built declaration fixture, 36 ordinary Node tests, 11 visibly
  skipped privileged tests, and hardening policy all passed;
- capability-available ordinary tests in a Node 26 container: 34 of 34 passed;
- isolated privileged Node 26 network namespace: 11 of 11 passed, including
  repeated IPv4, IPv6, packet, error-queue, ring, external-close, and Worker
  behavior;
- Phase 11 event stress: 256 sockets, 256 same-turn cycles, 1,024 active
  lifecycle cycles, descriptors 21 before/after, RSS delta 8,257,536 bytes;
- Phase 9 ring regression stress: 256 cycles, descriptors 21 before/after, RSS
  delta 917,504 bytes;
- declaration, ESM, synchronous `require(esm)`, package-subpath, clean-consumer,
  ELF/glibc, and reproducible native build gates remain required and pass in the
  final release rehearsal.

## Health conclusion

No known Phase 11 correctness, resource-lifetime, memory-ownership, API-shape,
or test-coverage defect remains after these corrections. The event adapter still
adds no production dependency, Rust/native operation, unsafe code, unbounded
queue, or borrowed native memory.

The remaining caveats are deliberate contract limits rather than defects: pause
does not stop kernel ingress; async EventEmitter listeners are not awaited;
packet-ring events, streams, async iteration, and `ref()`/`unref()` are future
designs. Native AArch64 execution remains untested and is still the only
declared publication gate.
