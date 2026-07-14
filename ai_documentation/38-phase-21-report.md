# Phase 21 completion report

Date: 2026-07-14

## Outcome

Phase 21 is complete. The new internal `nodenetscanner-engine` crate implements
the portable scanner's deterministic planning, timing, scheduling,
classification, and lifecycle core without N-API, Linux syscalls, or unsafe
code. It depends only on the already reviewed `nodenet-protocols` crate and does
not change either Node package's public API.

All nondeterministic or environment-owned work enters through injected `Clock`,
`EntropySource`, `ContextResolver`, `ProbeTransport`, and `ResultSink` traits.
The future Phase 22 data plane can therefore adapt real route context and packet
I/O without moving Linux ownership or packet bytes into this state machine.

## Compact targets and checked plans

`TargetSet` normalizes IPv4/IPv6 addresses, CIDRs, inclusive ranges, and
exclusions into sorted, merged, disjoint compact intervals. Include, exclude,
and normalized interval counts have independent 65,536 ceilings. Normalization
rejects reversed or mixed-family ranges, zero/unexpected/missing IPv6 zones,
ranges that cross scoped and unscoped IPv6 regions, empty results, and address
counts above `u64::MAX`. Full-width arithmetic uses checked addition, including
the maximum IPv6 address and a `2^128` CIDR cardinality.

`ScanPlan` validates explicit probe families and ports, rejects duplicates and
incompatible families, and computes target × family × port × attempt products
with checked `u64` arithmetic. `logical_probe_at()` lazily decodes a tuple; no
table proportional to total targets or logical probes is allocated.

`SeededPermutation` provides a constant-memory affine bijection over the exact
logical product. Explicit seeds are reportable reproducibility data. Generated
seeds enter through the entropy trait and are disclosed only when requested.
Correlation tokens and secrets remain independently owned by `nodenet-protocols`
and the future live session.

## Scheduling, timing, and fairness

The scheduler supports ARP, NDP, ICMPv4/v6 Echo, TCP SYN, and UDP logical
probes. One exact fixed-point token bucket charges every successful or
potentially partial frame attempt, including neighbor setup, retransmission, and
optional TCP reset cleanup. Active probes, deferred candidates, late-response
grace records, per-target occupancy, and context-supplied prefix occupancy are
separately bounded. A drive call performs at most 4,096 state transitions.

Adaptive timing uses an integer smoothed RTT/variance estimator and Karn-style
sampling: retransmitted probes report RTT from the latest transmission but do
not update the estimator. Loss uses checked exponential timeout backoff through
the explicit retry ceiling. Fixed timing remains bounded and exposes an
accuracy-tradeoff flag. The standalone token bucket and estimator constructors
also validate their arguments, so bypassing scheduler configuration cannot
create division-by-zero or invalid-clamp panics.

Deferred candidates are examined once per drive round before being requeued.
This prevents one quiet target or saturated prefix from immediately selecting
itself forever and starving later targets. Prefix and target occupancy limits,
seeded order, and Phase 22's required round-robin session driver compose without
an engine-global process singleton.

## Evidence and lifecycle semantics

TCP SYN-ACK is `open`, RST is `closed`, applicable ICMP error is `filtered`, and
silence is `filtered`. UDP response is `open`, ICMP port-unreachable is
`closed`, other applicable error is `filtered`, and silence is `open|filtered`.
ARP/NDP/Echo response is `up`, explicit unreachable evidence is `unreachable`,
and discovery silence remains `unknown` or explicit `down-by-policy` according
to configuration.

Terminal records retain evidence strength, logical attempt, on-wire transmission
count, RTT, route generation, and terminal reason. Exact timeout equality wins
over a response at the same boundary. Bounded grace records count later traffic
without resurrecting or duplicating terminal results. Forged, unrelated,
protocol-inapplicable, non-first-fragment, opaque-protocol, and
insufficient-quote inputs update saturating diagnostics only.

Pause stops new transmission while due retries remain queued; receive and
timeout processing continue. Resume restarts emission. Cancel, overall deadline,
and fatal transport failure stop admission and settle every already reserved
result through the same per-drive work budget. Context invalidation is
generation-selective, uses the same work budget, and blocks new admission until
its drain completes and restoration is explicit. Sink saturation stops admission
before emission. A sink or context collaborator error transactionally preserves
the candidate or active reservation rather than losing partially advanced work.

## Safety and verification evidence

The crate has `#![forbid(unsafe_code)]`, denies Rust and Clippy warnings, owns
no descriptor or thread, and has no syscall/N-API dependency. `cargo tree`
confirms its sole direct dependency is `nodenet-protocols`. Source inspection
finds no panic/unwrap path reachable through a public checked input.

The 26-test Phase 21 suite covers:

- merged ranges, exclusions, maximum-address subtraction, IPv6 zones and scope
  crossings, full-width count failure, checked plan overflow, and a 16,777,216
  target lazy plan with only two active records;
- a 1,000,003-entry permutation bijection plus 1,000,000 exact virtual token
  transitions without wall-clock sleep;
- every supported positive/error/silence classification, adaptive RTT,
  exponential retries, exact deadline equality, reordering, duplication,
  forgery, late evidence, and parser diagnostics;
- target/prefix/protocol/session progress, quiet-target deferral, neighbor
  setup, TCP cleanup, rate charging, pause/resume, backpressure, context pending
  and invalidation, collaborator failure recovery, cancellation, deadline, and
  transport failure;
- 5,000 outstanding deadline and context-invalidation records drained across
  multiple calls without any call exceeding the 4,096-transition budget; and
- identical emissions and results from repeated recorded-stream replay.

Canonical verification commands are:

```sh
npm run test:phase21
cargo clippy -p nodenetscanner-engine --all-targets --locked -- -D warnings
cargo check -p nodenetscanner-engine --target aarch64-unknown-linux-gnu --locked
npm run rust:fmt
npm run rust:clippy
npm run rust:test
npm run ci
```

The x86-64 tests and AArch64 cross-check pass locally. Native AArch64 execution
remains CI-owned and unverified locally, consistent with the repository support
note.

## Scope confirmation and next action

Phase 21 added no raw socket, packet loop, native thread, JavaScript result
batch, N-API export, or public scanner declaration. It performs no live network
operation and cannot require privilege.

Phase 22 is next: implement the portable Linux data plane and initial private
Node scanner API over the completed protocol, read-only context, and scheduler
contracts.
