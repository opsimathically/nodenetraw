# AGENTS.md

This file is the durable working context for contributors and coding agents in
this repository. Read it before changing the project. Keep it current when a
decision changes the commands, architecture, safety rules, or repository layout.

## Project purpose

`nodenet` is a monorepo for Linux-native Node.js networking packages.
`@opsimathically/nodenetraw` is the implemented, Linux-only native module for
low-level raw socket capabilities. TypeScript is its public Node-facing
environment. Rust implements native operations and crosses into Node through
N-API. `@opsimathically/nodenetscanner` is a private Phase 23 preview with an
initial TypeScript control API and Rust-owned portable Linux scan data plane.
Its shared protocol, deterministic scan-engine, and read-only network-context
foundations are implemented as internal crates.

The project prioritizes:

- memory and resource safety at the JavaScript/Rust/kernel boundaries;
- a low-level API that preserves useful Linux socket functionality;
- predictable lifecycle, error, and concurrency behavior;
- a small production dependency and binary footprint;
- explicit documentation of privileged Linux behavior.

Authentication, authorization between application users, and higher-level
protocol policy are outside the library's scope. Safe handling of untrusted
packet bytes and invalid arguments is in scope.

## Current phase

Phases 1 through 11 are complete. `RawSocket` exposes bounded IPv4/IPv6 raw and
Linux packet raw/cooked message I/O, scoped and link addresses, typed metadata,
AbortSignal cancellation, stable errors, and idempotent close. One
environment-scoped reactor fairly serializes native work. Advanced typed and
bounded opaque options, connected IPv4/IPv6 operation, packet membership,
auxdata/statistics/fanout, and classic/eBPF filter attachment are implemented.
Bounded `sendmmsg`/`recvmmsg`, measured fairness benchmarks, and receive-only
TPACKET_V3 rings with copied, explicitly releasable frame leases are included.
Phase 10 adds fuzz/sanitizer/advisory gates, native x86-64/AArch64 CI, and
rehearsed target packages. Nothing is published automatically. The public
TypeScript surface exports a focused set of Linux-compatible `IPPROTO_*` and
`ETH_P_*` constants while retaining numeric protocols for extensibility. The
post-Phase-10 release-readiness audit added lossless bounded completion
backpressure, close/admission ordering, malformed-ring recovery, and an enforced
glibc artifact baseline. Phase 11 adds the zero-dependency typed
`RawSocketEventEmitter` over `receiveMessage()` with one receive per source,
explicit start, awaitable pause/detach, receive-lane ownership,
fulfilled-before-boundary dispatch, explicit attachment lifetime, and
exactly-once close. Phase 12 adds pure bounded ICMPv4 checksum and Echo codecs,
structured compatible/canonical parsing and validation, Linux raw-receive
extraction, Echo correlation, one-operation socket helpers, and a captured
readonly `RawSocket.protocol` getter without changing Rust or adding a runtime
dependency. Phase 11's authoritative contract, feasibility audit, and completion
report are `ai_documentation/19-phase-11-event-api-plan.md`,
`ai_documentation/20-phase-11-plan-review.md`, and
`ai_documentation/21-phase-11-report.md`. The adversarial post-implementation
review and its scheduler/quiescence corrections are recorded in
`ai_documentation/22-phase-11-implementation-audit.md`. Native AArch64 remains
untested until its runner passes. Phase 12 implementation and its x86-64
ordinary, privileged, stress, consumer, artifact, and reproducibility gates are
complete. Phase 13 adds bounded ICMPv4 diagnostic-error codecs, quoted IPv4
validation and Echo correlation, RFC 1191 MTU handling, and RFC 4884 compliant
plus explicit legacy extension framing without automatic network policy. Phase
14 adds bounded Router Discovery, Timestamp, and deprecated Address Mask codecs,
timestamp/mask inspection, and enforced Router Discovery multicast destination
and per-message TTL without automatic host policy. Phase 15 adds conventional
increasing-TTL ICMP Echo traceroute with owned probes, pure response
classification, monotonic deadlines, compact bounded results, and deterministic
normal-lane cleanup. The package is now the unpublished `0.1.0-rc.6` candidate.
The authoritative Phase 12–15 scope and gates are in
`ai_documentation/23-icmp-and-traceroute-plan.md`; the closed preimplementation
audit is `ai_documentation/24-icmp-plan-review.md`. Completion evidence is in
`ai_documentation/25-phase-12-report.md` through
`ai_documentation/28-phase-15-report.md`. The post-implementation hostile-input,
policy-snapshot, callback-quiescence, and release-health review is
`ai_documentation/29-phase-12-15-implementation-audit.md`.

The repository is now the private `nodenet` npm/Cargo workspace governed by
D-030. Existing raw-package source and release tooling live under
`packages/nodenetraw`, its native crate lives under `crates/nodenetraw-native`,
and the scanner package remains a private non-publishable preview while its
internal Rust foundations and native addon live under `crates/`. The structural
migration did not change the public API or release version. D-031 accepts the
next evolution. Phase 18 is complete: scanner-relevant TCP, UDP, ICMPv4, ICMPv6,
NDP, quoted packet, keyed correlation, evidence-strength, and reuse-grace
primitives now live in the protocol crate. Phases 19–20 complete read-only
network context; Phase 21 completes the deterministic scheduler and Phase 22
adds the portable live scanner; Phase 23 adds scanner batching and Phase 24 adds
release hardening; Phase 25 is an evidence gate and Phase 26 is conditional.
Phase 16 is complete: `crates/nodenet-protocols` now owns the bounded protocol
types, strict/explicit quote parser boundary, transactional packet output,
independent fixtures, fuzz targets, and allocation baselines. Phase 17 is
complete: the protocol crate now owns bounded Ethernet/VLAN, ARP, IPv4, IPv6
extension/fragment, upper-layer disposition, checksum, and reusable
frame-template codecs. The authoritative plan is
`ai_documentation/31-network-and-scanner-evolution-plan.md`. Its
preimplementation audit is closed in
`ai_documentation/32-network-evolution-plan-review.md`: Phase 16 has no open
design blocker, and the review corrections are part of the accepted contract.
Completion evidence is in `ai_documentation/33-phase-16-report.md` through
`ai_documentation/40-phase-23-report.md`; D-032 records the implemented
correlation encoding, D-033 records the route-netlink dependency and read-only
descriptor boundary, and D-034 records kernel-selected egress plus the bounded
context owner. D-035 records the deterministic scheduler boundaries. Phase 21 is
complete: compact target products, seeded scheduling, virtual timing, fairness,
explicit evidence classification, bounded lifecycle draining, and lossless
result reservation are implemented without syscalls or unsafe code. Phase 22 is
complete: `crates/nodenetscanner-native` owns one bounded runtime per Node
environment, read-only context, raw/packet descriptors, packet buffers, timers,
secrets, and four portable live sessions. The private scanner package exposes
explicit plans, context inspection, pull batches, lifecycle, summaries, and
structured errors for live ARP/NDP, ICMPv4/v6 Echo, TCP SYN, and UDP scans.
Ordinary gates and the live dual-stack namespace/VLAN matrix pass locally.
Native AArch64 cross-compilation passes; native AArch64 execution remains a
publication gate. Phase 23 is complete under D-037: scanner results cross N-API
as versioned sealed columns rather than per-result objects, TypeScript provides
lazy rows over transferable Node-owned storage, pulls support worker-ordered
AbortSignal cancellation, and exact coalesced progress reports bounded
high/low-water backpressure. The optional Node event layer emits batches only.

The current source of planning truth is
[`ai_documentation/00-index.md`](ai_documentation/00-index.md).

## Non-negotiable engineering constraints

- Target Linux only. Do not add silent non-Linux fallbacks.
- Support Node.js 26 and later. Set the package engine floor to `>=26.0.0` and
  compile against stable Node-API 10, not experimental Node-API features.
- Use the latest stable Rust release, pinned exactly in the repository and
  updated intentionally when a new stable release ships. The initial pin is Rust
  1.97.0 with Rust 2024 edition.
- The initial supported native targets are 64-bit glibc Linux on x86-64 and
  AArch64, with Linux kernel 4.18+ and glibc 2.28+. musl and other architectures
  are unsupported until separately accepted and tested.
- Keep TypeScript strict and make the generated JavaScript/API boundary clear.
- Rust owns native socket handles and native allocation lifetimes.
- Treat all JavaScript values, packet bytes, kernel results, and asynchronous
  callbacks as untrusted boundary data.
- Avoid `unsafe` Rust where a safe alternative is practical. Every required
  `unsafe` block must be small, locally justified with a `SAFETY:` comment, and
  covered by focused tests or an explicitly documented invariant.
- Never allow a Rust panic to unwind across N-API/FFI.
- Make file-descriptor ownership unambiguous. Close must be idempotent at the
  public boundary, and no operation may use a descriptor after ownership has
  ended.
- Do not perform blocking socket I/O on the Node.js event-loop thread.
- Apply explicit bounds and checked conversions for lengths, offsets, integer
  widths, and socket option values.
- Preserve Linux errors in a stable Node-facing error shape; do not discard
  `errno` or the failed operation's context.
- Add dependencies only when their safety, maintenance, and implementation value
  exceeds the cost of another supply-chain and maintenance surface.

## Accepted architectural choices

- Use npm and commit `package-lock.json`; do not require a second package
  manager.
- Publish an ESM-only public package. A small internal CommonJS loader may use
  `createRequire()` to load the `.node` addon because native addon loading is an
  implementation detail, not a second public module format.
- Use napi-rs v3 with only required crate features and Node-API 10 enabled.
- Use rustix with only `std`, `event`, `fs`, and `net` features for safe Linux
  socket, descriptor, epoll, and eventfd calls. Do not bypass it with raw libc
  calls without a recorded safety justification.
- Exact-pinned nix 0.31.3 with default features disabled and only `socket`,
  `uio`, and `net` for safe typed message, ancillary, address, and missing
  sockopt support. Keep rustix for fd ownership and the reactor. D-020 covers
  immediate ownership/close of unexpected `SCM_RIGHTS`; D-022 covers the two
  fixed-size `sockaddr_ll` bind/send sites required because the safe crates
  expose no packet-address constructor.
- D-023 governs the reviewed advanced Linux adapter: opaque option values are
  initialized owned copies capped at 4096 bytes; ownership-sensitive tuples are
  reserved for typed APIs; classic BPF is capped at 4096 instructions; eBPF
  attachment duplicates but never consumes the caller fd. Do not weaken its
  reserved-option table or add general fd export without a new decision.
- D-024 governs batches and rings: 64 messages and 1 MiB per batch, 64 MiB per
  ring, 128 MiB of rings per environment, checked TPACKET_V3 traversal, and no
  mmap-backed Buffer crossing N-API. TX mmap remains deferred until a reviewed
  writable-frame contract beats the measured `sendmmsg` path.
- Use Node's built-in test runner.
- Keep source builds supported. Prebuilt GNU/Linux artifacts use a loader-only
  root package and exact-version x86-64/AArch64 target packages with no install
  scripts or download hooks (D-025). Optimized artifacts use napi-rs's pinned
  GNU cross toolchain and must pass the ELF architecture/glibc gate (D-027).
- Implement waiting socket I/O with nonblocking descriptors and one bounded,
  environment-scoped Linux `epoll` reactor woken by `eventfd`; do not consume
  libuv worker threads with indefinitely blocking receives.
- Deliver Node completions losslessly through a bounded blocking thread-safe
  callback queue. Backpressure may pause the reactor only while JavaScript is
  unable to drain completions; it must never drop a promise settlement (D-026).
- The first network slice is IPv4 raw IP sockets: `AF_INET`/`SOCK_RAW` with an
  explicit protocol, asynchronous byte send/receive, and explicit close.
- The long-term baseline is IPv4, IPv6, and `AF_PACKET`, message/control/error
  semantics, typed plus bounded extensible options, filters, batches, measured
  packet rings, and hardened x86-64/AArch64 distribution. See
  `ai_documentation/11-full-capability-plan.md` for exact sequencing.
- D-029 governs the planned protocol utility layer: implement the enumerated
  ICMPv4 codecs and traceroute composition in strict TypeScript with no runtime
  dependency or new native I/O engine. Codecs use owned bounded results and
  structured hostile-input failures, compatible receive parsing, and canonical
  validation; socket helpers preserve `RawSocket` ownership and receive lanes.
  RFC 4884 legacy framing is explicit opt-in. ICMPv6 codecs are a separate
  future design.
- D-031 governs scanner evolution. `nodenetraw` remains policy-free;
  `nodenetscanner` owns its descriptors and native packet hot path without a
  JavaScript dependency on the raw package. Planned non-published crates are
  `nodenet-protocols`, `nodenet-linux-context`, and `nodenetscanner-engine`,
  linked into `nodenetscanner-native`. Network context is read-only and
  generation-tagged. The portable engine must be release-capable before Phase 25
  may measure and select one optional extreme backend. Phase 26 cannot begin
  without a positive recorded evidence decision.
- D-036 governs the Phase 22 scanner boundary: one joined environment-owned
  runtime, no descriptor or packet storage across N-API, ordinary
  `AF_PACKET`/raw-IP transports, session-local neighbor learning, structured
  terminal failures, and bounded pull batches. Context generation changes
  invalidate joined probes; terminal wire-correlation state is pruned after its
  finite late-response grace period rather than growing with the total scan.

## Expected repository shape

The workspace uses this separation:

- root private npm workspace orchestration, Cargo workspace/lock, toolchain,
  ESLint, and Prettier configuration;
- `packages/nodenetraw/` for the published package's TypeScript, tests,
  package-specific release tooling, README, and changelog;
- `crates/nodenetraw-native/` for the Rust N-API crate and its independently
  locked fuzz project;
- `packages/nodenetscanner/` for the private, non-publishable Phase 22 scanner
  TypeScript API, tests, and documentation;
- implemented `crates/nodenet-protocols/`, `crates/nodenet-linux-context/`, and
  `crates/nodenetscanner-engine/` as non-published, N-API-free Rust libraries;
- `crates/nodenetscanner-native/` for the scanner's environment runtime, Linux
  sockets, packet path, and N-API adapter;
- `.github/workflows/ci.yml` for the unprivileged x86-64 quality gate;
- Rust-local unit tests for native invariants;
- `ai_documentation/` for plans, decisions, risks, and progress context.

Use npm workspaces rather than `npm link`. Keep one root `package-lock.json` and
one root Cargo workspace lock. Public packages version independently; internal
shared Rust crates must be `publish = false` and cross package boundaries only
at compile time. Do not make `nodenetraw` depend on scanner policy or make the
scanner call `nodenetraw` through JavaScript/borrow its descriptors. Do not move
raw reactor internals into a shared crate without a demonstrated shared contract
and regression/benchmark evidence. The private root and package source trees
both refuse direct publication; publish only inspected output under a package's
`release/stage` directory.

Do not commit generated package output, native build artifacts, coverage data,
or dependency directories.

## Working practices

- Keep the JavaScript layer thin. Native ownership and syscall semantics belong
  in Rust; ergonomic TypeScript types and stable exports belong in TypeScript.
- Phase 11 event reception must remain an adapter over `receiveMessage()`: do
  not create a parallel native receive loop, add automatic `peek`, or introduce
  an unbounded JavaScript queue.
- Treat a fulfilled message awaiting dispatch as part of the active event turn;
  use one generation-checked scheduler, transactional claims/observers, distinct
  ring-operation tokens, and explicit detach/close rather than GC claim release.
- For Phases 12 through 15, distinguish standalone ICMP bytes from Linux IPv4
  raw receive frames, copy variable parsed data, check every offset/count before
  slicing, and never apply Redirect, Router Advertisement, Timestamp, or Address
  Mask data to host configuration.
- Traceroute must use monotonic deadlines, strong direct/quoted probe matching,
  bounded timers/probes/payload/results/in-flight work, cleanup-before-reject,
  and the existing normal receive lane.
- Follow the Phase 16–26 dependency order. Protocol and scheduler crates stay
  syscall-free where planned; all target products, parser allocations, netlink
  dumps, active windows, correlation retention, result queues, batches, and
  native memory are independently bounded.
- Treat evidence strength by protocol: TCP acknowledgment and token-bearing ICMP
  may be strong; ARP/NDP, direct UDP, and short quotes are weaker
  unauthenticated evidence. Never reuse a source port/identifier while an
  outstanding or grace record could make correlation ambiguous, and never use
  the reproducible scheduling seed as a correlation secret.
- Scanner route context may issue only read/query/subscribe `NETLINK_ROUTE`
  operations. Never mutate links, addresses, routes, rules, neighbors, firewall
  state, qdiscs, namespaces, sysctls, or BPF state in portable phases.
- The first portable link matrix is Ethernet II with up to two VLAN tags and
  loopback/local raw IP. Reject other link types and encapsulation explicitly.
  Never call `setns()`; tests launch Node in the desired namespace.
- Keep raw packets in Rust by default. JavaScript configures compact plans and
  consumes sealed bounded result batches. Never expose packet-ring or UMEM
  storage through N-API.
- Do not begin an extreme backend before Phase 24 is release-capable and Phase
  25 records that one backend meets its performance/accuracy threshold.
- Prefer additive, reviewable API slices over attempting every raw socket
  feature in one change.
- Pair each exported native operation with argument validation, lifecycle
  behavior, error mapping, and tests.
- Treat cancellation, readiness, close, completion delivery, and environment
  shutdown as one exactly-once native settlement problem.
- Bound data bytes, control bytes, cmsg count, per-socket/global operations,
  completion delivery, batches, and any future mapped memory independently.
- Apply finite command and readiness work/byte budgets so a hot socket cannot
  starve another socket or a close/cancel command.
- Test without requiring root where possible. Privileged integration tests must
  be separately marked and opt-in.
- Never make CI broadly privileged merely to run raw-socket tests.
- Update the relevant plan/status document when a phase begins or completes.
- Record consequential choices in `ai_documentation/05-decision-log.md`; do not
  silently turn an open question into project policy.
- Preserve user changes in a dirty worktree and keep changes scoped to the
  active task.

## Verification expectations

Install reproducibly with `npm ci`. The supported commands are:

- `npm run build`: native development build followed by TypeScript compilation.
- `npm run build:native:release`: optimized, stripped GNU artifact build using
  napi-rs's pinned compatibility cross toolchain.
- `npm run typecheck`: strict TypeScript check without output.
- `npm run lint` / `npm run lint:fix`: ESLint verification or safe fixes.
- `npm run format` / `npm run format:check`: Prettier write or verification.
- `npm run rust:fmt`: Rust formatting verification.
- `npm run rust:clippy`: all-target Clippy with warnings denied.
- `npm run rust:test`: Rust unit tests.
- `npm test`: build and run unprivileged Node boundary tests.
- `sudo npm run test:privileged`: build as the invoking repository owner, then
  run the successful raw-packet suite as root inside a disposable network
  namespace. The harness locates that user's Node 26 and rustup installations
  and must not leave root-owned build output.
- `npm run test:namespace`: build and run the privileged tests in an isolated
  unprivileged user/network namespace where AppArmor and the host permit it.
- `npm run benchmark:namespace`: optimized isolated batch/copy/control/fairness
  measurements; informative rather than a timing-sensitive CI gate.
- `npm run test:phase9:stress`: 256 isolated packet-ring configure/cancel/close
  cycles with descriptor and bounded RSS checks.
- `sudo npm run test:phase11:stress`: 256 isolated event-adapter socket cycles,
  each with repeated start/pause/resume and alternating detach/close, plus
  descriptor and bounded RSS checks. The build runs as the repository owner.
- `sudo npm run test:phase15:stress`: 256 isolated traceroute cancellation and
  normal-lane reuse cycles with descriptor and bounded RSS checks. The build
  runs as the repository owner.
- `npm run test:phase20:namespace`: policy routing, gateway/on-link, ECMP,
  neighbor, link-down, and concurrent notification/query behavior in a
  disposable topology.
- `npm run test:phase20:stress`: 1,024 targeted lookups and repeated
  asynchronous context-owner lifecycle with descriptor and bounded RSS checks.
- `npm run test:phase21`: privilege-free deterministic scanner-engine tests with
  virtual time, scripted collaborators, million-scale scheduling/timing,
  lifecycle boundaries, and bounded-state assertions.
- `npm run test:phase22`: scanner native/unit, strict TypeScript declaration,
  capability-free context/API, resource-limit, and structured permission tests.
- `npm run test:phase22:namespace`: live loopback plus dual-stack veth/VLAN
  ARP/NDP, ICMPv4/v6 Echo, TCP SYN, and UDP open/closed tests. The wrapper uses
  an unprivileged user namespace when available and supports `sudo` otherwise.
- `npm run test:phase23`: compact schema, lazy decoding, mutation/transfer,
  AbortSignal, progress, event-adapter, native unit, and ordinary boundary
  tests.
- `npm run test:phase23:namespace`: Phase 23 batches and progress over the live
  loopback plus dual-stack veth/VLAN scanner matrix.
- `npm run hardening:verify`: release version, platform, license, dependency,
  target-manifest, and production advisory policy.
- `npm run fuzz`: one minute of syscall-free parser/serializer libFuzzer work;
  requires nightly Rust and `cargo-fuzz`.
- `npm run release:consumer-test`: assemble and install current-architecture
  tarballs into a clean temporary consumer with install scripts disabled.
- `npm run release:reproducibility`: compare two optimized native build hashes.
- `npm run release:verify-artifact`: verify the current native ELF architecture
  and enforce that its required glibc symbols do not exceed 2.28.
- `npm run ci`: the complete current unprivileged gate.

On Linux hosts that permit unprivileged namespaces, the privileged suite can be
isolated without host-level privilege:

```sh
unshare --user --map-root-user --net sh -c \
  'ip link set lo up && NODENETRAW_PRIVILEGED_TESTS=1 node --test packages/nodenetraw/test/privileged.test.mjs'
```

Do not report a change as verified without naming which gates actually ran.

## Documentation map

- `README.md`: concise workspace overview and package map.
- `packages/nodenetraw/README.md`: complete human-facing raw-package guide.
- `ai_documentation/00-index.md`: planning index and current status.
- `ai_documentation/01-scope-and-requirements.md`: goals, boundaries, and
  success criteria.
- `ai_documentation/02-architecture.md`: planned component and ownership model.
- `ai_documentation/03-safety-and-security.md`: safety invariants and threat
  analysis.
- `ai_documentation/04-roadmap.md`: phased delivery plan and gates.
- `ai_documentation/05-decision-log.md`: accepted decisions and remaining design
  details.
- `ai_documentation/06-tooling-and-testing.md`: bootstrap and verification
  strategy.
- `ai_documentation/07-phase-1-report.md`: completed bootstrap contents and
  verification record.
- `ai_documentation/08-phase-2-report.md`: lifecycle core invariants and
  verification record.
- `ai_documentation/09-phase-3-report.md`: first public API, reactor invariants,
  and privileged verification record.
- `ai_documentation/10-phase-4-report.md`: bind, typed option, metadata, and
  truncation verification record.
- `ai_documentation/11-full-capability-plan.md`: target capability matrix,
  expanded phases, and the frozen Phase 5 implementation contract.
- `ai_documentation/12-phase-5-report.md`: message I/O, cancellation, fairness,
  ancillary data, and verification record.
- `ai_documentation/13-phase-6-report.md`: IPv6 family, scoped-address,
  ancillary, option, and ICMPv6 verification record.
- `ai_documentation/14-phase-7-report.md`: packet raw/cooked, link-address,
  veth, and safety-adapter verification record.
- `ai_documentation/15-phase-8-report.md`: advanced option/filter verification.
- `ai_documentation/16-phase-9-report.md`: batch/ring benchmarks and stress.
- `ai_documentation/17-phase-10-report.md`: release hardening and distribution.
- `ai_documentation/18-release-readiness-audit.md`: post-Phase-10 correctness
  and artifact audit.
- `ai_documentation/19-phase-11-event-api-plan.md`: frozen event-adapter API,
  lifecycle, ownership, testing, and release contract.
- `ai_documentation/20-phase-11-plan-review.md`: implementation-feasibility and
  completeness audit for Phase 11.
- `ai_documentation/21-phase-11-report.md`: event adapter implementation and
  verification record.
- `ai_documentation/22-phase-11-implementation-audit.md`: post-implementation
  race, boundary, test-coverage, and release-health audit.
- `ai_documentation/23-icmp-and-traceroute-plan.md`: accepted Phase 12–15 scope,
  wire contracts, APIs, safety bounds, tests, and exit gates.
- `ai_documentation/24-icmp-plan-review.md`: closed preimplementation protocol,
  API, lifecycle, resource-bound, and test-topology review for Phases 12–15.
- `ai_documentation/25-phase-12-report.md`: ICMPv4 foundation/Echo
  implementation, safety, API, and verification record.
- `ai_documentation/26-phase-13-report.md`: ICMPv4 errors, quoted-datagram
  correlation, RFC 4884 extensions, and verification record.
- `ai_documentation/27-phase-14-report.md`: Router Discovery, Timestamp,
  deprecated Address Mask, multicast send policy, and verification record.
- `ai_documentation/28-phase-15-report.md`: bounded ICMP Echo traceroute,
  correlation, orchestration, routed-topology, cleanup, and verification record.
- `ai_documentation/29-phase-12-15-implementation-audit.md`: post-implementation
  protocol, hostile-input, lifecycle, privileged, stress, packaging, and
  release-health audit.
- `ai_documentation/30-monorepo-migration-report.md`: workspace boundaries,
  migration changes, and verification evidence.
- `ai_documentation/31-network-and-scanner-evolution-plan.md`: accepted Phase
  16–26 protocol, context, scheduler, batching, release, and conditional
  performance-backend contract.
- `ai_documentation/32-network-evolution-plan-review.md`: closed
  preimplementation correctness/readiness audit and corrections for Phases
  16–26.
- `ai_documentation/33-phase-16-report.md`: protocol foundation, dependency,
  allocation, fuzz, and cross-target evidence.
- `ai_documentation/34-phase-17-report.md`: link/internet codec, template,
  boundary, differential, namespace-capture, fuzz, and benchmark evidence.
- `ai_documentation/35-phase-18-report.md`: transport/control codec,
  correlation, hostile-input, fuzz, and dependency evidence.
- `ai_documentation/36-phase-19-report.md`: bounded route-netlink snapshot,
  namespace-oracle, fd/RSS, syscall-trace, and dependency evidence.
- `ai_documentation/37-phase-20-report.md`: kernel route selection, coherent
  refresh, egress planning, and bounded context-owner evidence.
- `ai_documentation/38-phase-21-report.md`: deterministic scanner planning,
  scheduling, classification, lifecycle, and virtual-test evidence.
- `ai_documentation/39-phase-22-report.md`: portable live scanner runtime,
  TypeScript/N-API API, socket-path, namespace-matrix, and verification
  evidence.
- `ai_documentation/40-phase-23-report.md`: compact scanner batches,
  backpressure, progress, abortable pulls, event adapter, and verification
  evidence.
