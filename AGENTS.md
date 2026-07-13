# AGENTS.md

This file is the durable working context for contributors and coding agents in
this repository. Read it before changing the project. Keep it current when a
decision changes the commands, architecture, safety rules, or repository layout.

## Project purpose

`nodenetraw` is a Linux-only Node.js native module intended to expose low-level
raw socket capabilities. TypeScript is the public Node-facing environment. Rust
implements the native operations and crosses into Node through N-API.

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
exactly-once close. The package is now the unpublished `0.1.0-rc.2` candidate.
Its authoritative contract, feasibility audit, and completion report are
`ai_documentation/19-phase-11-event-api-plan.md`,
`ai_documentation/20-phase-11-plan-review.md`, and
`ai_documentation/21-phase-11-report.md`. The adversarial post-implementation
review and its scheduler/quiescence corrections are recorded in
`ai_documentation/22-phase-11-implementation-audit.md`. Native AArch64 remains
untested until its runner passes.

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

## Expected repository shape

The scaffold uses this separation:

- root npm, TypeScript, ESLint, and Prettier configuration;
- `native/` for the Rust N-API crate;
- `src/` for TypeScript entry points, types, and any thin validation layer;
- `test/` for Node-facing behavior and integration tests;
- `.github/workflows/ci.yml` for the unprivileged x86-64 quality gate;
- Rust-local unit tests for native invariants;
- `ai_documentation/` for plans, decisions, risks, and progress context.

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
  'ip link set lo up && NODENETRAW_PRIVILEGED_TESTS=1 node --test test/privileged.test.mjs'
```

Do not report a change as verified without naming which gates actually ran.

## Documentation map

- `README.md`: concise human-facing project status and direction.
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
