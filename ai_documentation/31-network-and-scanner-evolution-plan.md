# Network and scanner evolution plan

Status: accepted, preimplementation-reviewed planning contract; Phases 16
through 18 are complete  
Date: 2026-07-13  
Phases: 16 through 26  
Review: [closed readiness audit](32-network-evolution-plan-review.md)

## Objective

Evolve the `nodenet` workspace in this dependency order:

1. a native protocol toolkit;
2. read-only Linux network context;
3. a general deterministic scan scheduler;
4. scanner-oriented command and result batching;
5. an optional evidence-gated extreme-performance engine.

The outcome is a release-capable `@opsimathically/nodenetscanner` package whose
packet hot path stays in Rust. `@opsimathically/nodenetraw` remains the
policy-free low-level socket package. Package separation must not add a packet-
by-packet N-API or JavaScript crossing.

This document is the authoritative implementation sequence after Phase 15. A
phase may refine names, but it may not weaken the ownership, bounds, package
boundaries, or exit gates without an accepted decision-log update.

## Architectural rules

### Public package boundary

- `nodenetraw` continues to expose raw IPv4, IPv6, and `AF_PACKET` sockets plus
  its existing TypeScript ICMPv4/traceroute conveniences.
- `nodenetscanner` owns scan targets, probe policy, timing, correlation,
  retries, session lifecycle, result classification, and scanner batching.
- `nodenetscanner` does not call the JavaScript `nodenetraw` API internally and
  does not borrow or export a `RawSocket` descriptor. Its native addon owns its
  descriptors for the entire scan session.
- Neither public package is a runtime dependency of the other. Applications may
  install both independently.
- No third public protocol or context package is planned. The protocol and
  context crates are internal implementation libraries until a separate public
  use case justifies another API and release contract.

### Rust workspace boundary

The planned internal crates are:

```text
crates/
  nodenetraw-native/          existing raw-socket N-API crate
  nodenet-protocols/          bounded wire codecs and probe correlation
  nodenet-linux-context/      read-only NETLINK_ROUTE context
  nodenetscanner-engine/      syscall-free scheduler and classification
  nodenetscanner-native/      scanner descriptors, I/O, and N-API adapter
```

All new crates are `publish = false`. `nodenet-protocols`,
`nodenet-linux-context`, and `nodenetscanner-engine` must not depend on napi.
The scanner addon statically links them. Shared crates expose owned values or
scoped borrows whose lifetimes Rust can prove; dependency-specific packet and
netlink types do not cross N-API.

Do not extract the mature `nodenetraw-native` reactor merely to make the tree
look shared. The scanner has different scheduling and data-plane requirements.
Extract a lower-level component only when both consumers need the same proven
contract and regression tests demonstrate unchanged raw-package behavior.

### Data-plane boundary

JavaScript configures sessions, controls lifecycle, pulls bounded result
batches, receives coalesced progress, and observes terminal summaries. Rust
expands compact target ranges, constructs packets, owns timers and correlation,
sends and receives packets, classifies responses, and batches results. Raw
packets do not cross N-API by default.

The portable engine uses ordinary nonblocking Linux raw/packet sockets and
bounded `sendmmsg`/`recvmmsg`-style work. `PACKET_MMAP` TX/RX or AF_XDP may be
added only after Phase 25 proves a material need. Backend choice never changes
result meaning.

## Global safety and behavior contract

- Every session has exactly one native lifecycle: `created`, `running`,
  `pausing`, `paused`, `cancelling`, `completed`, `failed`, or `closed`.
- Close and cancel are idempotent and repeated calls share their terminal
  outcome. While the Node environment is valid, every admitted JavaScript
  operation settles exactly once. Environment cleanup stops admission, wakes
  native workers, and uses a teardown-safe asynchronous join path rather than an
  unbounded join on the Node event-loop thread. It releases descriptors/
  mappings and drops callback references without making N-API calls after the
  environment becomes invalid.
- Packet bytes, netlink messages, scan options, callback behavior, and kernel
  lengths are untrusted.
- All parsing is length-first. No count, offset, nested attribute, extension
  header, or result record controls allocation before checked conversion and an
  independent limit.
- The scanner never changes routes, addresses, links, neighbors, firewall rules,
  qdiscs, namespaces, sysctls, or BPF state in the portable phases.
- Missing neighbor state is data, not permission to mutate the kernel table.
  Active ARP or Neighbor Solicitation is an explicit scan probe.
- The scanner never elevates privileges, installs capabilities, picks an
  implicit target, or supplies a default port list. Targets and probes are
  explicit.
- Time uses a monotonic clock. Wall-clock timestamps are optional presentation
  metadata and never drive deadlines.
- Positive results and terminal state are lossless unless the caller explicitly
  closes a session and thereby requests counted disposal of undrained results.
  Progress and telemetry may be coalesced only when the API exposes the
  coalescing count.
- Before transmitting an admitted probe, reserve enough bounded result capacity
  for its worst-case terminal record. Backpressure stops new admission while
  receive and timeout work consume those reservations; already-admitted work can
  therefore settle without exceeding the queue ceiling.
- No panic crosses N-API. Required `unsafe` remains small, justified with a
  `SAFETY:` comment, isolated from parsers/schedulers, and covered by focused
  ownership tests.

## Initial resource ceilings

These ceilings are independent. Implementations may choose smaller defaults but
may not exceed the maxima silently.

| Resource                                      | Default       | Maximum             |
| --------------------------------------------- | ------------- | ------------------- |
| Scanner objects per Node environment          | 1             | 4                   |
| Concurrent scan sessions per Node environment | 1             | 4                   |
| Target include intervals per session          | —             | 65,536              |
| Target exclude intervals per session          | —             | 65,536              |
| Ports per probe family                        | explicit only | 65,536              |
| Logical probes after checked multiplication   | —             | `u64::MAX`          |
| Portable-engine transmit rate                 | 100 packets/s | 1,000,000 packets/s |
| Outstanding probes                            | 4,096         | 262,144             |
| Retransmissions per logical probe             | 1             | 10                  |
| Per-probe timeout                             | 1,000 ms      | 60,000 ms           |
| Overall session deadline                      | explicit      | 30 days             |
| Packet bytes                                  | protocol/MTU  | 65,597              |
| Probe templates                               | —             | 256                 |
| All template/payload bytes per session        | —             | 1 MiB               |
| Results in one JavaScript batch               | up to 512     | 4,096               |
| Metadata bytes in one result batch            | —             | 4 MiB               |
| Queued result data per session                | —             | 64 MiB              |
| Native memory budget per session              | 256 MiB       | 512 MiB             |
| Native scanner memory per Node environment    | —             | 1 GiB               |

An estimate that exceeds `u64::MAX`, the configured deadline, the memory budget,
or any product bound is rejected before opening scan descriptors. Counts exposed
to JavaScript use `bigint` where a safe integer is insufficient. Per-session
maxima do not override the environment maximum; cumulative admission reserves
against both ceilings atomically.

## Stage 1 — Protocol toolkit

### Phase 16 — Protocol crate foundation

Status: complete on 2026-07-13; implementation evidence is recorded in
`33-phase-16-report.md`.

Goal: establish a dependency-isolated, syscall-free Rust codec foundation before
adding protocol breadth.

Deliverables:

- Add `crates/nodenet-protocols` as a non-published workspace library with
  `unsafe_code = "deny"`, warnings denied, and no N-API dependency.
- Adopt exact-pinned `etherparse` as the preferred reviewed codec engine. At
  implementation start, revalidate the current release, license, advisories,
  enabled features, transitive graph, and MSRV. Disable unused features. The
  workspace wrapper owns stable error and limit types because etherparse states
  that its API may change.
- Record a protocol coverage/ownership matrix before coding Phase 17. A missing
  or partial etherparse codec (including ICMP/ICMPv6 message breadth) is filled
  by bounded project-owned code. A proposed deferral requires a decision-log
  scope change and prevents the owning phase from exiting; dependency coverage
  never silently reduces this plan's accepted protocol surface. Fragment
  reassembly supplied by a dependency remains disabled and unused.
- Define checked address, MAC, EtherType, IP protocol, port, checksum, packet-
  span, parse-mode, and structured parse-error types.
- Support strict parsing for scanner responses and explicitly named compatible
  parsing for truncated ICMP quotes. Never silently fall back from strict to lax
  parsing.
- Provide construction into caller-owned bounded byte slices and owned
  construction for tests/control paths. Builders return required length before
  writing and never leave partially initialized output on failure.
- Add deterministic independent wire fixtures shared by protocol, engine, and
  namespace tests. Existing TypeScript ICMPv4 fixtures remain independent
  oracles rather than being replaced.
- Add parser/serializer fuzz targets, arbitrary-byte no-panic tests, mutation
  tests, and allocation-count benchmarks.
- Record the exact representation and comparison algorithm for session-keyed
  correlation before Phase 18 adds it. Use a reviewed keyed primitive or stored
  OS-random tokens; do not invent a cryptographic construction or reuse the
  caller-visible scheduling seed as a secret.

Toolkit-specific ceilings:

- at most 65,575 bytes per non-jumbogram IPv6 packet and 65,597 bytes per
  Ethernet frame with two VLAN tags and no captured FCS;
- at most two VLAN headers;
- at most eight IPv6 extension headers and 2,048 extension-header bytes;
- at most 40 TCP option bytes;
- no IPv4 or IPv6 fragment reassembly;
- no IPv6 jumbogram construction or parsing in the initial toolkit;
- returned owned payload/option data is capped separately from the input slice.

Non-goals:

- N-API exports;
- socket I/O or descriptor ownership;
- DNS, TLS, HTTP, service fingerprints, packet reassembly, or application
  payload interpretation;
- replacing the existing public TypeScript ICMPv4 API.

Exit gate:

- crate builds on x86-64 and AArch64 targets;
- zero unsafe code and no syscall/N-API dependency;
- hostile input cannot panic or allocate above declared bounds;
- golden, round-trip, fuzz-smoke, and dependency/license gates pass;
- microbenchmarks establish parse/build baselines without making a performance
  claim.

### Phase 17 — Link and internet protocol coverage

Status: complete on 2026-07-13; implementation evidence is recorded in
`34-phase-17-report.md`.

Goal: construct and parse the complete L2/L3 envelope needed by ordinary raw
scanners.

Deliverables:

- Ethernet II headers and one/two-level 802.1Q/802.1ad VLAN tags.
- Ethernet/IPv4 ARP request and reply parsing/building with explicit hardware
  and protocol lengths; unknown ARP combinations remain structured unknown
  values rather than being guessed.
- IPv4 base headers, options, DSCP/ECN, identification, flags/fragment offset,
  TTL, protocol, total length, and header checksum.
- IPv6 base headers, traffic class, flow label, payload length, next header, hop
  limit, and bounded traversal of Hop-by-Hop, Routing, Fragment, Destination
  Options, and Authentication headers needed to locate transport.
- Enforce structural extension lengths and traversal order. Represent
  `No Next Header`, unknown next-header values, and ESP as explicit opaque
  terminal states; never scan past them looking for a transport header. Report
  non-canonical duplicate/order combinations distinctly from unsafe truncation.
- Exact distinction between unfragmented, first fragment, and non-first
  fragment. Transport classification is attempted only when its bytes are
  present and semantically reachable.
- Frame templates whose invariant bytes are prebuilt once and whose addresses,
  lengths, identifiers, checksums, and tokens can be patched through checked
  field descriptors.

Tests:

- independent RFC and packet-capture vectors;
- every minimum/maximum header and option length;
- malformed IHL, total/payload length, VLAN nesting, extension cycles/counts,
  fragments, and checksum cases;
- builder buffer-too-small behavior and no partial initialization;
- differential parse/build checks against the pinned codec dependency;
- namespace capture proving emitted Ethernet/ARP/IPv4/IPv6 bytes.

Exit gate: every supported L2/L3 packet round-trips canonically, malformed
packets fail structurally without ambiguous transport classification, and
template patching matches a full rebuild byte-for-byte.

### Phase 18 — Transport, control, and correlation coverage

Status: complete on 2026-07-13; implementation evidence is recorded in
`35-phase-18-report.md`.

Goal: complete scanner-relevant L4/control codecs and strong response
correlation before any scheduler sends live probes.

Deliverables:

- TCP construction/parsing for ports, sequence/acknowledgment numbers, data
  offset, all standardized flag bits, window, urgent pointer, checksum, and
  bounded options including MSS, window scale, SACK-permitted/SACK, and
  timestamps. Unknown options are preserved safely.
- UDP construction/parsing with IPv4/IPv6 pseudo-header checksums, correct
  zero-checksum distinctions, and explicit payload ownership.
- ICMPv4 scanner subset using the existing Phase 12–15 vectors: Echo,
  Destination Unreachable, Time Exceeded, Parameter Problem, and quoted
  TCP/UDP/ICMP evidence.
- ICMPv6 Echo and error messages from RFC 4443, including Packet Too Big and
  bounded quoted-packet correlation.
- IPv6 Neighbor Discovery from RFC 4861: Router Solicitation/Advertisement,
  Neighbor Solicitation/Advertisement, Redirect, and bounded known/unknown
  options. Validation checks ICMPv6 pseudo-header checksum, code, minimum
  length, option length units, target/source/destination rules, required hop
  limit 255, and message-specific flags while preserving safe unknown options.
  It never changes host state.
- Session-keyed correlation primitives for TCP sequence/ack tokens, ICMP
  identifier/sequence/payload tokens, and UDP payload tokens. Tokens bind the
  probe family, target, source, port/protocol, attempt, and session secret.
- Constant-time token comparison where token secrecy affects forgery resistance.
  Random session secrets come from the OS and are never returned.
- Treat ICMP quotes that omit required token bytes as explicitly weak evidence;
  tuple-only TCP/UDP quotes must never be promoted to strong correlation.
- Define evidence strength per family. A TCP reply is strong only when its flags
  and acknowledgment validate the outstanding sequence token. ICMP Echo is
  strong only with its expected identifier, sequence, and payload token. Direct
  UDP replies, short ICMP quotes, ARP replies, and Neighbor Advertisements are
  tuple/interface/window-correlated but unauthenticated and are labeled
  accordingly. Source-port and identifier reuse is prohibited while an
  outstanding or late-response grace record could make a match ambiguous.
- Pure response classification evidence; final scan state remains an engine
  policy decision.

Tests:

- RFC/golden and checksum vectors for IPv4 and IPv6 pseudo-headers;
- forged tuple, token, checksum, fragment, quote, option, and late-response
  matrices;
- parity with existing public ICMPv4 behavior for overlapping messages without
  requiring identical internal representations;
- pcap replay that produces deterministic normalized evidence;
- fuzzing for every protocol entry point and nested quote path.

Exit gate: live-integration code can construct and correlate ARP, NDP Neighbor
Solicitation, ICMPv4/v6 Echo, TCP SYN, and UDP probes at their documented
evidence strength without custom byte parsing in the scheduler or N-API crate.

## Stage 2 — Read-only network context

### Phase 19 — Bounded NETLINK_ROUTE snapshot

Status: complete on 2026-07-14. See
[`36-phase-19-report.md`](36-phase-19-report.md).

Goal: obtain a complete immutable view of the current network namespace without
running `ip`, reading procfs text, or exposing a mutation API.

Deliverables:

- Add `crates/nodenet-linux-context`, non-published and independent of N-API.
- Use exact-pinned `netlink-packet-core`, `netlink-packet-route`, and
  `netlink-sys` after a focused dependency/license/advisory review. Do not add
  the higher-level `rtnetlink` mutation surface or a Tokio/async runtime merely
  for one-shot reads.
- Own a `NETLINK_ROUTE` socket with `CLOEXEC`, kernel-assigned port ID, checked
  sequence numbers, bounded receive buffers, sender PID validation, and
  multipart completion/error handling.
- Bind the context to the network namespace in which its descriptors are
  created. Record `SO_NETNS_COOKIE` when available, never call `setns()`, and
  require namespace tests to launch the Node process inside the target namespace
  rather than changing namespaces from a multithreaded process.
- Dump links, IPv4/IPv6 addresses, routes, rules needed to interpret context,
  and ARP/NDP neighbor entries using GET operations only.
- Produce immutable normalized records for interface identity/flags/type/MTU,
  hardware address, master/link relationship, addresses/prefix/scope/flags,
  routes/table/type/scope/priority/preferred source/gateway/metrics/multipath,
  rules, and neighbor state/link address.
- Preserve unknown bounded attributes for diagnostics only when safe; scanner
  decisions use recognized typed fields.
- Detect `NLM_F_DUMP_INTR`, `NLMSG_OVERRUN`, `ENOBUFS`, sequence mismatch,
  `NLMSG_ERROR`, truncation, missing terminators, and disappearing interfaces.
  Serialize dump transactions per socket, distinguish sequence-zero multicast
  notifications from replies, and reject non-kernel unicast senders. Retry a
  full snapshot at most three times, then fail as incomplete rather than
  presenting partial state as authoritative.

Snapshot ceilings:

| Resource                      | Maximum |
| ----------------------------- | ------- |
| One netlink datagram          | 1 MiB   |
| Messages per dump             | 65,536  |
| Attributes per message        | 256     |
| Nested attribute depth        | 8       |
| One string attribute          | 256 B   |
| Interfaces                    | 4,096   |
| Addresses                     | 16,384  |
| Routes/rules                  | 65,536  |
| Neighbors                     | 65,536  |
| Multipath next hops per route | 64      |

The implementation additionally caps aggregate bytes retained from one dump at
64 MiB, one link-layer address at 256 bytes, one unknown diagnostic attribute at
4 KiB, and all snapshot unknown diagnostics at 8 MiB. These defense-in-depth
limits preserve the planned record ceilings without allowing many large valid
attributes to accumulate unbounded memory.

Tests:

- synthetic multipart, ACK/error, interrupted, overrun, malformed attribute,
  unknown attribute, and churn sequences;
- snapshot parity with `ip -j link/address/route/neigh` as a test oracle only;
- isolated namespaces with loopback, veth, VLAN, IPv4/IPv6, multiple tables,
  blackhole/prohibit routes, and neighbor states;
- descriptor/RSS stability over repeated snapshots.

Exit gate: a complete snapshot is deterministic and bounded, incomplete dumps
cannot be mistaken for success, and syscall tracing confirms no netlink create,
set, delete, or replace operation.

### Phase 20 — Kernel route resolution and coherent refresh

Status: complete on 2026-07-14. See the
[Phase 20 report](37-phase-20-report.md).

Goal: turn snapshots into trustworthy egress context without reimplementing the
Linux forwarding-information-base policy in user space.

Deliverables:

- Resolve a destination through a targeted `RTM_GETROUTE` request, with checked
  optional source, mark, UID, IP protocol, and ports where needed. Let Linux
  choose policy rules and ECMP; do not choose the longest prefix independently.
- Return route type, table, output interface, preferred source, gateway or
  on-link next hop, effective MTU, selected multipath information, and an
  explicit unusable reason for unreachable/prohibit/blackhole/throw outcomes.
- Join route results to the matching immutable interface/address/neighbor
  generation. Never combine records from different generations silently.
- Serialize each route query with context publication: capture the generation,
  issue the query, drain already-received notifications, and retry within the
  query deadline if the generation changed before the joined result can be
  published. A result is never relabeled as belonging to a newer generation.
- Treat neighbor states (`INCOMPLETE`, `REACHABLE`, `STALE`, `DELAY`, `PROBE`,
  `FAILED`, `NOARP`, `PERMANENT`) explicitly. A missing/failed link address is
  reported; it is not inserted or refreshed through netlink.
- Subscribe read-only to link/address/route/rule/neighbor multicast groups.
  Subscribe before the initial dump, buffer notifications within a fixed bound,
  apply them after the dump, and publish an atomic generation.
- On event-buffer overflow, `ENOBUFS`, dump interruption, or undecodable state,
  invalidate the generation and perform a bounded full resync. Consumers never
  receive an allegedly current partial generation.
- Provide a synchronous pure route-plan API inside Rust and an asynchronous
  refresh/query driver for the future scanner addon.
- Distinguish local/loopback, Ethernet-like on-link/gateway, multicast,
  unreachable, and unsupported link/route plans. Preserve IPv6 scope/interface
  requirements. The initial scanner explicitly supports Ethernet/VLAN and
  loopback; tunnel, point-to-point, non-Ethernet hardware, and encapsulation
  routes return structured unsupported results rather than guessed L2 headers.

Additional ceilings:

- at most 8,192 buffered change notifications or 8 MiB, whichever comes first;
- at most one resync in flight;
- exponential resync delay capped at 5 seconds;
- at most 1,024 pending route queries per context owner;
- each query has a finite monotonic deadline and cancellation token.

Exit gate: namespace tests prove policy-route, on-link, gateway, ECMP,
unreachable, interface-down, neighbor-present/missing, and concurrent-change
behavior; all public results identify their generation and completeness.

## Stage 3 — General scan scheduler

### Phase 21 — Syscall-free deterministic scheduler

Status: complete on 2026-07-14; evidence is recorded in `38-phase-21-report.md`.

Goal: implement and exhaustively test scheduling, target expansion, timing, and
classification before combining them with privileged packet I/O.

Deliverables:

- Add `crates/nodenetscanner-engine`, depending on `nodenet-protocols` but not
  on N-API or Linux syscalls, and deny unsafe code in the crate.
- Define injected `Clock`, `ProbeTransport`, `ContextResolver`, entropy, and
  result-sink traits. Tests use a virtual monotonic clock and scripted packet
  evidence.
- Normalize IPv4/IPv6 CIDRs and inclusive ranges plus exclusions into sorted,
  disjoint compact intervals. Reject zone-invalid IPv6 targets and checked-count
  overflow. DNS names and files are application concerns in the first release.
- Combine target intervals, explicit ports, probe families, and attempts through
  checked arithmetic without materializing every tuple.
- Provide a deterministic seeded permutation over the logical probe index so
  repeated jobs can reproduce order while avoiding sequential concentration. The
  default seed uses OS entropy and is reported only if the caller asks for
  reproducibility. This scheduling seed is public reproducibility data and is
  cryptographically independent from all correlation secrets/tokens.
- Schedule explicit ARP and NDP link-neighbor discovery, ICMPv4/v6 Echo
  discovery, TCP SYN, and UDP probes through one generic probe/evidence
  interface.
- Implement a global token bucket, bounded outstanding window, per-target and
  per-prefix fairness, monotonic deadlines, adaptive RTT/variance, exponential
  loss backoff, and explicit retry limits. User-supplied fixed-rate mode remains
  bounded and reports the accuracy tradeoff.
- Charge every emitted frame against rate and outstanding budgets, including
  neighbor resolution, retransmissions, and any TCP reset cleanup the final
  transport contract elects to send. Internal setup traffic cannot bypass the
  user-visible ceiling.
- Retain compact late-response correlation state until a bounded grace deadline
  after timeout; never resurrect a terminal result.
- Define states without pretending silence is proof:
  - TCP SYN-ACK `open`, RST `closed`, applicable ICMP error `filtered`, timeout
    `filtered`;
  - UDP response `open`, ICMP port unreachable `closed`, other applicable ICMP
    errors `filtered`, timeout `open|filtered`;
  - discovery response `up`, explicit unreachable evidence `unreachable`, and
    silence `unknown/down-by-policy` according to the selected policy.
- State transitions carry evidence strength, attempt, RTT, route generation, and
  terminal reason. Duplicate responses update counters but do not duplicate
  terminal results.
- Non-first fragments, opaque ESP/unknown-next-header packets, and structurally
  valid but insufficient quotes increment bounded diagnostic counters and do not
  create guessed port/host results.
- Define pause, resume, cancel, deadline, transport failure, context
  invalidation, and result-backpressure behavior as deterministic state-machine
  events.

Tests:

- millions of virtual-clock transitions without wall-clock sleeps;
- loss, reordering, duplication, forgery, late responses, rate limiting, context
  generation changes, pause/resume, cancellation, and sink saturation;
- deterministic seed/order and exact boundary/deadline equality;
- property tests that every logical tuple appears at most once per attempt and
  exclusions never appear;
- memory proportional to active windows/results, not total target count;
- fairness across hosts, prefixes, protocols, sessions, and quiet/slow targets.

Exit gate: the engine can replay a recorded evidence stream into identical
results across runs, no test requires privilege or real time, and all resource
ceilings fail before partial session admission.

### Phase 22 — Portable live scanner and initial Node API

Goal: activate `@opsimathically/nodenetscanner` with a correctness-first native
data plane using ordinary Linux sockets.

Deliverables:

- Add `crates/nodenetscanner-native` and convert the private scanner workspace
  into a buildable, still-unpublished TypeScript/N-API package.
- Own all raw/packet descriptors, packet buffers, native threads/reactors,
  context subscriptions, timers, and session secrets in Rust. Do not expose
  descriptors or depend on the `nodenetraw` JavaScript package.
- Use one bounded runtime per Node environment, never process-global state.
  Multiplex at most four scanner objects and four concurrent sessions over an
  environment-owned control wakeup, scheduler/I/O worker, context driver, and
  completion bridge. Each live session retains unambiguous ownership of its scan
  descriptors and buffer reservations. Cross-session source ports, ICMP
  identifiers, and token spaces are allocated without an
  outstanding/grace-period collision.
- Never let the scheduler/I/O worker block on N-API delivery. Reserve completion
  capacity when admitting each async control operation; a bounded bridge may
  wait for JavaScript while the I/O worker continues receive, timeout, cancel,
  and teardown work. Environment cleanup invalidates delivery before joining the
  workers.
- Use Node-API's stable asynchronous environment cleanup mechanism through a
  verified napi-rs facility or one localized audited adapter. Completion of the
  cleanup hook is the proof that workers and N-API references are gone; do not
  detach a thread and report cleanup complete while it can still access addon
  state.
- Use nonblocking `AF_PACKET`/raw sockets, finite command/readiness work
  budgets, and bounded portable send/receive batches. Separate scheduling from
  I/O so a future backend implements the same internal transport contract.
- Use read-only route context to select interface/source/next hop. If a link-
  layer address is absent, an explicitly configured ARP/NS discovery step may
  resolve it from observed replies for the session only; it never writes the
  kernel neighbor table.
- Use `AF_PACKET` Ethernet frames for supported Ethernet/VLAN paths and raw IP
  sockets for loopback/local routes. Reject unsupported link types and
  encapsulation instead of fabricating an Ethernet header. Do not enable
  promiscuous or all-multicast membership by default.
- On packet receive, reject truncation, ignore locally looped `PACKET_OUTGOING`
  frames in software on every supported kernel, and use `PACKET_AUXDATA` to
  interpret VLAN metadata that hardware/kernel offload may remove from frame
  bytes. Account packet-socket drop statistics without using their reset-on-read
  behavior as a lifetime total accidentally.
- Implement live ARP/NDP link-neighbor, ICMPv4/v6 Echo, TCP SYN, and UDP scans
  for IPv4/IPv6 where the selected link and route support them.
- Require explicit targets and probe/port configuration. Source address,
  interface, VLAN, rate, retry, timeout, and exclusion overrides are validated
  and captured once at session creation.
- Reserve a configurable source-port range for TCP/UDP correlation and document
  host-stack interactions, including locally generated TCP resets and source-
  port conflicts. Never install firewall rules automatically.
- Initial public shape:

```ts
type ScanTarget =
  | { cidr: string }
  | { start: string; end: string };

type PortSelection = number | { start: number; end: number };

type ScanProbe =
  | { kind: "arp" }
  | { kind: "ndp" }
  | { kind: "icmpEcho"; family: "ipv4" | "ipv6" }
  | { kind: "tcpSyn"; ports: readonly PortSelection[] }
  | { kind: "udp"; ports: readonly PortSelection[]; payload?: Uint8Array };

interface ScanPlan {
  targets: readonly ScanTarget[];
  exclude?: readonly ScanTarget[];
  probes: readonly ScanProbe[];
  deadlineMs: number;
  rate?: ScanRateOptions;
  timing?: ScanTimingOptions;
  seed?: bigint;
}

inspectNetworkContext(options?): Promise<NetworkContextSnapshot>;
createScanner(options?): Promise<Scanner>;

interface Scanner {
  start(plan: ScanPlan): Promise<ScanSession>;
  close(): Promise<void>;
}

interface ScanSession {
  readonly state: ScanSessionState;
  pause(): Promise<void>;
  resume(): Promise<void>;
  cancel(reason?: string): Promise<ScanSummary>;
  nextBatch(options?): Promise<ScanResultBatch | null>;
  summary(): Promise<ScanSummary>;
  close(): Promise<void>;
}
```

- The sketch freezes the shape direction, not every exported name. Targets,
  probes, ports, and the overall deadline are never implicit. CIDRs/ranges and
  port ranges stay compact across N-API. ARP accepts only on-link IPv4 targets;
  NDP accepts only on-link IPv6 targets. Payload, timing, rate, source,
  interface, VLAN, seed, and family/probe combinations are independently
  validated against the resource table before session admission.
- `inspectNetworkContext()` and `createScanner()` perform only read-only context
  setup and do not require `CAP_NET_RAW`. `start()` opens scan descriptors and
  reports a structured permission error if the current network/user namespace
  lacks raw-socket authority. The library never retries with elevated privilege.
- `nextBatch()` is present from the first public preview so per-result promises
  never become a compatibility constraint. Phase 22 may fill it through a
  straightforward bounded native vector; Phase 23 freezes its compact layout.
- Scanner and session close are idempotent. Scanner close cancels sessions,
  waits for native ownership to end, then releases context and descriptors.
- Pause stops new transmission only after the returned promise resolves;
  receive, timeout, cancel, close, and result draining continue. Cancel stops
  admission and returns the terminal summary after native cleanup while queued
  results remain drainable. Explicit session close is the caller's instruction
  to cancel if needed, release native ownership, and discard any undrained
  result batches; that intentional discard is reported in the summary.
- A session retains its terminal summary as an owned bounded value after native
  I/O resources end. `summary()` waits for terminal state and returns the same
  value on repeated calls; after explicit close, it returns the final cached
  summary without reopening resources.
- Errors distinguish invalid plan, permission, unsupported route/link/probe,
  queue/resource limit, cancellation, deadline, context invalidation, I/O, and
  environment closure while retaining Linux operation/errno context.

Tests:

- fully isolated dual-stack namespaces with live/open/closed/silent targets,
  routers, VLAN, ARP/NDP, ICMP errors, fragments, and route changes;
- packet capture validates exact emitted bytes, source selection, checksums,
  exclusions, rate ceiling, retry count, and no netlink/firewall mutation;
- forged/unrelated responses never create results;
- cancel/close/Worker teardown and repeated session fd/RSS stress;
- direct comparison between live captured evidence and pure engine replay.

Exit gate: the portable engine completes bounded end-to-end scans accurately,
the Node thread never runs packet loops, and a slow JavaScript consumer cannot
cause unbounded native allocation.

## Stage 4 — Scanner-oriented batching

### Phase 23 — Compact command/result batches and backpressure

Goal: make N-API cost proportional to batches rather than probes while retaining
lossless results and ergonomic TypeScript access.

Deliverables:

- Freeze a versioned `ScanResultBatch` layout using owned packed address bytes,
  fixed-width protocol/port/state/attempt/evidence arrays, 64-bit monotonic RTT
  and timestamp storage, route-generation IDs, and bounded offset-addressed
  metadata.
- Define timestamps as unsigned nanoseconds relative to the session's monotonic
  origin; wall time, when requested for presentation, is a separate snapshot and
  never participates in ordering. Values wider than JavaScript's safe integer
  use `bigint`/BigInt typed views or checked accessors without lossy conversion.
- IPv4 and IPv6 are never inferred from byte content; each row has an explicit
  family. All fixed-width integer buffers define byte order.
- Native memory is copied or transferred into Node-owned initialized storage
  only after the batch is sealed. JavaScript mutation cannot affect native
  correlation or session state. No mmap/UMEM memory crosses N-API.
- TypeScript provides lazy row access, iteration, filtering, and optional owned
  object materialization without a runtime dependency. It does not eagerly make
  one object per result.
- Batch target/control admission where dynamic callers need it, while CIDR/range
  plans remain compact native descriptions. One control command is bounded to
  65,536 intervals/items and 4 MiB.
- Maintain a bounded result channel. When full, pause new transmissions while
  continuing to drain receive packets, settle expirations, and accept cancel or
  close. Resume only below a low-water mark.
- Never drop positive/terminal results. Coalescible progress snapshots include
  counts for sent, received, matched, duplicate, invalid, timed out, retried,
  kernel-dropped, application-backpressured, and coalesced updates.
- `nextBatch()` has one pending-call limit per session, AbortSignal
  cancellation, terminal `null`, and deterministic delivery-before-cancel
  ordering.
- Aborting `nextBatch()` cancels only that wait, not the scan. After cancel or
  natural completion it drains sealed queued batches and then returns `null`;
  after explicit session close discards queued results, a pending/future pull
  returns `null`. No batch is delivered twice.
- Add an optional Node-style batch event adapter over the pull API with explicit
  start/pause/detach/close and at most one pending `nextBatch()`. There is no
  per-result event mode.

Exit gate: throughput and CPU profiles show N-API calls scale with batches;
result saturation stops transmission without loss or deadlock; batch buffers
survive retention, mutation, Worker transfer, cancellation, and teardown safely.

Status: complete. D-037 freezes schema version 1, the worker/Node ownership
boundary, pull ordering, progress counters, and result-queue hysteresis.
Implementation and gate evidence are in
[the Phase 23 report](40-phase-23-report.md).

### Phase 24 — Scanner hardening and release candidate

Goal: make the portable scanner package independently releasable before any
extreme backend is considered.

Deliverables:

- Stabilize the TypeScript declarations, error model, session lifecycle,
  result-batch schema version, context snapshot, and supported probe matrix.
- Add package README examples for discovery, TCP SYN, UDP, IPv6, progress,
  batches, cancellation, exclusions, route inspection, and privilege setup.
- Document the initial Ethernet/VLAN/loopback link matrix, namespace binding,
  source-port/local-RST interactions, offload/VLAN metadata, ICMP rate limits,
  and that an `AF_PACKET` result describes observed wire traffic rather than
  proving an application could traverse the host firewall or complete a
  connection.
- Add syscall-free engine/protocol fuzzing, N-API hostile-value tests, sanitizer
  jobs, namespace fault injection, completion-queue saturation, repeated Worker
  termination, fd/RSS/native-memory stress, and long-run loss simulations.
- Benchmark target expansion, packet construction, portable TX/RX, correlation,
  scheduling, result batching, N-API delivery, and multi-session fairness.
  Publish hardware/kernel/interface/configuration with every claim.
- Create loader-only `@opsimathically/nodenetscanner` staging plus exact-version
  x64/AArch64 glibc target packages, mirroring the no-install-script,
  reproducible, provenance-recorded model used by `nodenetraw`.
- Keep the scanner package unpublished until native x86-64 and AArch64 ordinary
  gates, supported privileged namespace gates, clean consumers, artifact ABI,
  reproducibility, advisories, and documentation all pass.
- Advance the scanner to `0.1.0-rc.1` only in this phase. Internal development
  before this remains private `0.0.0`.

Portable-release non-goals:

- connect scans, banner grabbing, service/version detection, OS fingerprinting,
  DNS, scripting, vulnerability checks, firewall changes, distributed scanning,
  checkpoint files, or Internet-scan policy;
- claiming Masscan-class packet rates;
- requiring PACKET_MMAP TX, AF_XDP, an XDP program, or a newer kernel than the
  declared baseline.

Exit gate: the portable scanner is accurate, bounded, documented, reproducible,
and independently publishable. Phase 24 completion is useful even if Phases 25
and 26 never proceed.

## Stage 5 — Optional extreme-performance engine

### Phase 25 — Evidence and backend decision gate

Goal: determine whether another data plane is justified and select exactly one
next backend through measurements rather than aspiration.

Deliverables:

- Define a backend-neutral internal I/O contract covering frame-template
  submission, receive batches, monotonic timestamps, interface/queue identity,
  drops, backpressure, cancellation, and shutdown.
- Profile the portable engine at increasing rates in offline construction,
  loopback/veth, and dedicated physical-interface tests. Separate scheduler,
  checksum, syscall, copy, N-API, NIC, and kernel-drop costs.
- Prototype, outside the public API, ordinary `sendmmsg`/`recvmmsg`,
  `PACKET_TX_RING` plus receive ring, and AF_XDP copy/zero-copy where hardware
  supports it.
- Record kernel, driver, NIC, queue count, CPU topology, NUMA placement, MTU,
  ring sizes, packet mix, loss, power/CPU, and p50/p95/p99 latency.
- Assess ownership and operational cost:
  - PACKET_MMAP has writable shared TX frames and status transitions that must
    remain native-owned and checked;
  - AF_XDP requires an XDP program/XSKMAP, queue-matched sockets, single-
    producer/single-consumer ring ownership, UMEM frame accounting, and explicit
    copy-versus-zero-copy reporting;
  - attaching/loading XDP expands privileges and cleanup obligations and cannot
    be hidden inside the portable package contract.
- For an AF_XDP candidate, separately review libbpf/libxdp, maintained Rust
  wrappers, and any project-owned FFI for license, native build, artifact ABI,
  loader, and ownership cost. Kernel documentation's libbpf recommendation does
  not override this repository's dependency and reproducibility gates.
- Select a backend only if it provides at least 1.5x sustained matched-result
  throughput at no greater CPU/core budget, or at least 30% CPU reduction at
  equal sustained throughput, with equal verified results/loss and without
  weakening cancellation, bounds, or cleanup. Compare identical workloads on the
  same isolated hardware with preregistered warmup/duration and at least ten
  steady-state repetitions; a bootstrap 95% confidence interval must not cross
  the threshold. Material regressions in tail latency, drops, power, or
  operational requirements block selection unless separately accepted in the
  backend decision. Otherwise record the evidence and stop.
- Freeze compatibility policy. An extreme backend may have a higher optional
  kernel/driver requirement, but the portable engine and package installation
  baseline remain unchanged.

Exit outcomes:

1. `no-go`: portable engine is sufficient; no Phase 26 implementation;
2. `PACKET_MMAP`: implement checked native-owned TX/RX rings;
3. `AF_XDP experimental`: implement only with an explicit XDP program and UMEM
   lifecycle contract;
4. a different backend requires a new decision and plan review.

### Phase 26 — Conditional extreme backend and parity

This phase starts only after Phase 25 records a `PACKET_MMAP` or `AF_XDP`
decision. It is not required for the first scanner release.

Common deliverables:

- Implement the chosen backend behind the same scheduler/result contract.
- Keep every writable ring, descriptor, UMEM frame, and packet template native-
  owned. JavaScript receives only sealed ordinary result batches.
- Assign one authoritative owner to each single-producer/single-consumer ring.
  Cross-thread communication uses bounded rings with explicit ownership
  transfer, never shared mutable frame access.
- Bound mappings independently per session and environment; validate geometry,
  alignment, producer/consumer indices, frame addresses, lengths, status bits,
  and kernel-returned metadata before access.
- Provide explicit `engine: "portable" | "auto" | "packetMmap" | "afXdp"`.
  `auto` may fall back only during creation and reports the selected engine.
  Explicit modes fail rather than silently falling back. No mid-session backend
  switch is allowed.
- Prove result/classification parity by replaying identical packet evidence
  through portable and extreme paths.
- Fault-test interface removal, queue mismatch, ring exhaustion, malformed
  descriptors/status, XDP replacement, cancellation, environment teardown, and
  partial initialization cleanup.

PACKET_MMAP-specific requirements:

- choose and document the TPACKET version for TX/RX semantics;
- never mark a frame `SEND_REQUEST` before every byte/header field is
  initialized;
- treat `WRONG_FORMAT`, unavailable frames, and poll/send wakeups explicitly;
- unmap only after kernel ownership and all engine references end.

AF_XDP-specific requirements:

- define who loads, pins, replaces, and removes the XDP program and XSKMAP;
- never replace or detach an operator-owned XDP program by default. Prefer an
  externally managed compatible program/map contract. Any module-owned attach
  requires an explicit mode, no conflicting program, and an ownership mechanism
  such as a supported BPF link whose close semantics prevent a crashed process
  from leaving silent host state; cleanup detaches only an identity-matching
  module-owned attachment;
- require queue/device match and report copy versus zero-copy mode truthfully;
- maintain a checked state machine for every UMEM frame across fill, RX, TX,
  completion, cancellation, and shutdown;
- cap UMEM/rings and prohibit multiple producers/consumers for a shared ring;
- extend release tests only on declared compatible drivers/hardware. Generic XDP
  copy-mode behavior is not evidence of zero-copy support.

Exit gate: the chosen backend meets the Phase 25 improvement threshold again in
the final implementation, matches portable results, passes sanitizer/stress/
fault cleanup, and remains optional. If any ownership or parity proof fails, the
backend stays experimental and the portable engine remains default.

## Cross-phase verification topology

### Ordinary gates

- strict TypeScript declarations and runtime hostile-value tests;
- Rust formatting, Clippy, unit/property tests, deterministic virtual clocks,
  parser fuzz smoke, and dependency/license/advisory review;
- pcap and golden-vector replay with no raw-socket privilege;
- clean consumer builds for each activated public package.

### Privileged namespace gates

- dual-stack source/router/target namespaces with veth and VLAN;
- open, closed, unreachable, prohibited, blackhole, fragmented, silent, and
  rate-limited response behavior;
- ARP and NDP present/missing/stale cases without kernel-table mutation by the
  library;
- policy routes, multiple tables, route changes, link down/removal, and context
  resync;
- exact packet capture, rate, retry, exclusion, and checksum assertions;
- concurrent session fairness, cancellation, close, and Worker teardown.

### Dedicated hardware gates

- portable performance claims on named hardware;
- TX ring and AF_XDP only when the selected backend requires them;
- AArch64 native execution before publishing an AArch64 scanner artifact;
- no timing-sensitive performance threshold in ordinary shared CI.

## Phase ordering and stop conditions

| Phase | Depends on | May begin when                                  |
| ----- | ---------- | ----------------------------------------------- |
| 16    | 15/D-031   | D-031 is accepted; revalidation is first task   |
| 17    | 16         | foundation fuzz/golden/ownership gates pass     |
| 18    | 17         | L2/L3 strict and template parity pass           |
| 19    | 18         | protocol evidence types are stable              |
| 20    | 19         | complete bounded snapshots pass under churn     |
| 21    | 18, 20     | route-plan and correlation contracts are stable |
| 22    | 21         | virtual scheduler state matrix is complete      |
| 23    | 22         | portable live correctness and teardown pass     |
| 24    | 23         | batch schema/backpressure are frozen            |
| 25    | 24         | portable scanner is release-capable             |
| 26    | 25 go      | one backend and ownership contract are accepted |

Do not combine protocol breadth, netlink context, scheduler logic, live I/O,
batch schema, and extreme mappings in one change. If a prior phase exposes a
correctness or ownership gap, fix and repeat that phase's gates before
advancing.

## Research basis

Primary references reviewed for this plan:

- Linux kernel
  [route](https://www.kernel.org/doc/html/next/networking/netlink_spec/rt-route.html)
  and [neighbor](https://kernel.org/doc/html/latest/netlink/specs/rt-neigh.html)
  netlink specifications plus
  [`rtnetlink(7)`](https://man7.org/linux/man-pages/man7/rtnetlink.7.html);
- Linux kernel
  [`PACKET_MMAP`](https://docs.kernel.org/networking/packet_mmap.html) and
  [AF_XDP](https://docs.kernel.org/networking/af_xdp.html) documentation;
- [Nmap scan algorithms](https://nmap.org/book/port-scanning-algorithms.html),
  [host discovery algorithms](https://nmap.org/book/host-discovery-algorithms.html),
  and [timing controls](https://nmap.org/book/man-performance.html);
- Masscan's official
  [asynchronous, randomized architecture description](https://github.com/robertdavidgraham/masscan#design);
- [RFC 826](https://www.rfc-editor.org/rfc/rfc826.html) (ARP),
  [RFC 8200](https://www.rfc-editor.org/rfc/rfc8200.html) (IPv6),
  [RFC 9293](https://www.rfc-editor.org/rfc/rfc9293.html) (TCP),
  [RFC 768](https://www.rfc-editor.org/rfc/rfc768.html) (UDP),
  [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html) (ICMPv6), and
  [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861.html) (IPv6 Neighbor
  Discovery);
- current [`etherparse`](https://docs.rs/etherparse/latest/etherparse/),
  [`netlink-packet-route`](https://docs.rs/netlink-packet-route/latest/netlink_packet_route/),
  and [`netlink-sys`](https://docs.rs/netlink-sys/latest/netlink_sys/) rustdoc.
  Exact dependency versions and features must be revalidated at the phase that
  adds them.
