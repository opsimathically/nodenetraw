# Network and scanner evolution plan review

Status: closed; Phases 16–26 are coherent and Phase 16 is ready to implement  
Date: 2026-07-13  
Reviewed plan:
[Network and scanner evolution plan](31-network-and-scanner-evolution-plan.md)

## Review objective

Audit the post-Phase-15 plan as an implementation contract rather than a feature
wishlist. The review checked package and crate boundaries, current dependency
capability, protocol correctness, Linux namespace/netlink/packet semantics,
session and N-API lifecycle, resource proofs, scanner accuracy, testability,
release independence, and the conditional high-performance gate.

No implementation code was written. Findings below were corrected directly in
the authoritative plan and propagated to the roadmap, scope, architecture,
safety, testing, decision log, index, and durable agent context.

## Outcome

The five-stage order remains correct:

1. protocol codecs and evidence;
2. read-only Linux network context;
3. deterministic scheduler and portable live scanner;
4. compact batching and portable release hardening;
5. optional measured data-plane specialization.

The order avoids three expensive failure modes: privileged I/O before parsers
are trustworthy, timing policy mixed into syscall code before it is
deterministically testable, and specialized shared-memory ownership before the
portable engine establishes a measured baseline.

Phase 16 has no unresolved design blocker. Later phases have explicit dependency
gates, and Phase 26 remains prohibited unless Phase 25 records one positive
backend decision. “Ready” does not waive each phase's required start-of-phase
dependency/advisory revalidation or its exit tests.

## Findings and corrections

### R-001 — Codec dependency breadth was not a complete protocol contract

Severity: blocking before Phase 17; closed

Current etherparse documentation covers the base Ethernet/VLAN/ARP/IP/TCP/UDP
families but explicitly says not every IPv6 extension or ICMP/ICMPv6 message is
supported and that its API may change. The plan now requires Phase 16 to record
a coverage/ownership matrix. Missing accepted codecs are implemented behind
project-owned bounded types; deferral requires a scope decision and blocks the
owning phase's exit. Dependency gaps may not silently shrink scope, and
dependency fragment reassembly remains unused.

### R-002 — “Strong correlation” was too broad for every probe family

Severity: correctness; closed

ARP, NDP, direct UDP responses, and short ICMP quotes cannot all return a
session token equivalent to a TCP acknowledgment or token-bearing Echo reply.
The plan now defines protocol-specific evidence strength. Strong TCP requires a
valid acknowledgment of the outstanding sequence token; strong Echo requires
identifier, sequence, and payload token. Other evidence is labeled as weaker
tuple/interface/window correlation. Ambiguous source-port or identifier reuse is
forbidden through the late-response grace period.

### R-003 — IPv6 opaque-header and NDP validation rules needed precision

Severity: parser correctness; closed

Phase 17 now stops explicitly at ESP, unknown Next Header, or No Next Header and
does not scan ahead for transport bytes. Phase 18 now requires the ICMPv6
pseudo-header checksum and RFC 4861 message-specific source, destination, hop
limit, code, minimum-length, option-length, target, and flag validations.
Opaque, non-first-fragment, and insufficient-quote inputs cannot produce guessed
scan results.

### R-004 — Route results needed a concrete generation-race proof

Severity: correctness; closed

A targeted kernel route reply can race a link/address/route/neighbor
notification. Phase 20 now captures the context generation, serializes the query
with notification publication, drains received changes, and retries within the
query deadline if the generation changed. Results are never relabeled onto a
newer snapshot. Interrupted/overrun/error dumps remain incomplete rather than
partial success.

### R-005 — Network namespace and supported-link behavior were implicit

Severity: API/platform scope; closed

The initial portable scanner is now explicitly limited to Ethernet II, up to two
VLAN tags, and local/loopback raw-IP routes. Unsupported hardware, tunnel,
point-to-point, and encapsulation plans return structured errors. Context and
scan descriptors remain in the network namespace where they were created; the
addon never calls `setns()` from a multithreaded Node process. Namespace tests
launch Node inside the desired namespace.

### R-006 — Native runtime and N-API completion isolation needed a fixed shape

Severity: lifecycle and availability; closed

Phase 22 now uses one bounded runtime per Node environment, not process-global
state or a thread per probe. It multiplexes bounded scanner/session counts over
an environment control wakeup, scheduler/I/O worker, context driver, and
completion bridge. Completion capacity is reserved at operation admission, and
the I/O worker never blocks on JavaScript callback delivery. Environment cleanup
invalidates delivery and uses a teardown-safe asynchronous join path rather than
an unbounded Node-thread join; it never calls N-API after the environment is
invalid.

### R-007 — Result backpressure and rate ceilings needed complete accounting

Severity: resource/network safety; closed

Each admitted probe now reserves worst-case terminal-result capacity before it
is transmitted, allowing already-admitted work to settle after the result queue
stops new sends. All emitted neighbor-resolution, probe, retry, and optional
cleanup frames consume the configured rate/outstanding budgets. Positive and
terminal results are lossless except when explicit session close requests and
counts disposal of undrained results.

### R-008 — Portable packet-socket receive semantics needed explicit handling

Severity: live-result correctness; closed

Phase 22 now ignores `PACKET_OUTGOING` in software for the entire supported
kernel baseline, rejects truncated frames, interprets `PACKET_AUXDATA` VLAN
metadata, and accounts reset-on-read packet statistics correctly. Promiscuous or
all-multicast mode is not enabled by default. Local/loopback routes use raw IP
sockets rather than fabricated Ethernet headers.

### R-009 — Pull/cancel/close semantics contained observable ambiguity

Severity: public API; closed

Cancellation reasons are copied strings rather than arbitrary retained
JavaScript objects. Aborting `nextBatch()` cancels only that wait. Natural
completion and cancel drain sealed batches before terminal `null`; explicit
close discards and counts undrained data and causes pending/future pulls to
return `null`. The terminal summary is cached after native I/O ownership ends.
Pause stops new transmission after its promise resolves while receive and
deadlines continue.

### R-010 — The extreme-backend threshold and XDP ownership policy were loose

Severity: scope and host-state safety; closed

Phase 25 now compares identical preregistered workloads on the same isolated
hardware for at least ten steady-state repetitions. A backend must exceed the
threshold with a bootstrap 95% confidence interval: at least 1.5x matched-result
throughput at no greater CPU budget, or 30% lower CPU at equal throughput, with
equal results/loss and no unaccepted material regression. AF_XDP dependency/ABI
cost is separately reviewed. An AF_XDP mode does not replace an operator-owned
program by default and detaches only an identity-matching module-owned
attachment with a crash-safe ownership mechanism.

## Phase readiness

| Phase | Readiness             | Blocking start condition                                                 |
| ----- | --------------------- | ------------------------------------------------------------------------ |
| 16    | ready next            | revalidate and record exact codec dependency before changing locks       |
| 17    | ready after 16        | Phase 16 coverage matrix, bounds, fuzz smoke, and golden foundation pass |
| 18    | ready after 17        | L2/L3/template parity passes; correlation primitive review is recorded   |
| 19    | ready after 18        | stable project-owned protocol/evidence types exist                       |
| 20    | ready after 19        | bounded complete snapshots pass churn/interruption tests                 |
| 21    | ready after 18 and 20 | route-generation and evidence contracts are frozen                       |
| 22    | ready after 21        | virtual-clock lifecycle/classification matrix passes                     |
| 23    | ready after 22        | portable live correctness, teardown, and memory bounds pass              |
| 24    | ready after 23        | result schema and backpressure contract are frozen                       |
| 25    | ready after 24        | portable scanner is independently release-capable                        |
| 26    | conditional only      | Phase 25 selects one backend and records its ownership contract          |

## Confirmed external constraints

- `CAP_NET_RAW` is required when Phase 22 opens packet/raw scan descriptors;
  read-only context inspection itself does not elevate privilege.
- Native AArch64 execution remains a publication gate. Cross-compilation alone
  is not release verification.
- Linux kernel 4.18 and glibc 2.28 remain the portable package baseline.
  Optional AF_XDP capabilities may require a newer kernel/driver without raising
  that baseline.
- Performance thresholds require suitable physical hardware and are not shared-
  CI timing gates.

## Primary technical confirmations

- Current
  [`etherparse` documentation](https://docs.rs/etherparse/latest/etherparse/)
  describes zero-allocation parsing for the planned base families, explicit lax
  parsing for truncated packets, incomplete ICMP/ICMPv6 breadth, and a changing
  API; this supports the wrapper and coverage-matrix decision.
- Linux documents interrupted dumps through
  [`NLM_F_DUMP_INTR`](https://www.kernel.org/doc/html/latest/core-api/netlink.html#support-dump-consistency)
  and exposes route-query source/destination/interface/protocol/port/mark/UID
  inputs in the
  [route netlink specification](https://docs.kernel.org/netlink/specs/rt-route.html).
- [`packet(7)`](https://man7.org/linux/man-pages/man7/packet.7.html) defines
  `PACKET_OUTGOING`, VLAN auxdata, ring ownership/status, and reset-on-read
  statistics used by the portable receive contract.
- [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443.html) requires the IPv6
  pseudo-header in ICMPv6 checksums, while
  [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861.html) defines hop-limit 255
  and the message-specific NDP validation rules.
- Linux's [AF_XDP documentation](https://docs.kernel.org/networking/af_xdp.html)
  confirms the mandatory XDP/XSKMAP path, queue match, UMEM ownership, and
  single-producer/single-consumer ring constraints that keep it conditional.
- Node 26's
  [Node-API documentation](https://nodejs.org/api/n-api.html#napi_add_async_cleanup_hook)
  provides a stable asynchronous cleanup hook and warns that Worker environments
  may terminate with JavaScript execution already disallowed, supporting the
  reviewed teardown contract.
- Nmap's
  [scan algorithm description](https://nmap.org/book/port-scanning-algorithms.html)
  confirms the need for RTT variance, bounded outstanding state, late-response
  retention, congestion control, and adaptive retransmission rather than a
  fixed-rate-only scheduler.

## Final readiness conclusion

The reviewed plan is internally coherent, implementable in the current monorepo,
bounded at every hostile or asynchronous boundary, and sufficiently specific to
begin Phase 16 without making Phase 17 or scanner API decisions prematurely. Any
implementation that changes a package boundary, permits network mutation,
weakens evidence labels, bypasses rate/result reservations, adds unsupported
link inference, or starts an extreme backend without the Phase 25 decision must
update D-031 and undergo another plan review first.
