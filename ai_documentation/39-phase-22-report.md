# Phase 22 completion report

Date: 2026-07-14

## Outcome

Phase 22 is implemented. The private `@opsimathically/nodenetscanner` workspace
is now a buildable TypeScript/N-API package backed by the new
`nodenetscanner-native` crate. It connects the completed protocol, read-only
Linux context, and deterministic scheduler crates to a portable live Linux data
plane without depending on the `nodenetraw` JavaScript package or sharing its
descriptors.

The package intentionally remains `private: true` at `0.0.0`. Phase 23 still
owns the stable compact batch representation, and Phase 24 owns public API and
artifact release hardening.

## Runtime and ownership

One runtime is created per Node environment. A single named Rust worker owns its
`epoll` instance, `eventfd` control wakeup, route context, raw and packet socket
descriptors, native packet buffers, scheduler timers, result queues, and session
secrets. There is no process-global scanner state. The runtime accepts at most
four scanner objects, four concurrent live sessions, 64 pending asynchronous
control operations, and a 128-command queue. Driving, command, receive, active,
grace, target, prefix, and result work have independent finite budgets. Wire
route/token state is marked as results settle and removed after the same finite
late-response grace window, so draining result batches cannot let native
correlation storage grow with total historical targets.

Node-API tasks wait for command replies outside the JavaScript event loop. The
I/O worker never calls or waits on JavaScript. napi-rs's asynchronous
environment cleanup hook stops admission, wakes the worker, and joins it; object
finalizers use the same idempotent shutdown path. Scanner and session close are
idempotent, terminal summaries remain owned after I/O teardown, and explicit
session close accounts for intentionally discarded undrained results.

All unavoidable Linux ABI calls are isolated in `socket.rs`, where descriptors
are immediately converted to `OwnedFd`. Each `unsafe` block has a local
`SAFETY:` argument for initialized storage, checked lengths, stable pointers, or
kernel syscall ownership. No raw pointer or descriptor crosses N-API.

## Packet and route data plane

Session creation validates the complete immutable plan before opening raw
sockets. Targets and exclusions retain the engine's compact interval form;
ports, payload, deadline, timing, rate, retry, VLAN, source/interface, seed, and
source-port range each have checked bounds. Every session receives a separate
operating-system-random correlation secret; a reproducible scheduling seed is
never used as that secret.

Read-only route context selects interface, source address, next hop, and link
kind. Supported Ethernet paths use nonblocking `AF_PACKET`; explicit 802.1Q
plans build tagged frames. Loopback and local routes use nonblocking IPv4/IPv6
raw IP sockets instead of fabricated Ethernet headers. Unsupported route and
link combinations fail explicitly. ARP and Neighbor Solicitation may populate
only a session-local neighbor map from validated replies; no netlink neighbor,
route, address, link, firewall, or namespace mutation exists in the addon.

The worker drains subscribed route notifications and tracks the published
generation. A generation change losslessly settles probes joined to stale
context as `contextInvalidated`, then restores admission against the new
snapshot. A malformed or unavailable context becomes a structured failed
terminal summary rather than being misreported as ordinary cancellation.

The wire implementation covers ARP, NDP with IPv6 hop limit 255, ICMPv4/v6 Echo,
TCP SYN, and UDP over IPv4 and IPv6. It uses the protocol crate for checked
construction, checksums, parsing, quote handling, keyed correlation, and
evidence classification. TCP/UDP source ports are separated by environment
session lane and probe slot across the outstanding/grace window.

Packet receive rejects truncated data, ignores `PACKET_OUTGOING`, and consumes
`PACKET_AUXDATA` so a VLAN tag removed by kernel or hardware offload is restored
before parsing. When the kernel explicitly reports `TP_STATUS_CSUMNOTREADY`, the
addon completes the transport checksum in a private packet copy before strict
parsing; it does not waive checksum validation for ordinary packets. Packet
statistics are converted from reset-on-read observations into saturating
lifetime session accounting. Raw receive paths retain the family-specific kernel
framing distinction.

## Public TypeScript preview

The package exports `inspectNetworkContext()`, `createScanner()`, `Scanner`,
`ScanSession`, plan/result/context types, and `ScannerError`. Context inspection
and scanner creation require no raw-socket authority. `start()` reports a
structured permission error with Linux operation and `errno` when the namespace
lacks raw authority.

Plans require explicit targets, probes, and an overall deadline. Results are
delivered only through `nextBatch()`; the initial owned object-vector batch is
bounded to 4,096 rows and will be replaced or versioned only in Phase 23.
`pause()` stops new transmission while receive and timeout work continues;
`cancel()` and `summary()` await native terminal cleanup; terminal queued
results remain drainable before `null`; explicit close discards and accounts for
remaining rows.

The package README includes full context, scan, batch-draining, error, VLAN,
lifecycle, privilege, accuracy, source-port, host-reset, and support examples.

## Verification evidence

The Phase 22 unit and ordinary integration suites cover:

- invalid and bounded plan conversion before raw socket creation;
- environment creation and read-only context inspection without privilege;
- idempotent scanner cleanup and structured permission behavior;
- result-capacity reservation and bounded pull conversion;
- Ethernet multicast mapping, VLAN encode/auxdata reconstruction, NDP hop-limit
  and checksum parsing; and
- Rust formatting, Clippy warning denial, workspace tests, strict TypeScript,
  ESLint, Prettier, and public declaration fixtures.

The isolated namespace suite builds a dual-stack veth topology and an explicit
VLAN 42 subinterface, runs IPv4/IPv6 TCP and UDP targets in a second network
namespace, and asserts ARP, NDP, ICMPv4/v6 Echo, TCP open/closed, UDP
open/closed, loopback raw-IP, and tagged Ethernet results. The wrapper supports
an interactive `sudo npm run test:phase22:namespace` flow while preserving the
invoking user's build ownership.

Canonical verification commands are:

```sh
npm run format:check
npm run lint
npm run typecheck
npm run rust:fmt
npm run rust:clippy
npm run rust:test
npm test
npm run test:phase22
npm run test:phase22:namespace
```

The ordinary x86-64 gates and live namespace matrix pass locally. The live gate
found and now covers cross-namespace veth peer normalization, explicit fixture
readiness/cleanup, and veth checksum-offload receive metadata. The AArch64
cross-compilation check passes. Native AArch64 execution is still untested and
remains a publication gate.

## Scope confirmation and next action

Phase 22 adds no compact typed-array batch ABI, batch event adapter, public
package artifacts, firewall management, kernel neighbor writes, namespace
switching, promiscuous capture, packet mmap, or AF_XDP backend.

Phase 23 is next: freeze a versioned compact result schema, make backpressure
use explicit high/low watermarks, add cancellable single-pull ordering and
progress accounting, and optionally layer one bounded batch event adapter over
the pull API.
