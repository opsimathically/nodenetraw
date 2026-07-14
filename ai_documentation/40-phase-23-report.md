# Phase 23 completion report

Date: 2026-07-14

## Outcome

Phase 23 is complete. Scanner results no longer cross N-API as one mapped object
per probe. The native worker seals bounded Rust-owned column vectors, the N-API
resolve boundary converts them to initialized Node buffers, and TypeScript
copies them into ordinary transferable `ArrayBuffer` storage. The worker never
owns or drops a JavaScript-managed buffer.

The public package now provides lazy row views and compatibility iteration,
worker-ordered abortable pulls, exact coalesced progress snapshots, queue
hysteresis, bounded plan/control admission, and a batch-only Node event adapter.
D-037 freezes this boundary.

## Frozen schema version 1

Each batch has 1–4,096 rows and at most 4 MiB of UTF-8 metadata. IP address
octets remain in network byte order. All fixed-width integer columns use
little-endian encoding.

| Column                 | Encoding                                                           |
| ---------------------- | ------------------------------------------------------------------ |
| addresses              | packed 4-byte IPv4 or 16-byte IPv6 octets plus `u32` offsets       |
| families               | explicit `4` or `6` per row                                        |
| scopes                 | `u32`; zero means absent                                           |
| probes                 | `u8`: ARP 1, NDP 2, ICMPv4 Echo 3, ICMPv6 Echo 4, TCP SYN 5, UDP 6 |
| ports                  | `u16`; zero means absent                                           |
| states                 | `u8`; zero absent, then open through down-by-policy as 1–8         |
| outcomes               | `u8`: network 1, cancelled 2, deadline 3, transport 4, context 5   |
| attempts/transmissions | independent `u32` columns                                          |
| RTT                    | `u64` nanoseconds; `u64::MAX` means absent                         |
| terminal timestamp     | `u64` nanoseconds from the session monotonic origin                |
| route generation       | exact `u64`                                                        |
| evidence               | `u8`; zero absent, tuple/quote/TCP32/payload128 as 1–4             |
| reason metadata        | fatal UTF-8 plus bounded monotonic `u32` offsets                   |

The engine's deterministic clock is microsecond-based, so current native RTT and
timestamp values have microsecond resolution widened exactly to nanoseconds. No
wall-clock value participates in result ordering.

## TypeScript API

`ScanResultBatch` exposes `length`, `at()`, iteration, lazy filtering,
`materialize()`, the lazy indexable `results` compatibility view, raw copied
columns, and `transferList()`. `ScanResultView` performs checked decoding only
when a property is accessed. Values wider than JavaScript's safe integer range
remain `bigint`. Invalid lengths, offsets, codes, UTF-8, or detached storage
fail with `ERR_INVALID_BATCH`.

`nextBatch({ signal })` assigns a monotonically increasing pull identifier. The
native worker serializes pull and cancel commands, including cancellation that
arrives before the pull task is admitted. An aborted pull rejects with
`AbortError` and leaves the scan running. A batch already sealed by the worker
is delivered before cancellation. There remains at most one pending pull per
session, terminal sessions drain before `null`, and explicit close returns
pending and future pulls as `null` after discarding queued results.

`progress()` reports exact `bigint` counts for sent, received, matched,
duplicate, invalid, timed out, retried, kernel dropped, application
backpressured, and coalesced updates. `session.batches()` supplies an optional
batch-only `EventEmitter` with explicit `start()`, `resume()`, awaitable
`pause()`, awaitable ownership-returning `detach()`, and idempotent `close()`.
It uses one `nextBatch()` and no parallel receive path.

## Bounds and backpressure

- a plan/control command is rejected above 65,536 items or 4 MiB before native
  admission;
- a batch contains at most 4,096 results and 4 MiB of metadata;
- the native result queue remains capped at 262,144 terminal results;
- saturation stops new result reservation and therefore new transmission;
- admission resumes only at the half-capacity low-water mark;
- a pending pull coalesces new rows for at most one bounded 2 ms worker
  interval, while a requested-full or terminal batch seals immediately;
- receive processing, evidence settlement, expiry, cancel, close, and pulls
  continue while transmit admission is paused; and
- no positive or terminal result is dropped except the already documented,
  counted discard requested by explicit session close.

## Safety review

- Native packet, correlation, descriptor, and result-queue storage never crosses
  N-API.
- Only initialized sealed vectors reach N-API resolution.
- Node buffers are created on the N-API resolve side, never retained by the Rust
  worker, then copied into transferable TypeScript-owned storage.
- JavaScript mutation can alter only decoding of that retained batch.
- Transfer detaches the sender's columns; subsequent access fails explicitly.
- Every fixed-width access checks row and exact column size, while variable
  storage checks bounded monotonic offsets and fatal UTF-8.
- Abort, close, terminal drain, and adapter boundaries settle once and never
  reuse pull identifiers.

## Verification

The following gates pass locally on Linux x86-64 with Node.js 26 and Rust
1.97.0:

- `npm run test:phase23`
- `npm run test:phase23:namespace`
- `cargo clippy -p nodenetscanner-native --all-targets --locked -- -D warnings`
- `cargo test -p nodenetscanner-native --locked`
- `npm run ci`
- `cargo check -p nodenetscanner-native --target aarch64-unknown-linux-gnu --locked`

Coverage includes synthetic IPv4/IPv6 columns, values above JavaScript's safe
integer range, lazy/indexed/materialized access, mutation isolation, retained
views, structured-clone transfer and sender detachment, hostile schema lengths
and offsets, AbortSignal delivery races, progress conversion, adapter
start/pause/resume/detach/end/close behavior, high/low-water hysteresis, bounded
control commands, ordinary capability/error behavior, and the live loopback,
dual-stack veth, VLAN, ARP/NDP, ICMPv4/v6, TCP, and UDP matrix.

The isolated loopback batch profile completed 256 TCP rows in four 64-row N-API
pulls. The final recorded local run used 76.25 ms wall time and 44,221 µs
aggregate process CPU; this is informative evidence rather than a
timing-sensitive gate.

Native AArch64 execution remains untested and is still a publication gate.

## Next phase

Phase 24 hardens the portable scanner as a release candidate. It owns API/error
stabilization, documentation completeness, fuzzing, sanitizer and fault
injection, Worker teardown and resource stress, artifact packaging, and final
release evidence. Phase 25 remains an evidence gate; Phase 26 remains
conditional.
