# @opsimathically/nodenetraw

`@opsimathically/nodenetraw` is a Linux-only Node.js native module for low-level
raw socket access. It exposes a TypeScript API backed by Rust through N-API,
with an emphasis on memory safety, correct file-descriptor ownership, stable
Linux error reporting, and a small dependency footprint.

> **Status:** IPv4, IPv6, and raw/cooked Linux packet sockets support typed
> message I/O, metadata, advanced options, packet controls, filter attachment,
> AbortSignal cancellation, stable errors, explicit close, and an optional typed
> event-driven receive adapter. Bounded ICMPv4 checksum, Echo codec, parsing,
> validation, correlation, ICMPv4 diagnostic-error codecs, quoted-packet
> matching, RFC 4884 extension parsing, Router Discovery, Timestamp and legacy
> Address Mask codecs, one-operation socket helpers, and bounded conventional
> ICMP Echo traceroute are also available. Version `0.1.0-rc.6` is an
> unpublished release candidate.

The initial support baseline is Node.js 26+, Rust 1.97.0 (updated with each
stable Rust release), and 64-bit glibc Linux on x86-64 or AArch64 with kernel
4.18+ and glibc 2.28+.

> **Architecture verification:** x86-64 is tested. AArch64 (also called ARM64)
> is an intended build target but is currently untested because no ARM64 test
> machine is available. Treat ARM64 packages as experimental until they pass on
> native AArch64 hardware or a native AArch64 CI runner.

## Direction

The package is developed in the `nodenet` monorepo and is intended to remain
Node's policy-free, memory-safe bridge to Linux raw packet networking. Scanner
policy and orchestration belong to the separate planned `nodenetscanner`
package; reusable performance-sensitive Rust code may be shared at compile time
without expanding this package's public scope. The separation and phased scanner
design are documented in the
[network and scanner evolution plan](../../ai_documentation/31-network-and-scanner-evolution-plan.md).

The project is intended to become Node's memory-safe bridge to Linux raw packet
networking: IPv4 and IPv6 raw IP, `AF_PACKET`, message flags and ancillary data,
extended errors and timestamps, filters, bounded batching, and measured packet
rings. It is deliberately Linux-specific so the API can describe kernel
semantics honestly instead of presenting incomplete portable abstractions.

The design separates responsibilities:

- TypeScript provides the public package surface, types, and Node conventions.
- Rust owns sockets, native buffers, syscall interaction, and lifecycle rules.
- N-API provides the ABI-stable bridge between Node.js and the Rust library.

Opening raw sockets commonly requires elevated Linux capabilities such as
`CAP_NET_RAW` (or sufficient privilege in the governing user/network namespace).
The library reports permission failures; it does not attempt to grant itself
privileges.

## Project principles

- Safe-by-default ownership and cleanup of native resources.
- No blocking network operations on the Node.js event-loop thread.
- Explicit validation at every language and kernel boundary.
- Linux errors represented without losing operation or `errno` context.
- Strict TypeScript, ESLint, and Prettier from the first implementation phase.
- Minimal runtime dependencies and justified development dependencies.
- Privileged tests kept opt-in and isolated from normal development and CI.

The package is ESM-only, built with npm and napi-rs v3 against Node-API 10. The
current slice covers IPv4/IPv6 raw IP and Linux raw/cooked packet sockets,
including advanced options, filters, bounded batches, and receive-only
TPACKET_V3 rings.

The x86-64 release artifact is built with napi-rs's pinned GNU compatibility
toolchain and rejected unless ELF inspection proves that its required glibc
symbols are at or below 2.28. This verifies the addon's link baseline; the
package still requires glibc 2.28 because that is the supported Node 26 floor.

Phases 5 through 11 are complete: bounded message I/O, cancellation, IPv4/IPv6,
Linux `AF_PACKET`, advanced configuration, filtering, batching, and measured
receive-ring work are in place, together with the event receive adapter,
fuzz/sanitizer gates, and target-specific release rehearsal. See the
[full capability plan](../../ai_documentation/11-full-capability-plan.md).

Phases 12 through 15 are implemented with zero-dependency ICMPv4 checksum, Echo,
diagnostic-error, Router Discovery, Timestamp, and deprecated Address Mask
construction; standalone and Linux raw-receive parsing; quoted-packet
correlation; RFC 4884 extensions; validation; socket helpers; and bounded
increasing-TTL ICMP Echo traceroute. See the
[ICMP and traceroute plan](../../ai_documentation/23-icmp-and-traceroute-plan.md)
and its
[preimplementation review](../../ai_documentation/24-icmp-plan-review.md).

## Supported feature matrix

| Area                                       | Status                | Conditions                                                                               |
| ------------------------------------------ | --------------------- | ---------------------------------------------------------------------------------------- |
| IPv4 and IPv6 raw sockets                  | Implemented           | Usually requires `CAP_NET_RAW`                                                           |
| `AF_PACKET` raw/cooked sockets             | Implemented           | Linux interface and `CAP_NET_RAW` required                                               |
| Ancillary data and error queues            | Implemented           | Individual controls/options remain kernel-dependent                                      |
| Typed/common/opaque options                | Implemented           | Privileged options may return `EPERM`; opaque tuples exclude ownership-sensitive options |
| Classic BPF and compatible eBPF attachment | Implemented           | Linux verifier applies; this module does not load eBPF programs                          |
| `sendmmsg`/`recvmmsg` batches              | Implemented           | 64 messages and 1 MiB per operation                                                      |
| TPACKET_V3 receive ring                    | Implemented           | Receive-only, copied frame leases, 64 MiB per ring                                       |
| Typed EventEmitter receive adapter         | Implemented           | One bounded receive per source; normal and error-queue lanes are independent             |
| ICMPv4 Echo utilities                      | Implemented           | Phase 12; bounded owned codecs and helpers over existing IPv4 ICMP sockets               |
| ICMPv4 diagnostic-error utilities          | Implemented           | Phase 13; bounded quotes, error codecs, MTU, correlation, and RFC 4884 envelopes         |
| ICMPv4 informational utilities             | Implemented           | Phase 14; Router Discovery, Timestamp, and deprecated Address Mask formats               |
| ICMP Echo traceroute utilities             | Implemented           | Phase 15; bounded conventional TTL-limited probes, not deprecated ICMP type 30           |
| Hardware timestamps and driver behavior    | Capability-detected   | Not a portable release gate                                                              |
| TX packet mmap and AF_XDP                  | Unsupported           | Require separate ownership and performance reviews                                       |
| x86-64 glibc Linux                         | Tested                | Kernel 4.18+, glibc 2.28+, Node 26+                                                      |
| AArch64/ARM64 glibc Linux                  | Untested/experimental | Intended target; requires verification on a native ARM64 runner                          |
| musl, non-Linux, and 32-bit targets        | Unsupported           | No fallback or install-time download                                                     |

## API

```ts
import { IPPROTO_ICMP, RawSocket } from "@opsimathically/nodenetraw";

const socket = await RawSocket.open({ protocol: IPPROTO_ICMP });

try {
  await socket.bind("127.0.0.1");
  await socket.setOption("ipTtl", 64);

  const receive = socket.receive();
  const bytesSent = await socket.send(icmpPacket, "127.0.0.1");
  const packet = await receive;

  console.log(
    bytesSent,
    packet.sourceAddress,
    packet.packetLength,
    packet.ipv4?.destinationAddress,
    packet.data,
  );
} finally {
  await socket.close();
}
```

Message I/O exposes Linux flags and ancillary metadata without numeric flag or
pointer escape hatches:

```ts
await socket.setOption("receivePacketInfo", true);
await socket.setOption("receiveTimestampNanoseconds", true);

const controller = new AbortController();
const incoming = socket.receiveMessage({ signal: controller.signal });
await socket.sendMessage({
  data: icmpPacket,
  destination: { family: "ipv4", address: "127.0.0.1" },
  flags: ["dontRoute"],
  control: [{ kind: "ipv4Ttl", value: 64 }],
});
const message = await incoming;
```

### Promise and event receive styles

Both receive styles produce the same `ReceivedMessage` shape. Use the promise
API when the application should explicitly control every receive, or wrap a
normal `RawSocket` in `RawSocketEventEmitter` when a long-lived Node-style
listener is a better fit. Do not use both styles on the same receive lane at the
same time; `ERR_RECEIVER_ACTIVE` reports accidental competing consumers.

#### Promise-driven repeated reception

The low-level API can receive one message at a time in an explicit loop. Passing
the same `AbortSignal` to every receive gives the application a clean way to
stop even while the loop is waiting for traffic:

```ts
import {
  IPPROTO_ICMP,
  RawSocket,
  RawSocketError,
  type ReceivedMessage,
} from "@opsimathically/nodenetraw";

function handleMessage(message: ReceivedMessage): void {
  console.log(message.source, message.control, message.data);
}

const socket = await RawSocket.open({ protocol: IPPROTO_ICMP });
await socket.bind("127.0.0.1");

const stop = new AbortController();
process.once("SIGINT", () => stop.abort());

try {
  for (;;) {
    try {
      const message = await socket.receiveMessage({ signal: stop.signal });
      handleMessage(message);
    } catch (error: unknown) {
      if (error instanceof RawSocketError && error.code === "ERR_ABORTED") {
        break;
      }
      throw error;
    }
  }
} finally {
  stop.abort();
  await socket.close();
}
```

The same pattern works with a caller-defined loop condition instead of a signal.
The promise API is also the required style for `receiveBatch()` and
`receiveRingFrame()`.

#### Event-driven repeated reception

`RawSocketEventEmitter` owns one receive lane and continuously rearms one
bounded `receiveMessage()` operation. Construction is inert: attach listeners
first, then call `start()` when the application is ready to consume packets.

```ts
import {
  IPPROTO_ICMP,
  RawSocket,
  RawSocketError,
  RawSocketEventEmitter,
} from "@opsimathically/nodenetraw";

const socket = await RawSocket.open({ protocol: IPPROTO_ICMP });
await socket.bind("127.0.0.1");

const source = new RawSocketEventEmitter(socket, {
  dataCapacity: 65_535,
  controlCapacity: 4_096,
});

source.on("message", (message) => {
  console.log(message.source, message.control, message.data);
});
source.on("error", (error: unknown) => {
  if (error instanceof RawSocketError) {
    console.error(error.operation, error.code, error.errnoName);
  } else {
    // With Node's captureRejections enabled, this may be a listener rejection.
    console.error("event listener failed", error);
  }
});
source.once("close", () => console.log("socket closed"));

async function pauseReception(): Promise<void> {
  // Stop admission and wait for a stable boundary with no later message event.
  await source.pause();
  console.log(source.status); // "paused"
}

function resumeReception(): void {
  source.resume();
}

source.start(); // Continues emitting messages until paused, detached, or closed.

process.once("SIGINT", () => {
  // close() also closes the wrapped RawSocket and emits `close` exactly once.
  void source.close().catch((error: unknown) => {
    console.error("socket close failed", error);
  });
});
```

Message listeners run synchronously and in registration order, as with Node's
`EventEmitter`. The adapter does not start a second receive until synchronous
dispatch of the current message finishes, but it does not await promises
returned by async listeners. Use `pauseReception()` or an application queue when
asynchronous work needs explicit backpressure, then call `resumeReception()`.
Sending and socket option methods can still be used directly on `socket` while
the adapter owns reception.

| Choose promises when…                              | Choose events when…                                  |
| -------------------------------------------------- | ---------------------------------------------------- |
| each receive belongs to an explicit async workflow | a long-lived Node-style message listener is natural  |
| you need caller-owned cancellation or batching     | one ordered message at a time is the desired pacing  |
| you use `receiveRingFrame()` leases                | you use ordinary non-ring `receiveMessage()` results |

Construction snapshots its options but does not start receiving. `start()` and
`resume()` return the source synchronously. `pause()` returns a cached boundary
promise and resolves only after an already-received message or error has been
dispatched. To return to promise-driven reception without closing the socket,
use `detach()` instead of `close()`. It permanently quiesces the source,
releases its receive lane, and resolves to the still-open `RawSocket`:

```ts
await source.pause();
const lowLevelSocket = await source.detach();
const next = await lowLevelSocket.receiveMessage();
```

The readonly status is one of `idle`, `running`, `pausing`, `paused`,
`detaching`, `detached`, `closing`, or `closed`. Invalid lifecycle transitions
use `ERR_INVALID_STATE`. An idle or paused source still owns its lane; only
`detach()` or terminal socket close releases it.

Normal traffic and Linux's error queue are separate lanes. At most one event
source can own each lane, so both can operate on the same IP socket:

```ts
await socket.setOption("receiveErrors", true);
const messages = new RawSocketEventEmitter(socket);
const networkErrors = new RawSocketEventEmitter(socket, { errorQueue: true });

const handleReceiveFailure = (error: unknown): void => {
  if (error instanceof RawSocketError) {
    console.error(error.operation, error.code, error.errnoName);
    return;
  }
  console.error("event listener failed", error);
};

networkErrors.on("message", (message) => {
  // These are MSG_ERRQUEUE messages, not EventEmitter `error` events.
  console.log(message.flags, message.control);
});
messages.on("error", handleReceiveFailure);
networkErrors.on("error", handleReceiveFailure);
messages.start();
networkErrors.start();
```

Conflicting direct, batch, ring, or duplicate event receivers fail with
`ERR_RECEIVER_ACTIVE` rather than silently splitting packets. Packet sockets do
not support `errorQueue: true`, and an active TPACKET ring cannot be wrapped by
the message-event adapter. Calling `close()` on either of two lane sources
closes their shared socket; each source emits its own exactly-once `close`.

### Phase 12–15 ICMPv4 quick reference

The ICMPv4 layer is additive: the raw socket API remains available, and the
utilities provide bounded construction, parsing, correlation, and orchestration
when an application does not want to manipulate every wire field itself.

| Task                                                  | Public API                                                                                    | Socket or receive-lane behavior                                                |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Compute or verify an Internet checksum                | `computeInternetChecksum()`, `validateInternetChecksum()`                                     | Pure; no socket or privilege required                                          |
| Construct, parse, or validate standalone ICMPv4 bytes | `encodeIcmpMessage()`, `parseIcmpMessage()`, `validateIcmpMessage()`                          | Pure; input begins at the ICMP type octet                                      |
| Parse bytes returned by a Linux IPv4 raw socket       | `parseIcmpReceivedMessage()`                                                                  | Pure; accepts an existing `ReceivedMessage` containing its IPv4 header         |
| Send or receive one ICMPv4 operation                  | `sendIcmpMessage()`, `receiveIcmpMessage()`                                                   | Uses a caller-owned `IPPROTO_ICMP` socket; receive claims the normal lane once |
| Correlate Echo and quoted diagnostics                 | `matchesIcmpEchoReply()`, `matchIcmpEchoQuote()`                                              | Pure; requires explicit tuple/token evidence                                   |
| Interpret diagnostic, timestamp, or mask values       | `classifyIcmpDestinationUnreachable()`, `classifyIcmpTimestamp()`, `inspectIpv4AddressMask()` | Pure; never changes host configuration                                         |
| Build or classify one traceroute probe                | `createIcmpTracerouteProbe()`, `classifyIcmpTracerouteResponse()`                             | Pure; suitable when the application already owns reception                     |
| Run a bounded conventional Echo traceroute            | `traceIcmpRoute()`                                                                            | Temporarily owns the socket's normal receive lane and leaves the socket open   |

Pure codecs do not require elevated privileges. Opening and using the raw ICMP
socket normally requires `CAP_NET_RAW` or root. Every variable byte field
returned by a parser is an owned bounded copy, so callers may retain results
after the original input goes out of scope.

### ICMPv4 Echo utilities

Phase 12 provides non-mutating Internet-checksum helpers and bounded owned Echo
Request/Reply codecs without changing the low-level socket API. Standalone ICMP
bytes begin at the ICMP type field and use `parseIcmpMessage()`. Linux IPv4 raw
receives include an IPv4 header, so use `parseIcmpReceivedMessage()` for an
existing `ReceivedMessage`, or `receiveIcmpMessage()` for exactly one combined
receive-and-parse operation.

The standalone codec can be used independently of raw sockets—for example in a
packet builder, capture reader, or test fixture:

```ts
import {
  computeInternetChecksum,
  encodeIcmpMessage,
  parseIcmpMessage,
  validateIcmpMessage,
  validateInternetChecksum,
} from "@opsimathically/nodenetraw";

const bytes = encodeIcmpMessage({
  kind: "echoRequest",
  identifier: 0x4e52,
  sequence: 1,
  data: new TextEncoder().encode("hello"),
});

console.log(computeInternetChecksum(bytes)); // 0 for a complete valid message
console.log(validateInternetChecksum(bytes)); // true

const validation = validateIcmpMessage(bytes, {
  checksum: "require",
  conformance: "canonical",
});
if (!validation.valid) {
  console.error(validation.error, validation.issues);
}

const parsed = parseIcmpMessage(bytes);
if (parsed.ok && parsed.packet.message.kind === "echoRequest") {
  console.log(parsed.packet.message.identifier, parsed.packet.message.data);
} else if (!parsed.ok) {
  // Malformed network input is a structured result rather than a thrown error.
  console.error(parsed.error.reason, parsed.checksumStatus, parsed.issues);
}
```

Construction-time misuse—such as an out-of-range identifier or oversized
payload—throws `RawSocketError` with `ERR_INVALID_ARGUMENT`. Packet defects
found while parsing are normally returned through `ok: false`, `error`,
`checksumStatus`, and `issues`, allowing untrusted traffic to be inspected
without exception-driven packet handling. `compatible` conformance is the
receive default; request `canonical` when validating locally generated bytes.

This promise-driven example sends one Echo Request and keeps consuming explicit
one-shot receives until its strongly correlated reply arrives. Raw sockets may
also observe the outbound request and unrelated ICMP traffic, so one receive is
not assumed to be the reply:

```ts
import {
  IPPROTO_ICMP,
  RawSocket,
  matchesIcmpEchoReply,
  receiveIcmpMessage,
  sendIcmpMessage,
} from "@opsimathically/nodenetraw";

const socket = await RawSocket.open({ protocol: IPPROTO_ICMP });
const stop = new AbortController();
const timeout = setTimeout(() => stop.abort(), 2_000);
const identifier = 0x4e52;
const sequence = 1;
const token = new TextEncoder().encode("request-1");

try {
  await socket.bind("127.0.0.1");
  const firstReceive = receiveIcmpMessage(socket, { signal: stop.signal });
  await sendIcmpMessage(
    socket,
    { kind: "echoRequest", identifier, sequence, data: token },
    {
      destination: { family: "ipv4", address: "127.0.0.1" },
      ttl: 64,
      signal: stop.signal,
    },
  );

  let received = await firstReceive;
  while (
    !matchesIcmpEchoReply(received, {
      identifier,
      sequence,
      expectedSourceAddress: "127.0.0.1",
      token,
    })
  ) {
    received = await receiveIcmpMessage(socket, { signal: stop.signal });
  }
  if (!received.ok) throw new Error("correlated reply was not parseable");
  console.log(received.ipv4, received.packet.message);
} finally {
  clearTimeout(timeout);
  stop.abort();
  await socket.close();
}
```

Event-driven applications retain the same single receive engine. Parse each
ordinary event synchronously; the ICMP layer does not create another emitter or
hidden queue:

```ts
import {
  IPPROTO_ICMP,
  RawSocket,
  RawSocketEventEmitter,
  matchesIcmpEchoReply,
  parseIcmpReceivedMessage,
  sendIcmpMessage,
} from "@opsimathically/nodenetraw";

const socket = await RawSocket.open({ protocol: IPPROTO_ICMP });
const source = new RawSocketEventEmitter(socket);
const identifier = 0x4e52;
const sequence = 2;
const token = new TextEncoder().encode("request-2");

source.on("message", (message) => {
  const parsed = parseIcmpReceivedMessage(message);
  if (
    parsed.ok &&
    matchesIcmpEchoReply(parsed, { identifier, sequence, token })
  ) {
    console.log("reply from", parsed.ipv4.sourceAddress);
  }
});
source.on("error", console.error);
source.start();

process.once("SIGINT", () => void source.close());

await sendIcmpMessage(
  socket,
  { kind: "echoRequest", identifier, sequence, data: token },
  { destination: { family: "ipv4", address: "127.0.0.1" } },
);
```

`receiveIcmpMessage()` performs exactly one normal-lane receive and never skips
traffic internally. It conflicts predictably with an event source owning that
lane. Checksum verification defaults to `require`; `report` and `ignore` are
explicit parser policies. Decodable unknown types/codes remain available as
owned bytes and validation issues rather than being mislabeled.

### ICMPv4 diagnostic errors and quoted packets

Phase 13 adds Destination Unreachable (including Fragmentation Needed), Time
Exceeded, Parameter Problem, and Redirect. Builders require a valid quoted IPv4
header with its checksum and the required leading payload bytes. They never
choose traffic to answer, send automatically, accept a Redirect, or alter host
routing; those decisions remain application policy.

The same `encodeIcmpMessage()` and `sendIcmpMessage()` APIs used for Echo accept
the diagnostic message unions. Named constants keep codes readable:

```ts
import {
  ICMP_FRAG_NEEDED,
  IPPROTO_ICMP,
  RawSocket,
  sendIcmpMessage,
} from "@opsimathically/nodenetraw";

async function reportMtu(
  socket: RawSocket,
  recipient: string,
  quotedIpv4Datagram: Uint8Array,
): Promise<void> {
  if (socket.protocol !== IPPROTO_ICMP) throw new Error("ICMP socket required");

  await sendIcmpMessage(
    socket,
    {
      kind: "destinationUnreachable",
      code: ICMP_FRAG_NEEDED,
      nextHopMtu: 1_500,
      quote: quotedIpv4Datagram,
      extensions: [
        {
          // Unknown/private object classes are preserved as bounded bytes.
          classNumber: 250,
          cType: 1,
          data: Uint8Array.of(0x00, 0x00, 0x05, 0xdc),
        },
      ],
    },
    { destination: { family: "ipv4", address: recipient } },
  );
}
```

On receive, parsed diagnostics retain the bounded quoted IPv4 bytes and expose
checked header/ICMP-prefix evidence. `matchIcmpEchoQuote()` reports `strong`
when the complete token is available, `weak` for a matching historical short
quote, or an unmatched result. An event source continues to own the only receive
loop:

```ts
import {
  ICMP_FRAG_NEEDED,
  IPPROTO_ICMP,
  RawSocket,
  RawSocketEventEmitter,
  matchIcmpEchoQuote,
  parseIcmpReceivedMessage,
} from "@opsimathically/nodenetraw";

const socket = await RawSocket.open({ protocol: IPPROTO_ICMP });
const source = new RawSocketEventEmitter(socket);

source.on("message", (received) => {
  const parsed = parseIcmpReceivedMessage(received);
  if (!parsed.ok || parsed.packet.message.kind !== "destinationUnreachable") {
    return;
  }

  const diagnostic = parsed.packet.message;
  const correlation = matchIcmpEchoQuote(diagnostic.quote, {
    expectedDestinationAddress: "198.51.100.9",
    identifier: 0x4e52,
    sequence: 1,
    token: new TextEncoder().encode("request-1"),
  });
  if (correlation.matched) {
    console.log({
      code: diagnostic.code,
      fragmentationNeeded: diagnostic.code === ICMP_FRAG_NEEDED,
      nextHopMtu: diagnostic.nextHopMtu,
      strength: correlation.strength,
      extensions: diagnostic.extensions?.objects,
    });
  }
});
source.on("error", console.error);
source.start();
```

RFC 4884 extension construction uses `{ classNumber, cType, data }` and
preserves unknown object classes as owned bytes. Compliant length framing is the
default. Set `legacyExtensions: true` only when parsing peers that used the old
fixed 128-byte boundary; a zero quote-length byte otherwise means no extension.
The extension checksum and object bounds are reported separately from the outer
ICMP checksum. ICMP messages remain unauthenticated network input.

### ICMPv4 Router Discovery and legacy informational messages

Phase 14 adds explicit Router Solicitation/Advertisement, Timestamp
Request/Reply, and Address Mask Request/Reply values to the same codec and
socket helpers. The library does not schedule solicitations or advertisements,
select a router, answer requests, read or change a clock, or apply a mask.

Router Discovery builders use standard two-word address entries. Parsed
advertisements retain larger forward-compatible entries as `extensionWords` and
preserve ignored trailing bytes. A preference of `-2147483648` is exposed as not
default-eligible rather than silently discarded:

```ts
import {
  IPPROTO_ICMP,
  RawSocket,
  sendIcmpMessage,
} from "@opsimathically/nodenetraw";

const socket = await RawSocket.open({ protocol: IPPROTO_ICMP });

// Multicast Router Discovery receives a per-message TTL of 1 automatically.
// The caller still chooses the source/interface and any multicast membership.
await sendIcmpMessage(
  socket,
  { kind: "routerSolicitation" },
  { destination: { family: "ipv4", address: "224.0.0.2" } },
);

await sendIcmpMessage(
  socket,
  {
    kind: "routerAdvertisement",
    lifetime: 1_800,
    addresses: [{ address: "192.0.2.1", preference: 0 }],
  },
  { destination: { family: "ipv4", address: "224.0.0.1" } },
);
```

The correct all-routers/all-systems multicast destination is enforced, and a
conflicting TTL is rejected. Limited broadcast remains explicit: set the
socket's `broadcast` option yourself before sending to `255.255.255.255`. The
helper never enables it automatically.

Receiving these messages uses the same discriminated parse result as Echo and
diagnostic errors. Applications can switch on `message.kind` without manually
reading type numbers:

```ts
import { receiveIcmpMessage, type RawSocket } from "@opsimathically/nodenetraw";

async function inspectInformationalMessage(socket: RawSocket): Promise<void> {
  const parsed = await receiveIcmpMessage(socket);
  if (!parsed.ok) {
    console.warn(parsed.error.reason, parsed.issues);
    return;
  }

  const message = parsed.packet.message;
  switch (message.kind) {
    case "routerAdvertisement":
      console.log(message.lifetime, message.addresses);
      break;
    case "timestampRequest":
    case "timestampReply":
      console.log(message.originateTimestamp);
      break;
    case "addressMaskReply":
      console.log(message.mask.address, message.mask.prefixLength);
      break;
    default:
      console.log("other ICMP message", message.kind);
  }
}
```

Timestamp values are always preserved as raw unsigned 32-bit numbers and
classified as `standard`, `nonStandard`, or `invalidStandardRange`. Request
builders write receive/transmit timestamps as zero; replies require explicit
values or can copy a parsed request tuple with `createIcmpTimestampReply()`:

```ts
import {
  classifyIcmpTimestamp,
  createIcmpTimestampReply,
  encodeIcmpMessage,
  parseIcmpMessage,
} from "@opsimathically/nodenetraw";

const requestBytes = encodeIcmpMessage({
  kind: "timestampRequest",
  identifier: 7,
  sequence: 1,
  originateTimestamp: 12_345,
});
const parsed = parseIcmpMessage(requestBytes);

if (parsed.ok && parsed.packet.message.kind === "timestampRequest") {
  const reply = createIcmpTimestampReply(parsed.packet.message, {
    receiveTimestamp: 12_400,
    transmitTimestamp: 12_450,
  });
  console.log(classifyIcmpTimestamp(reply.transmitTimestamp), reply);
}
```

Address Mask types 17 and 18 are deprecated wire formats. Request construction
always writes a zero mask, while replies require an explicit dotted-decimal
mask. Parsing and `inspectIpv4AddressMask()` report contiguity and a prefix
length when one exists; they do not normalize or apply the value:

```ts
import {
  encodeIcmpMessage,
  inspectIpv4AddressMask,
} from "@opsimathically/nodenetraw";

const legacyReply = encodeIcmpMessage({
  kind: "addressMaskReply",
  identifier: 7,
  sequence: 1,
  mask: "255.255.255.0",
});
console.log(inspectIpv4AddressMask("255.255.255.0")); // prefixLength: 24
void legacyReply;
```

Event-driven consumers continue to call `parseIcmpReceivedMessage()` in their
existing `RawSocketEventEmitter` listener; Phase 14 adds no emitter, timer,
queue, discovery state, or automatic responder. All received ICMP remains
unauthenticated input.

### ICMP Echo traceroute

Phase 15 provides both deterministic probe/classification primitives and a
bounded convenience operation. It implements conventional increasing-TTL Echo
probing; it does not construct the deprecated ICMP Traceroute type 30.

`traceIcmpRoute()` claims the socket's normal receive lane for the operation and
therefore expects a dedicated existing IPv4 `IPPROTO_ICMP` socket. It detaches
on every terminal path and leaves the caller-owned socket open:

```ts
import {
  IPPROTO_ICMP,
  RawSocket,
  traceIcmpRoute,
} from "@opsimathically/nodenetraw";

const traceSocket = await RawSocket.open({ protocol: IPPROTO_ICMP });
const abortController = new AbortController();
try {
  const trace = await traceIcmpRoute(
    traceSocket,
    { family: "ipv4", address: "198.51.100.9" },
    {
      maxHops: 30,
      probesPerHop: 3,
      maxInFlight: 3,
      timeoutMilliseconds: 3_000,
      overallTimeoutMilliseconds: 300_000,
      signal: abortController.signal,
      onProgress: ({ result }) => console.log(result),
    },
  );
  for (const hop of trace.hops) {
    const probes = hop.probes.map((probe) => {
      if (probe.kind === "timeout") return "*";
      const milliseconds = Number(probe.roundTripNanoseconds) / 1_000_000;
      return `${probe.responderAddress} ${milliseconds.toFixed(2)} ms`;
    });
    console.log(hop.hop, ...probes);
  }
  console.log("finished:", trace.termination);
} finally {
  await traceSocket.close();
}
```

Normal completion reports `destination`, `unreachable`, `maxHops`, or
`overallTimeout`. Individual silence is a compact `timeout` probe result.
External cancellation rejects with `ERR_ABORTED` after lane and timer cleanup;
it is not fabricated as a network response. The destination is a literal IPv4
address and no DNS lookup occurs. Do not attach a `RawSocketEventEmitter` or
start another normal-lane receive on the trace socket while the operation is
running; competing consumers fail with `ERR_RECEIVER_ACTIVE`.

Defaults are hops 1–30, three probes per hop, one active probe, a 3-second probe
timeout, a 5-minute overall timeout, and stop-on-unreachable behavior. A random
identifier and 16-byte correlation token are generated unless supplied. Set
explicit values when repeatability matters. `maxInFlight` applies within the
current hop and cannot exceed `probesPerHop`; the operation does not send every
hop concurrently.

Event-driven applications that already own the receive lane can use the pure
builder and classifier instead of the convenience operation:

```ts
import {
  IPPROTO_ICMP,
  RawSocket,
  RawSocketEventEmitter,
  classifyIcmpTracerouteResponse,
  createIcmpTracerouteProbe,
  parseIcmpReceivedMessage,
  sendIcmpMessage,
} from "@opsimathically/nodenetraw";

const eventSocket = await RawSocket.open({ protocol: IPPROTO_ICMP });
const probe = createIcmpTracerouteProbe({
  destination: { family: "ipv4", address: "198.51.100.9" },
  identifier: 0x5152,
  sequence: 1,
  token: Uint8Array.of(0x54, 0x52, 0x43, 0x45),
  ttl: 1,
  sentAt: process.hrtime.bigint(),
});
const events = new RawSocketEventEmitter(eventSocket);
events.on("message", (message) => {
  const receivedAt = process.hrtime.bigint();
  const match = classifyIcmpTracerouteResponse(
    probe,
    parseIcmpReceivedMessage(message),
    receivedAt,
  );
  if (match.matched) console.log(match);
});
events.on("error", console.error);
events.start();
await sendIcmpMessage(
  eventSocket,
  {
    kind: "echoRequest",
    identifier: probe.identifier,
    sequence: probe.sequence,
    data: probe.data,
  },
  { destination: probe.destination, ttl: probe.ttl },
);
```

The convenience operation bounds hops to 255, probes to 10 per hop, token data
to 64 bytes, caller payload to 4,096 bytes, and active probes to 10. Returned
history contains compact response summaries rather than received packets or raw
quotes. Firewalls, ICMP rate limiting, asymmetric or load-balanced paths, NAT
rewriting, and silent routers can produce missing or varying hops. ICMP
responses remain unauthenticated network input and are never applied as routing
policy.

These protocol utilities cover ICMPv4 through Phase 15. ICMPv6 protocol codecs
remain a separate design.

IPv6 uses the same message API with explicit scope and flow fields:

```ts
import { IPPROTO_ICMPV6, RawSocket } from "@opsimathically/nodenetraw";

const socket6 = await RawSocket.open({
  family: "ipv6",
  protocol: IPPROTO_ICMPV6,
});
await socket6.bind({ family: "ipv6", address: "::1" });
const incoming6 = socket6.receiveMessage();
await socket6.sendMessage({
  data: icmpv6Packet,
  destination: { family: "ipv6", address: "::1", scopeId: 0 },
  control: [{ kind: "ipv6HopLimit", value: 64 }],
});
```

IPv6 receive buffers contain protocol payload, not an IPv6 header synthesized by
this library. Packet info, hop limit, traffic class, timestamps, and extended
errors are reported through ancillary controls.

Packet sockets use link-layer addresses and interface indices:

```ts
import {
  ETH_P_IP,
  RawSocket,
  interfaceIndex,
} from "@opsimathically/nodenetraw";

const index = interfaceIndex("eth0");
const packets = await RawSocket.open({
  family: "packet",
  mode: "cooked",
  protocol: ETH_P_IP,
});
await packets.bind({
  family: "packet",
  interfaceIndex: index,
  protocol: ETH_P_IP,
});
const message = await packets.receiveMessage();
```

Raw packet mode includes the link header; cooked mode exposes the link payload.
Received packet addresses report interface index, `EtherType`, hardware address
and type, and Linux packet direction/type. Packet sockets also support explicit
promiscuous/multicast membership, `PACKET_AUXDATA`, statistics, fanout, and BPF
filters:

```ts
await packets.addPacketMembership({
  interfaceIndex: index,
  kind: "promiscuous",
});
await packets.setPacketAuxdata(true);
await packets.attachClassicFilter([
  { code: 0x06, jumpTrue: 0, jumpFalse: 0, value: 0xffff_ffff },
]);
const message = await packets.receiveMessage();
console.log(message.packetAuxdata, await packets.packetStatistics());
await packets.detachFilter();
await packets.dropPacketMembership({
  interfaceIndex: index,
  kind: "promiscuous",
});
```

Classic BPF programs contain at most 4096 instructions and are structurally
checked before Linux performs its verifier pass. `attachEbpfFilter(fd)` attaches
a close-on-exec duplicate and never consumes the caller's descriptor.

The package exports a focused set of Linux-compatible `IPPROTO_*` and `ETH_P_*`
constants for readable socket creation and packet binding. These names are not
an exhaustive protocol registry; numeric values remain accepted for custom or
less-common protocols. IP `protocol` values must be integers from 1 through 255,
while packet-socket protocol values must be integers from 1 through 65,535.
`send()` accepts a non-empty `Uint8Array` of at most 65,535 bytes and a
dotted-decimal IPv4 destination.

The IP exports are `IPPROTO_ICMP`, `IPPROTO_IGMP`, `IPPROTO_IPIP`,
`IPPROTO_TCP`, `IPPROTO_UDP`, `IPPROTO_IPV6`, `IPPROTO_GRE`, `IPPROTO_ESP`,
`IPPROTO_AH`, `IPPROTO_ICMPV6`, `IPPROTO_SCTP`, `IPPROTO_UDPLITE`, and
`IPPROTO_RAW`. Packet exports are `ETH_P_ALL`, `ETH_P_IP`, `ETH_P_ARP`,
`ETH_P_8021Q`, `ETH_P_IPV6`, and `ETH_P_8021AD`. Values match the Linux UAPI
names and are ordinary zero-dependency TypeScript/JavaScript number exports.

`receive()` accepts an optional buffer length from 1 through 65,535 and returns
the received bytes, source address, and an explicit truncation flag. `close()`
is asynchronous and idempotent; it cancels admitted operations and releases the
descriptor before resolving.

`bind()` selects a local IPv4 address and `localAddress()` reports the current
binding. `getOption()` and `setOption()` support `broadcast`, `ipTtl`,
`ipTypeOfService`, `receiveBufferSize`, `sendBufferSize`, `receivePacketInfo`,
`receiveTtl`, `receiveTypeOfService`, `receiveTimestampNanoseconds`,
`receiveQueueOverflow`, `receiveErrors`, and `bindToDevice`. Socket buffer
requests are limited to 16 MiB; Linux may clamp or double them, so getters
report the effective kernel value.

Advanced typed names include `headerIncluded`, `ipv6ChecksumOffset`, `freebind`,
`transparent`, `priority`, `mark`, `pathMtuDiscovery`, multicast TTL/loop, and
bounded `busyPollMicroseconds`. `connect()` and `disconnect()` support both raw
IP families. For Linux options not yet modeled, `getSocketOption()` and
`setSocketOption()` copy at most 4096 initialized bytes; filter, descriptor,
ring, membership, fanout, and all typed tuples are rejected from this escape
hatch and must use their ownership-aware APIs.

`sendBatch()` and `receiveBatch()` use nonblocking `sendmmsg(2)` and
`recvmmsg(2)` with 64-message and 1 MiB limits. Batch ancillary controls remain
on the one-message API. Packet sockets can configure a receive-only TPACKET_V3
ring and obtain explicitly releasable copied frame leases:

```ts
await packets.configurePacketRing();
const lease = await packets.receiveRingFrame();
try {
  const frame = lease.read();
  console.log(frame, lease.timestamp, lease.originalLength);
} finally {
  lease.release();
}
```

No Buffer aliases mutable mmap memory, and `read()` fails after release. TX mmap
is intentionally deferred; the optimized namespace benchmark currently shows a
measured advantage for the safer `sendmmsg` path.

`receiveMessage()` independently reports data/control truncation and returns
typed packet-info, TTL, TOS, timestamp, overflow, and extended-error controls.
Unknown receive controls are bounded owned bytes. Timestamp controls include a
lossless bigint nanosecond value. `send()`, `receive()`, `sendMessage()`, and
`receiveMessage()` accept optional AbortSignals where they can wait.

Each received packet includes `packetLength`, which remains the original Linux
datagram length even when the capture buffer truncates it. When the captured
bytes contain a complete valid IPv4 header, `ipv4` reports destination,
protocol, TTL, TOS, header/total length, identification, and fragmentation
fields. It is `undefined` when a short capture cannot be parsed safely.

Failures are `RawSocketError` instances with stable `kind`, `code`, `operation`,
optional numeric `errno`, and optional `errnoName` fields. Queue limits fail
immediately with `ERR_QUEUE_FULL`; operations after close fail with
`ERR_SOCKET_CLOSED`; incompatible receive ownership fails with
`ERR_RECEIVER_ACTIVE`.

### Event adapter limits and ownership

Event listeners run synchronously in registration order and receive the same
initialized, JavaScript-owned `ReceivedMessage`. A listener may retain it; copy
the Buffer if listeners need mutation isolation. Promise values returned by
listeners are not awaited and do not create backpressure. With Node's default
settings, a rejected async listener is an unhandled rejection; if the process
enables `EventEmitter.captureRejections` before construction, Node routes that
reason to `error`, which is why the event payload is typed `unknown`.

The adapter holds no message queue: each source retains at most one native
receive, one bounded result during synchronous dispatch, and one internal
AbortController. Slow listeners or `pause()` stop userspace rearming, not
network ingress. Linux may fill the socket receive buffer and drop packets;
applicable queue-overflow metadata and packet statistics remain the observation
mechanisms.

Attachment has explicit lifetime. A socket retains an idle, running, or paused
source and its receive claim even if application code drops the source
reference. Call `detach()` to return a live lane or `close()` to end the socket.
A running source has the same process and Worker liveness implications as a
pending `receiveMessage()`; Phase 11 adds no `ref()`/`unref()`. Inherited
`newListener`, `removeListener`, `errorMonitor`, custom event names, and public
synthetic `emit()` behavior remain standard Node behavior and do not mutate the
adapter lifecycle.

## Documentation

The workspace plan begins at
[`ai_documentation/00-index.md`](../../ai_documentation/00-index.md).
Contributors and coding agents should also read [`AGENTS.md`](../../AGENTS.md)
before making changes.

## Development

Run development commands from the repository root. Prerequisites are Node.js
26+, npm 11+, Rust 1.97.0 through `rustup`, and a working Linux linker. The
pinned Rust toolchain is described by
[`rust-toolchain.toml`](../../rust-toolchain.toml).

```sh
npm ci
npm run build
npm test
```

Run the entire local quality gate with:

```sh
npm run ci
```

An optimized source build is explicit. It may fetch napi-rs's pinned build-time
GNU compatibility toolchain; installing the resulting npm packages performs no
download or compilation:

```sh
npm ci
npm run build:native:release
npm run build:typescript
```

`npm run release:consumer-test` stages the root and current-architecture native
packages under `packages/nodenetraw/release/stage`, packs them, installs them
into a temporary clean project with scripts disabled, and tests ESM plus
`require()`. `npm run release:reproducibility` builds the optimized addon twice
and compares SHA-256 hashes. `npm run release:verify-artifact` checks ELF
architecture and the glibc symbol ceiling. Actual npm publication is
intentionally not automated by these commands.

The private workspace root and the package source tree both refuse direct
publication. Only inspect and publish the staged packages produced by
`npm run release:assemble`.

Additional focused commands include `npm run typecheck`, `npm run lint`,
`npm run format:check`, `npm run rust:fmt`, `npm run rust:clippy`, and
`npm run rust:test`. See [`AGENTS.md`](../../AGENTS.md) for the complete command
map.

Successful raw-socket integration tests can be launched with ordinary `sudo`:

```sh
sudo npm run test:privileged
```

The harness detects the invoking repository owner, builds with that user's Node
26/npm/rustup environment, and elevates only the already-built test process.
Tests run in a disposable network namespace with their own loopback and veth
fixtures, so they do not alter the host network namespace or leave root-owned
build artifacts. If Node 26 cannot be discovered automatically, set
`NODENETRAW_NODE` to its absolute executable path.

An entirely unprivileged alternative, where AppArmor and the host's user
namespace policy permit it, is:

```sh
npm run test:namespace
```

Do not use `sudo npm run build`; use the privileged test command above so the
build step can deliberately drop back to the repository owner.

Implementation and verification details are in the
[Phase 10 report](../../ai_documentation/17-phase-10-report.md) and the
[release-readiness audit](../../ai_documentation/18-release-readiness-audit.md).
The event adapter is recorded in the
[Phase 11 report](../../ai_documentation/21-phase-11-report.md); its adversarial
post-implementation review is the
[Phase 11 implementation audit](../../ai_documentation/22-phase-11-implementation-audit.md).
The Phase 12 foundation is recorded in the
[Phase 12 report](../../ai_documentation/25-phase-12-report.md). The completed
ICMPv4 and traceroute sequence is defined by the
[ICMPv4 and traceroute capability plan](../../ai_documentation/23-icmp-and-traceroute-plan.md),
whose readiness findings are closed in the
[preimplementation review](../../ai_documentation/24-icmp-plan-review.md). Its
final implementation evidence is in the
[Phase 15 report](../../ai_documentation/28-phase-15-report.md), followed by the
[Phase 12–15 implementation audit](../../ai_documentation/29-phase-12-15-implementation-audit.md).

## License

Licensed under the [MIT License](LICENSE).
