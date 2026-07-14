# @opsimathically/nodenetscanner

`@opsimathically/nodenetscanner` is a private Phase 23 preview of a bounded,
Linux-native network scanner for Node.js 26+. TypeScript provides the public
control API; Rust owns route inspection, raw and packet sockets, packet bytes,
correlation secrets, scheduling, timers, result storage, and cleanup.

The package is not published yet. It is developed independently from
`@opsimathically/nodenetraw` and does not call that package or borrow its file
descriptors. Shared protocol, read-only network-context, and scheduler code is
linked into the scanner addon at build time.

## Current capabilities

- IPv4 ARP and IPv6 Neighbor Discovery for directly connected targets;
- ICMPv4 and ICMPv6 Echo discovery;
- IPv4 and IPv6 TCP SYN scanning;
- IPv4 and IPv6 UDP scanning with an optional owned payload;
- Ethernet, explicit 802.1Q VLAN, loopback, and local raw-IP paths;
- compact CIDR or inclusive-range targets and exclusions;
- bounded rate, outstanding-work, retry, deadline, and result controls;
- pause, resume, cancel, terminal summaries, abortable compact result batches,
  coalesced progress snapshots, and an optional batch event adapter; and
- read-only interface, address, route, rule, and neighbor inspection.

The scanner does not change links, addresses, routes, neighbors, firewall rules,
or network namespaces. It does not enable promiscuous mode and never tries to
elevate its own privileges.

## Build and test

From the monorepo root:

```sh
npm ci
npm run build --workspace=@opsimathically/nodenetscanner
npm run test:phase23
```

The ordinary tests do not require raw-socket authority. The live dual-stack,
veth, and VLAN matrix runs in disposable network namespaces:

```sh
sudo npm run test:phase23:namespace
```

The wrapper builds as the invoking user before entering the namespace, which
avoids root-owned build artifacts. It requires `ip`, `unshare`, `nsenter`, and
Node.js 26+.

## Scan example

Creating a scanner and inspecting network context do not open raw sockets.
Raw-socket authority is checked when `start()` opens a session, normally through
root or `CAP_NET_RAW` in the current user/network namespace.

```ts
import {
  ScannerError,
  createScanner,
  inspectNetworkContext,
} from "@opsimathically/nodenetscanner";

const context = await inspectNetworkContext();
console.log(context.generation, context.interfaces);

const scanner = await createScanner();

try {
  const session = await scanner.start({
    targets: [{ cidr: "192.0.2.0/24" }, { cidr: "2001:db8::/120" }],
    exclude: [{ cidr: "192.0.2.1/32" }],
    probes: [
      { kind: "icmpEcho", family: "ipv4" },
      { kind: "icmpEcho", family: "ipv6" },
      { kind: "tcpSyn", ports: [22, 443, { start: 8000, end: 8010 }] },
      {
        kind: "udp",
        ports: [53],
        payload: new Uint8Array([0x00]),
      },
    ],
    deadlineMs: 30_000,
    rate: {
      packetsPerSecond: 1_000,
      burst: 32,
      maxOutstanding: 1_024,
    },
    timing: {
      timeoutMs: 1_000,
      retries: 1,
    },
    sourcePortRange: { start: 49_152, end: 65_535 },
  });

  for (;;) {
    const batch = await session.nextBatch({ maxResults: 512 });
    if (batch === null) break;

    // Rows are decoded lazily. `batch.results` is also a compatible lazy,
    // indexable iterable when that spelling is more convenient.
    for (const result of batch) {
      console.log(result.target, result.probe, result.port, result.state);
    }
  }

  console.log(await session.summary());
  await session.close();
} catch (error) {
  if (error instanceof ScannerError) {
    console.error(error.kind, error.code, error.operation, error.errno);
  }
  throw error;
} finally {
  await scanner.close();
}
```

ARP accepts IPv4 targets and NDP accepts IPv6 targets only when route context
shows that the target is on-link. Their learned link address is session-local;
it is not inserted into the kernel neighbor table.

To select an explicit VLAN path, capture the interface, source address, and tag
in the plan:

```ts
const session = await scanner.start({
  targets: [{ cidr: "198.51.100.2/32" }],
  probes: [{ kind: "arp" }, { kind: "tcpSyn", ports: [443] }],
  deadlineMs: 10_000,
  interface: "eth0",
  sourceAddress: "198.51.100.1",
  vlan: { identifier: 42, priority: 0 },
});
```

Unsupported link types, routes, source overrides, and probe/family combinations
fail explicitly rather than guessing an Ethernet header or route.

## Compact batches

`ScanResultBatch` schema version 1 is columnar. Creating a batch does not create
one JavaScript object per result. Use `batch.at(index)`, iterate the batch, use
`batch.filter(predicate)`, or call `batch.materialize()` only when owned
ordinary objects are wanted. Exact RTTs, terminal timestamps, and route
generations are `bigint`; timestamps are unsigned nanoseconds from the session's
monotonic origin and never wall time.

The public `columns` contain copied, Node-owned `Uint8Array` storage.
Fixed-width integers are little-endian; IP address octets remain in network byte
order and each row carries an explicit family. Mutating these views can change
how that batch decodes but cannot affect native correlation or scanner state. To
transfer the columns to a Worker, use `batch.transferList()` as the
structured-clone transfer list. Accessing the original batch after transfer
fails explicitly.

```ts
const batch = await session.nextBatch({ maxResults: 512 });
if (batch !== null) {
  const open = Array.from(
    batch.filter((row) => row.state === "open"),
    (row) => row.materialize(),
  );
  console.log(open);

  worker.postMessage(
    {
      schemaVersion: batch.schemaVersion,
      rowCount: batch.length,
      byteOrder: batch.byteOrder,
      ...batch.columns,
    },
    batch.transferList(),
  );
}
```

## Pull, progress, and lifecycle semantics

`nextBatch()` defaults to at most 512 results and accepts 1 through 4,096. At
most one pull may wait per session. Pass an `AbortSignal` to cancel only that
wait; the scan continues. If native delivery wins the cancellation race, the
sealed batch is delivered. A terminal session remains drainable: queued batches
are returned first, followed by `null`.

```ts
const controller = new AbortController();
const waiting = session.nextBatch({ signal: controller.signal });
controller.abort();
await waiting; // rejects with AbortError unless a batch was already delivered
```

`progress()` returns a coalesced snapshot with exact `bigint` counts for sent,
received, matched, duplicate, invalid, timed-out, retried, kernel-dropped, and
application-backpressured work. Result saturation stops new transmissions and
does not resume until the bounded queue reaches its low-water mark; receive,
expiry, cancel, close, and result draining continue.

`pause()` stops new transmission after its promise resolves; receive processing,
timeouts, cancellation, and result draining continue. `resume()` permits
transmission again. `cancel()` stops admission and resolves with the terminal
summary after native I/O ownership has ended. `summary()` waits for the same
terminal summary. `close()` is idempotent and intentionally discards any
undrained results; scanner close cancels and closes all of its sessions.

If a live context or socket boundary fails, the summary state is `failed` and
`summary.error` retains its stable kind/code, operation, message, and Linux
`errno` when one exists. Already reserved probes still produce
`contextInvalidated` or `transportFailed` terminal results.

One Node environment has one native runtime with no process-global scanner
state. It accepts at most four scanner objects, four concurrent sessions, 64
pending control operations, and independently bounded command, active-probe,
grace, and result storage. Slow JavaScript consumption can stop new admission;
it cannot cause unbounded native allocation.

## Batch events

For Node applications that prefer event-driven consumption, `session.batches()`
creates an adapter over `nextBatch()`; it does not add another native receive
loop or a per-result event mode. Call `start()` explicitly. `pause()` and
`detach()` are awaitable boundaries, while `close()` closes the underlying scan
session. A fulfilled batch is emitted before any competing pause, detach, or
close boundary settles.

```ts
const events = session.batches({ maxResults: 512 });

events.on("batch", (batch) => {
  for (const result of batch) console.log(result.target, result.state);
});
events.once("end", () => console.log("all queued results drained"));
events.on("error", console.error);
events.start();

await events.pause();
events.resume();

// Stop event delivery but keep direct ownership of the scan session.
const directSession = await events.detach();
const next = await directSession.nextBatch();
```

## Accuracy and host interaction

Raw scan replies are unauthenticated network evidence. Results record the
protocol-specific evidence strength and distinguish `open`, `closed`,
`filtered`, `open|filtered`, `up`, `unreachable`, and `unknown` where the wire
protocol permits that conclusion. UDP silence is `open|filtered`; discovery
silence is `unknown`.

The default TCP/UDP source range is 49152–65535. Choose a range that does not
conflict with local applications or the host ephemeral allocator. The host TCP
stack may send a reset after receiving a SYN-ACK for a raw SYN probe; the
library deliberately does not install firewall rules to suppress it. Source port
reuse is separated across outstanding work and late-response grace state, but
applications remain responsible for coordinating other host users of an explicit
range.

Packet parsing rejects truncation, ignores locally looped `PACKET_OUTGOING`
frames, interprets stripped VLAN tags through packet auxiliary metadata, and
reports lifetime kernel-drop accounting in the terminal summary.

## Support status

This Phase 23 package remains `private: true` at version `0.0.0`. Linux x86-64
development and tests are the current local baseline. AArch64 is an intended
future artifact target but native execution remains untested and is a release
gate. The compact columnar batch format is now frozen; Phase 24 owns API
stabilization and release hardening.

The authoritative design is the
[Phase 16–26 network and scanner evolution plan](../../ai_documentation/31-network-and-scanner-evolution-plan.md).
