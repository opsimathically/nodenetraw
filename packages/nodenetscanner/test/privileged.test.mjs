import assert from "node:assert/strict";
import test from "node:test";

import { createScanner } from "../dist/index.js";

const enabled = process.env.NODENETSCANNER_PRIVILEGED_TESTS === "1";
const matrix = process.env.NODENETSCANNER_NAMESPACE_MATRIX === "1";

test(
  "portable engine scans IPv4 loopback with ICMP and TCP",
  { skip: !enabled },
  async () => {
    const scanner = await createScanner();
    const session = await scanner.start({
      targets: [{ cidr: "127.0.0.1/32" }],
      probes: [
        { kind: "icmpEcho", family: "ipv4" },
        { kind: "tcpSyn", ports: [9] },
      ],
      deadlineMs: 5_000,
      timing: { timeoutMs: 500, retries: 0 },
      rate: { packetsPerSecond: 100, burst: 2, maxOutstanding: 2 },
    });
    const results = await drain(session);
    const summary = await session.summary();
    assert.equal(summary.results, 2n);
    assert.ok(summary.progress.sent >= 2n);
    assert.ok(summary.progress.matched >= 2n);
    assertResult(results, "127.0.0.1", "icmpEchoIpv4", undefined, "up");
    assertResult(results, "127.0.0.1", "tcpSyn", 9, "closed");
    await session.close();
    await scanner.close();
  },
);

test(
  "terminal compact pulls scale with batches instead of probe rows",
  { skip: !enabled },
  async (context) => {
    const cpuStart = process.cpuUsage();
    const wallStart = globalThis.performance.now();
    const scanner = await createScanner();
    const session = await scanner.start({
      targets: [{ cidr: "127.0.0.1/32" }],
      probes: [{ kind: "tcpSyn", ports: [{ start: 20_000, end: 20_255 }] }],
      deadlineMs: 10_000,
      timing: { timeoutMs: 500, retries: 0 },
      rate: {
        packetsPerSecond: 10_000,
        burst: 256,
        maxOutstanding: 256,
      },
    });
    const summary = await session.summary();
    assert.equal(summary.results, 256n);
    let batches = 0;
    let rows = 0;
    for (;;) {
      const batch = await session.nextBatch({ maxResults: 64 });
      if (batch === null) break;
      batches += 1;
      rows += batch.length;
    }
    assert.equal(rows, 256);
    assert.equal(batches, 4);
    const cpu = process.cpuUsage(cpuStart);
    context.diagnostic(
      `256 rows / ${String(batches)} N-API pulls; ${(
        globalThis.performance.now() - wallStart
      ).toFixed(2)} ms wall; ${String(cpu.user + cpu.system)} µs process CPU`,
    );
    await session.close();
    await scanner.close();
  },
);

test(
  "portable engine covers dual-stack discovery and transport evidence",
  { skip: !matrix },
  async () => {
    const scanner = await createScanner();
    const session = await scanner.start({
      targets: [{ cidr: "192.0.2.2/32" }, { cidr: "2001:db8:22::2/128" }],
      probes: [
        { kind: "arp" },
        { kind: "ndp" },
        { kind: "icmpEcho", family: "ipv4" },
        { kind: "icmpEcho", family: "ipv6" },
        { kind: "tcpSyn", ports: [18080, 18081] },
        { kind: "udp", ports: [18082, 18083, 18084] },
      ],
      deadlineMs: 10_000,
      timing: { timeoutMs: 1_000, retries: 0 },
      rate: { packetsPerSecond: 500, burst: 16, maxOutstanding: 16 },
    });
    const results = await drain(session);
    const summary = await session.summary();
    assert.equal(summary.error, undefined, formatValue(summary));
    assert.ok(summary.progress.sent >= summary.results);
    assert.ok(summary.progress.received > 0n);
    assert.ok(summary.progress.matched > 0n);
    assertResult(results, "192.0.2.2", "arp", undefined, "up");
    assertResult(results, "2001:db8:22::2", "ndp", undefined, "up");
    assertResult(results, "192.0.2.2", "icmpEchoIpv4", undefined, "up");
    assertResult(results, "2001:db8:22::2", "icmpEchoIpv6", undefined, "up");
    assertResult(results, "192.0.2.2", "tcpSyn", 18080, "open");
    assertResult(results, "2001:db8:22::2", "tcpSyn", 18081, "closed");
    assertResult(results, "192.0.2.2", "udp", 18082, "open");
    assertResult(results, "2001:db8:22::2", "udp", 18083, "closed");
    assertResult(results, "2001:db8:22::2", "udp", 18084, "open");
    await session.close();
    await scanner.close();
  },
);

test(
  "portable engine sends and receives an explicit VLAN path",
  { skip: !matrix },
  async () => {
    const scanner = await createScanner();
    const session = await scanner.start({
      targets: [{ cidr: "198.51.100.2/32" }],
      probes: [
        { kind: "arp" },
        { kind: "icmpEcho", family: "ipv4" },
        { kind: "tcpSyn", ports: [18080] },
        { kind: "udp", ports: [18082] },
      ],
      deadlineMs: 10_000,
      interface: "scan0",
      sourceAddress: "198.51.100.1",
      vlan: { identifier: 42 },
      timing: { timeoutMs: 1_000, retries: 0 },
      rate: { packetsPerSecond: 200, burst: 4, maxOutstanding: 4 },
    });
    const results = await drain(session);
    const summary = await session.summary();
    assert.equal(summary.error, undefined, formatValue(summary));
    assert.ok(summary.progress.sent >= summary.results);
    assertResult(results, "198.51.100.2", "arp", undefined, "up");
    assertResult(results, "198.51.100.2", "icmpEchoIpv4", undefined, "up");
    assertResult(results, "198.51.100.2", "tcpSyn", 18080, "open");
    assertResult(results, "198.51.100.2", "udp", 18082, "open");
    await session.close();
    await scanner.close();
  },
);

async function drain(session) {
  const results = [];
  for (;;) {
    const batch = await session.nextBatch({ maxResults: 64 });
    if (batch === null) return results;
    assert.equal(batch.schemaVersion, 1);
    assert.equal(batch.byteOrder, "little-endian");
    assert.ok(batch.length > 0 && batch.length <= 64);
    assert.ok(
      Array.from(batch).every(
        (result) => typeof result.timestampNanoseconds === "bigint",
      ),
    );
    results.push(...batch.results);
  }
}

function assertResult(results, target, probe, port, state) {
  assert.ok(
    results.some(
      (result) =>
        result.target === target &&
        result.probe === probe &&
        result.port === port &&
        result.state === state,
    ),
    `missing ${target} ${probe} ${String(port)} ${state}: ${formatValue(results)}`,
  );
}

function formatValue(value) {
  return JSON.stringify(value, (_key, item) =>
    typeof item === "bigint" ? item.toString() : item,
  );
}
