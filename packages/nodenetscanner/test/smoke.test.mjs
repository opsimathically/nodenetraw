import assert from "node:assert/strict";
import test from "node:test";

import {
  ScannerError,
  createScanner,
  inspectNetworkContext,
} from "../dist/index.js";

test("read-only context inspection works without raw-socket setup", async () => {
  const snapshot = await inspectNetworkContext();
  assert.equal(typeof snapshot.generation, "bigint");
  assert.ok(snapshot.interfaces.length > 0);
  assert.ok(
    snapshot.interfaces.every(
      (item) => item.hardwareAddress instanceof Uint8Array,
    ),
  );
});

test("createScanner is capability-free and invalid plans fail before raw sockets", async () => {
  const scanner = await createScanner();
  await assert.rejects(
    scanner.start({ targets: [], probes: [], deadlineMs: 1_000 }),
    (error) => error instanceof ScannerError && error.kind === "invalidPlan",
  );
  await scanner.close();
  await scanner.close();
});

test("environment scanner admission is bounded independently of raw authority", async () => {
  const scanners = await Promise.all(
    Array.from({ length: 4 }, () => createScanner()),
  );
  await assert.rejects(
    createScanner(),
    (error) => error instanceof ScannerError && error.kind === "resourceLimit",
  );
  await Promise.all(scanners.map((scanner) => scanner.close()));
});

test("valid start either opens a session or preserves Linux permission context", async () => {
  const scanner = await createScanner();
  try {
    const session = await scanner.start({
      targets: [{ cidr: "127.0.0.1/32" }],
      probes: [{ kind: "icmpEcho", family: "ipv4" }],
      deadlineMs: 1_000,
      timing: { timeoutMs: 100, retries: 0 },
      rate: { packetsPerSecond: 10, burst: 1, maxOutstanding: 1 },
    });
    await session.cancel();
    await session.close();
  } catch (error) {
    assert.ok(error instanceof ScannerError);
    assert.equal(error.kind, "permission");
    assert.equal(error.code, "ERR_PERMISSION");
    assert.equal(typeof error.operation, "string");
    assert.equal(typeof error.errno, "number");
  } finally {
    await scanner.close();
  }
});

test("scanner control commands enforce the independent 4 MiB boundary", async () => {
  const scanner = await createScanner();
  await assert.rejects(
    scanner.start({
      targets: [{ cidr: "127.0.0.1/32" }],
      probes: [
        { kind: "udp", ports: [7], payload: new Uint8Array(4 * 1024 * 1024) },
      ],
      deadlineMs: 1_000,
    }),
    (error) =>
      error instanceof ScannerError && error.code === "ERR_CONTROL_BYTES",
  );
  await scanner.close();
});
