import assert from "node:assert/strict";
import test from "node:test";

import {
  ScanBatchEventEmitter,
  ScanResultBatch,
  ScanSession,
  ScannerError,
} from "../dist/index.js";

test("versioned columns decode lazily and preserve exact wide integers", () => {
  const encoded = fixture();
  const batch = new ScanResultBatch(encoded);
  assert.equal(batch.schemaVersion, 1);
  assert.equal(batch.byteOrder, "little-endian");
  assert.equal(batch.length, 2);
  assert.equal(batch.results.length, 2);
  assert.equal(batch.results[0].target, "192.0.2.1");
  assert.equal(batch.at(-1).target, "2001:db8::2%7");
  assert.equal(batch.results[1].port, 443);
  assert.equal(batch.results[1].state, "open");
  assert.equal(batch.results[1].rttNanoseconds, 9_007_199_254_740_993n);
  assert.equal(batch.results[1].timestampNanoseconds, 10_000_000_000n);
  assert.equal(batch.results[1].routeGeneration, 9_007_199_254_740_997n);
  assert.deepEqual(
    Array.from(
      batch.filter((row) => row.state === "open"),
      (row) => row.target,
    ),
    ["2001:db8::2%7"],
  );
  assert.equal(batch.materialize()[0].reason, "timeout");

  encoded.addressBytes.fill(0);
  assert.equal(batch.results[0].target, "192.0.2.1");
});

test("batch storage can be retained, mutated, and transferred without native ownership", () => {
  const batch = new ScanResultBatch(fixture());
  batch.columns.states[0] = 5;
  assert.equal(batch.results[0].state, "up");

  const columns = globalThis.structuredClone(batch.columns, {
    transfer: batch.transferList(),
  });
  assert.equal(batch.detached, true);
  assert.throws(
    () => batch.at(0),
    (error) =>
      error instanceof ScannerError && error.code === "ERR_INVALID_BATCH",
  );

  const received = new ScanResultBatch({
    schemaVersion: 1,
    rowCount: 2,
    byteOrder: "little-endian",
    ...columns,
  });
  assert.equal(received.results[0].state, "up");
  assert.equal(received.results[1].target, "2001:db8::2%7");
});

test("malformed or oversized column schemas fail closed", () => {
  const malformed = fixture();
  malformed.addressOffsets = new Uint8Array(4);
  assert.throws(
    () => new ScanResultBatch(malformed),
    (error) =>
      error instanceof ScannerError && error.code === "ERR_INVALID_BATCH",
  );
});

test("AbortSignal cancels only a pending pull and delivery wins an earlier native race", async () => {
  let settle;
  const handle = mockHandle({
    nextBatch: () => new Promise((resolve) => (settle = resolve)),
    cancelPull: async () => {
      settle({ status: "aborted" });
      return true;
    },
  });
  const session = new ScanSession(handle, 1);
  const controller = new globalThis.AbortController();
  const pending = session.nextBatch({ signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, (error) => error?.name === "AbortError");
  assert.equal(await session.progress().then((value) => value.sent), 0n);

  const delivered = new ScanSession(
    mockHandle({
      nextBatch: async () => ({ status: "batch", batch: fixture() }),
    }),
    2,
  );
  const late = new globalThis.AbortController();
  const batchPromise = delivered.nextBatch({ signal: late.signal });
  late.abort();
  assert.equal((await batchPromise).length, 2);
});

test("batch event adapter emits batches, terminal end, and closes its session", async () => {
  const values = [new ScanResultBatch(fixture()), null];
  let closed = 0;
  const session = {
    async nextBatch() {
      return values.shift();
    },
    async close() {
      closed += 1;
    },
  };
  const events = new ScanBatchEventEmitter(session, { maxResults: 2 });
  const batches = [];
  const ended = new Promise((resolve) => events.once("end", resolve));
  events.on("batch", (batch) => batches.push(batch));
  events.start();
  await ended;
  assert.equal(events.status, "ended");
  assert.equal(batches.length, 1);
  await events.close();
  await events.close();
  assert.equal(closed, 1);
  assert.equal(events.status, "closed");
});

test("batch event adapter pause and detach quiesce their one pending pull", async () => {
  let terminal = false;
  const session = {
    nextBatch({ signal }) {
      if (terminal) return Promise.resolve(null);
      return new Promise((_resolve, reject) => {
        signal.addEventListener(
          "abort",
          () => reject(new globalThis.DOMException("aborted", "AbortError")),
          { once: true },
        );
      });
    },
    close() {
      return Promise.resolve();
    },
  };
  const events = new ScanBatchEventEmitter(session);
  events.start();
  await events.pause();
  assert.equal(events.status, "paused");
  terminal = true;
  const ended = new Promise((resolve) => events.once("end", resolve));
  events.resume();
  await ended;

  const detachedSession = {
    nextBatch({ signal }) {
      return new Promise((_resolve, reject) => {
        signal.addEventListener(
          "abort",
          () => reject(new globalThis.DOMException("aborted", "AbortError")),
          { once: true },
        );
      });
    },
    async close() {
      throw new Error("detach must not close the session");
    },
  };
  const detached = new ScanBatchEventEmitter(detachedSession).start();
  assert.equal(await detached.detach(), detachedSession);
  assert.equal(detached.status, "detached");
});

function mockHandle(overrides = {}) {
  return {
    pause: async () => undefined,
    resume: async () => undefined,
    cancel: async () => summary(),
    nextBatch: async () => ({ status: "terminal" }),
    cancelPull: async () => false,
    progress: async () => progress(),
    summary: async () => summary(),
    closeSession: async () => undefined,
    state: () => "running",
    close: async () => undefined,
    ...overrides,
  };
}

function progress() {
  return {
    sent: "0",
    received: "0",
    matched: "0",
    duplicate: "0",
    invalid: "0",
    timedOut: "0",
    retried: "0",
    kernelDropped: "0",
    applicationBackpressured: "0",
    coalescedUpdates: "0",
  };
}

function summary() {
  return {
    state: "completed",
    logicalProbes: "0",
    results: "0",
    open: "0",
    closed: "0",
    filtered: "0",
    openOrFiltered: "0",
    up: "0",
    unreachable: "0",
    unknown: "0",
    cancelled: "0",
    deadline: "0",
    discarded: "0",
    kernelDropped: "0",
    forgedOrUnrelated: "0",
    duplicates: "0",
    lateResponses: "0",
    progress: progress(),
    accuracyTradeoff: false,
  };
}

function fixture() {
  const reasons = ["timeout", "evidence:TcpSynAcknowledgment"];
  const metadataBytes = new globalThis.TextEncoder().encode(reasons.join(""));
  const addressBytes = Uint8Array.from([
    192, 0, 2, 1, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
  ]);
  return {
    schemaVersion: 1,
    rowCount: 2,
    byteOrder: "little-endian",
    addressBytes,
    addressOffsets: u32([0, 4, 20]),
    families: Uint8Array.from([4, 6]),
    scopes: u32([0, 7]),
    probes: Uint8Array.from([6, 5]),
    ports: u16([53, 443]),
    states: Uint8Array.from([4, 1]),
    outcomes: Uint8Array.from([1, 1]),
    attempts: u32([1, 2]),
    transmissions: u32([1, 2]),
    rttNanoseconds: u64([0xffff_ffff_ffff_ffffn, 9_007_199_254_740_993n]),
    timestampsNanoseconds: u64([1_000n, 10_000_000_000n]),
    routeGenerations: u64([1n, 9_007_199_254_740_997n]),
    evidence: Uint8Array.from([1, 3]),
    metadataBytes,
    metadataOffsets: u32([0, reasons[0].length, metadataBytes.length]),
  };
}

function u16(values) {
  const output = new Uint8Array(values.length * 2);
  const view = new DataView(output.buffer);
  values.forEach((value, index) => view.setUint16(index * 2, value, true));
  return output;
}

function u32(values) {
  const output = new Uint8Array(values.length * 4);
  const view = new DataView(output.buffer);
  values.forEach((value, index) => view.setUint32(index * 4, value, true));
  return output;
}

function u64(values) {
  const output = new Uint8Array(values.length * 8);
  const view = new DataView(output.buffer);
  values.forEach((value, index) => view.setBigUint64(index * 8, value, true));
  return output;
}
