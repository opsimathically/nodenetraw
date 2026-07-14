import {
  createScanner,
  inspectNetworkContext,
  type ScanPlan,
  type ScanResultBatch,
  type ScanSummary,
} from "../../src/index.js";

const plan: ScanPlan = {
  targets: [{ cidr: "127.0.0.1/32" }],
  probes: [
    { kind: "icmpEcho", family: "ipv4" },
    { kind: "tcpSyn", ports: [22, { start: 80, end: 81 }] },
    { kind: "udp", ports: [53], payload: new Uint8Array([1, 2, 3]) },
  ],
  deadlineMs: 5_000,
  seed: 1n,
};

async function consume(): Promise<void> {
  const context = await inspectNetworkContext();
  context.generation satisfies bigint;
  const scanner = await createScanner();
  const session = await scanner.start(plan);
  const batch: ScanResultBatch | null = await session.nextBatch({
    maxResults: 64,
    signal: new AbortController().signal,
  });
  if (batch?.results[0] !== undefined)
    batch.results[0].routeGeneration satisfies bigint;
  batch?.at(0)?.timestampNanoseconds satisfies bigint | undefined;
  batch?.transferList() satisfies ArrayBuffer[] | undefined;
  const progress = await session.progress();
  progress.applicationBackpressured satisfies bigint;
  const events = session.batches({ maxResults: 128 });
  events.on("batch", (eventBatch) => eventBatch.length satisfies number);
  events.on("end", () => undefined);
  const summary: ScanSummary = await session.cancel("test complete");
  summary.results satisfies bigint;
  summary.error satisfies import("../../src/index.js").ScannerError | undefined;
  await session.close();
  await scanner.close();
}

void consume;
