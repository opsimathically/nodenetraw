import { Buffer } from "node:buffer";
import { EventEmitter } from "node:events";
import { createRequire } from "node:module";

export type ScanTarget =
  { readonly cidr: string } | { readonly start: string; readonly end: string };

export type PortSelection =
  number | { readonly start: number; readonly end: number };

export type ScanProbe =
  | { readonly kind: "arp" }
  | { readonly kind: "ndp" }
  | { readonly kind: "icmpEcho"; readonly family: "ipv4" | "ipv6" }
  | { readonly kind: "tcpSyn"; readonly ports: readonly PortSelection[] }
  | {
      readonly kind: "udp";
      readonly ports: readonly PortSelection[];
      readonly payload?: Uint8Array;
    };

export interface ScanRateOptions {
  readonly packetsPerSecond?: number;
  readonly burst?: number;
  readonly maxOutstanding?: number;
}

export interface ScanTimingOptions {
  readonly timeoutMs?: number;
  readonly minimumTimeoutMs?: number;
  readonly maximumTimeoutMs?: number;
  readonly retries?: number;
  readonly fixed?: boolean;
}

export interface ScanVlanOptions {
  readonly identifier: number;
  readonly priority?: number;
  readonly dropEligible?: boolean;
}

export interface ScanPlan {
  readonly targets: readonly ScanTarget[];
  readonly exclude?: readonly ScanTarget[];
  readonly probes: readonly ScanProbe[];
  readonly deadlineMs: number;
  readonly rate?: ScanRateOptions;
  readonly timing?: ScanTimingOptions;
  readonly seed?: bigint;
  readonly sourceAddress?: string;
  readonly interface?: string;
  readonly vlan?: ScanVlanOptions;
  readonly sourcePortRange?: { readonly start: number; readonly end: number };
}

export type ScanSessionState =
  | "created"
  | "running"
  | "pausing"
  | "paused"
  | "cancelling"
  | "completed"
  | "failed"
  | "closed";

export type ScanNetworkState =
  | "open"
  | "closed"
  | "filtered"
  | "open|filtered"
  | "up"
  | "unreachable"
  | "unknown"
  | "downByPolicy";

export interface ScanResult {
  readonly target: string;
  readonly probe:
    "arp" | "ndp" | "icmpEchoIpv4" | "icmpEchoIpv6" | "tcpSyn" | "udp";
  readonly port?: number | undefined;
  readonly state?: ScanNetworkState | undefined;
  readonly outcome:
    | "network"
    | "cancelled"
    | "deadline"
    | "transportFailed"
    | "contextInvalidated";
  readonly attempt: number;
  readonly transmissions: number;
  readonly rttMicros?: bigint | undefined;
  readonly rttNanoseconds?: bigint | undefined;
  readonly timestampNanoseconds: bigint;
  readonly routeGeneration: bigint;
  readonly evidence?:
    "tuple" | "truncatedQuote" | "tcpSequence32" | "payload128" | undefined;
  readonly reason: string;
}

export interface ScanResultBatchColumns {
  readonly addressBytes: Uint8Array;
  readonly addressOffsets: Uint8Array;
  readonly families: Uint8Array;
  readonly scopes: Uint8Array;
  readonly probes: Uint8Array;
  readonly ports: Uint8Array;
  readonly states: Uint8Array;
  readonly outcomes: Uint8Array;
  readonly attempts: Uint8Array;
  readonly transmissions: Uint8Array;
  readonly rttNanoseconds: Uint8Array;
  readonly timestampsNanoseconds: Uint8Array;
  readonly routeGenerations: Uint8Array;
  readonly evidence: Uint8Array;
  readonly metadataBytes: Uint8Array;
  readonly metadataOffsets: Uint8Array;
}

export interface EncodedScanResultBatch extends ScanResultBatchColumns {
  readonly schemaVersion: number;
  readonly rowCount: number;
  readonly byteOrder: string;
}

export interface ScanResultRows extends Iterable<ScanResultView> {
  readonly length: number;
  readonly [index: number]: ScanResultView | undefined;
  at(index: number): ScanResultView | undefined;
  materialize(): ScanResult[];
}

export interface ScanSummary {
  readonly state: ScanSessionState;
  readonly logicalProbes: bigint;
  readonly results: bigint;
  readonly open: bigint;
  readonly closed: bigint;
  readonly filtered: bigint;
  readonly openOrFiltered: bigint;
  readonly up: bigint;
  readonly unreachable: bigint;
  readonly unknown: bigint;
  readonly cancelled: bigint;
  readonly deadline: bigint;
  readonly discarded: bigint;
  readonly kernelDropped: bigint;
  readonly forgedOrUnrelated: bigint;
  readonly duplicates: bigint;
  readonly lateResponses: bigint;
  readonly progress: ScanProgress;
  readonly schedulingSeed?: bigint;
  readonly accuracyTradeoff: boolean;
  readonly error?: ScannerError;
}

export interface NextBatchOptions {
  readonly maxResults?: number;
  readonly signal?: AbortSignal;
}

export interface ScanProgress {
  readonly sent: bigint;
  readonly received: bigint;
  readonly matched: bigint;
  readonly duplicate: bigint;
  readonly invalid: bigint;
  readonly timedOut: bigint;
  readonly retried: bigint;
  readonly kernelDropped: bigint;
  readonly applicationBackpressured: bigint;
  readonly coalescedUpdates: bigint;
}

export interface ScanBatchEventEmitterOptions {
  readonly maxResults?: number;
}

export type ScanBatchEventEmitterStatus =
  | "idle"
  | "running"
  | "pausing"
  | "paused"
  | "detaching"
  | "detached"
  | "closing"
  | "ended"
  | "closed";

export interface ScanBatchEventMap {
  batch: [batch: ScanResultBatch];
  end: [];
  error: [error: Error];
  close: [];
}

export interface NetworkInterface {
  readonly index: number;
  readonly name: string;
  readonly flags: number;
  readonly linkLayerType: number;
  readonly mtu?: number;
  readonly hardwareAddress: Uint8Array;
  readonly linkKind?: string;
}

export interface NetworkAddress {
  readonly interfaceIndex: number;
  readonly family: 2 | 10;
  readonly prefixLength: number;
  readonly address?: string;
  readonly local?: string;
}

export interface NetworkRoute {
  readonly family: 2 | 10;
  readonly destination?: string;
  readonly prefixLength: number;
  readonly gateway?: string;
  readonly preferredSource?: string;
  readonly interfaceIndex?: number;
  readonly table: number;
  readonly routeType: number;
}

export interface NetworkContextSnapshot {
  readonly generation: bigint;
  readonly netnsCookie?: bigint;
  readonly interfaces: readonly NetworkInterface[];
  readonly addresses: readonly NetworkAddress[];
  readonly routes: readonly NetworkRoute[];
  readonly ruleCount: number;
  readonly neighborCount: number;
}

export type ScannerErrorKind =
  | "invalidPlan"
  | "permission"
  | "unsupported"
  | "resourceLimit"
  | "lifecycle"
  | "context"
  | "io"
  | "environmentClosed"
  | "internal";

/** Stable scanner failure with the underlying Linux operation and errno when present. */
export class ScannerError extends Error {
  override readonly name = "ScannerError";
  readonly kind: ScannerErrorKind;
  readonly code: string;
  readonly operation: string;
  readonly errno: number | undefined;

  constructor(
    kind: ScannerErrorKind,
    code: string,
    operation: string,
    errno: number | undefined,
    message: string,
  ) {
    super(message);
    this.kind = kind;
    this.code = code;
    this.operation = operation;
    this.errno = errno;
  }
}

const RESULT_BATCH_SCHEMA_VERSION = 1 as const;
const MAX_BATCH_RESULTS = 4_096;
const MAX_BATCH_METADATA_BYTES = 4 * 1_024 * 1_024;
const MISSING_U64 = 0xffff_ffff_ffff_ffffn;
const textDecoder = new TextDecoder("utf-8", { fatal: true });

/** One lazy row view over sealed, Node-owned compact batch storage. */
export class ScanResultView implements ScanResult {
  readonly #batch: ScanResultBatch;
  readonly #index: number;

  constructor(batch: ScanResultBatch, index: number) {
    this.#batch = batch;
    this.#index = index;
  }

  get target(): string {
    return this.#batch.targetAt(this.#index);
  }

  get probe(): ScanResult["probe"] {
    return decodeProbe(this.#batch.byteAt("probes", this.#index));
  }

  get port(): number | undefined {
    const value = this.#batch.u16At("ports", this.#index);
    return value === 0 ? undefined : value;
  }

  get state(): ScanNetworkState | undefined {
    return decodeState(this.#batch.byteAt("states", this.#index));
  }

  get outcome(): ScanResult["outcome"] {
    return decodeOutcome(this.#batch.byteAt("outcomes", this.#index));
  }

  get attempt(): number {
    return this.#batch.u32At("attempts", this.#index);
  }

  get transmissions(): number {
    return this.#batch.u32At("transmissions", this.#index);
  }

  get rttNanoseconds(): bigint | undefined {
    const value = this.#batch.u64At("rttNanoseconds", this.#index);
    return value === MISSING_U64 ? undefined : value;
  }

  get rttMicros(): bigint | undefined {
    const value = this.rttNanoseconds;
    return value === undefined ? undefined : value / 1_000n;
  }

  get timestampNanoseconds(): bigint {
    return this.#batch.u64At("timestampsNanoseconds", this.#index);
  }

  get routeGeneration(): bigint {
    return this.#batch.u64At("routeGenerations", this.#index);
  }

  get evidence(): ScanResult["evidence"] | undefined {
    return decodeEvidence(this.#batch.byteAt("evidence", this.#index));
  }

  get reason(): string {
    return this.#batch.metadataAt(this.#index);
  }

  materialize(): ScanResult {
    const port = this.port;
    const state = this.state;
    const rttNanoseconds = this.rttNanoseconds;
    const evidence = this.evidence;
    return {
      target: this.target,
      probe: this.probe,
      ...(port === undefined ? {} : { port }),
      ...(state === undefined ? {} : { state }),
      outcome: this.outcome,
      attempt: this.attempt,
      transmissions: this.transmissions,
      ...(rttNanoseconds === undefined
        ? {}
        : {
            rttNanoseconds,
            rttMicros: rttNanoseconds / 1_000n,
          }),
      timestampNanoseconds: this.timestampNanoseconds,
      routeGeneration: this.routeGeneration,
      ...(evidence === undefined ? {} : { evidence }),
      reason: this.reason,
    };
  }
}

/** Version 1 little-endian columnar result batch with lazy row decoding. */
export class ScanResultBatch implements Iterable<ScanResultView> {
  readonly schemaVersion = RESULT_BATCH_SCHEMA_VERSION;
  readonly byteOrder = "little-endian" as const;
  readonly length: number;
  readonly columns: ScanResultBatchColumns;
  readonly results: ScanResultRows;

  constructor(encoded: EncodedScanResultBatch) {
    const snapshot = snapshotEncodedBatch(encoded);
    validateEncodedBatch(snapshot);
    const owned = ownedEncodedBatch(snapshot);
    validateEncodedBatch(owned);
    this.length = owned.rowCount;
    this.columns = Object.freeze({
      addressBytes: owned.addressBytes,
      addressOffsets: owned.addressOffsets,
      families: owned.families,
      scopes: owned.scopes,
      probes: owned.probes,
      ports: owned.ports,
      states: owned.states,
      outcomes: owned.outcomes,
      attempts: owned.attempts,
      transmissions: owned.transmissions,
      rttNanoseconds: owned.rttNanoseconds,
      timestampsNanoseconds: owned.timestampsNanoseconds,
      routeGenerations: owned.routeGenerations,
      evidence: owned.evidence,
      metadataBytes: owned.metadataBytes,
      metadataOffsets: owned.metadataOffsets,
    });
    this.results = createResultRows(this);
    Object.freeze(this);
  }

  get detached(): boolean {
    // Every valid batch has at least one family byte. The documented
    // transferList moves every column together, so this is an unambiguous
    // detached sentinel without misclassifying an empty metadata payload.
    return this.columns.families.byteLength === 0;
  }

  at(index: number): ScanResultView | undefined {
    if (!Number.isInteger(index)) return undefined;
    const normalized = index < 0 ? this.length + index : index;
    if (normalized < 0 || normalized >= this.length) return undefined;
    this.assertAttached();
    return new ScanResultView(this, normalized);
  }

  *[Symbol.iterator](): IterableIterator<ScanResultView> {
    for (let index = 0; index < this.length; index += 1) {
      yield new ScanResultView(this, index);
    }
  }

  *filter(
    predicate: (row: ScanResultView, index: number) => boolean,
  ): IterableIterator<ScanResultView> {
    let index = 0;
    for (const row of this) {
      if (predicate(row, index)) yield row;
      index += 1;
    }
  }

  materialize(): ScanResult[] {
    return Array.from(this, (row) => row.materialize());
  }

  transferList(): ArrayBuffer[] {
    this.assertAttached();
    return batchColumns(this.columns).map((column) => {
      if (!(column.buffer instanceof ArrayBuffer)) {
        throw batchDataError(
          "batch column is not backed by a transferable ArrayBuffer",
        );
      }
      return column.buffer;
    });
  }

  byteAt(
    column: "probes" | "states" | "outcomes" | "evidence",
    index: number,
  ): number {
    this.assertIndex(index);
    const value = this.columns[column][index];
    if (value === undefined)
      throw batchDataError(`${column} column is truncated`);
    return value;
  }

  u16At(column: "ports", index: number): number {
    return this.dataView(column, 2).getUint16(index * 2, true);
  }

  u32At(
    column: "attempts" | "scopes" | "transmissions",
    index: number,
  ): number {
    return this.dataView(column, 4).getUint32(index * 4, true);
  }

  u64At(
    column: "routeGenerations" | "rttNanoseconds" | "timestampsNanoseconds",
    index: number,
  ): bigint {
    return this.dataView(column, 8).getBigUint64(index * 8, true);
  }

  targetAt(index: number): string {
    this.assertIndex(index);
    const start = this.offsetAt("addressOffsets", index);
    const end = this.offsetAt("addressOffsets", index + 1);
    const family = this.columns.families[index];
    const expected = family === 4 ? 4 : family === 6 ? 16 : 0;
    if (
      expected === 0 ||
      end - start !== expected ||
      end > this.columns.addressBytes.length
    ) {
      throw batchDataError("address family or offset is invalid");
    }
    const bytes = this.columns.addressBytes.subarray(start, end);
    const address = family === 4 ? ipv4String(bytes) : ipv6String(bytes);
    const scope = this.u32At("scopes", index);
    return scope === 0 ? address : `${address}%${String(scope)}`;
  }

  metadataAt(index: number): string {
    this.assertIndex(index);
    const start = this.offsetAt("metadataOffsets", index);
    const end = this.offsetAt("metadataOffsets", index + 1);
    if (end < start || end > this.columns.metadataBytes.length) {
      throw batchDataError("metadata offset is invalid");
    }
    try {
      return textDecoder.decode(
        this.columns.metadataBytes.subarray(start, end),
      );
    } catch {
      throw batchDataError("metadata is not valid UTF-8");
    }
  }

  private offsetAt(
    column: "addressOffsets" | "metadataOffsets",
    index: number,
  ): number {
    return this.dataView(column, 4, true).getUint32(index * 4, true);
  }

  private dataView(
    column: keyof ScanResultBatchColumns,
    width: number,
    offsetColumn = false,
  ): DataView {
    if (!offsetColumn) this.assertAttached();
    const value = this.columns[column];
    const required = (offsetColumn ? this.length + 1 : this.length) * width;
    if (value.byteLength !== required) {
      throw batchDataError(`${column} column has an invalid length`);
    }
    return new DataView(value.buffer, value.byteOffset, value.byteLength);
  }

  private assertIndex(index: number): void {
    this.assertAttached();
    if (!Number.isInteger(index) || index < 0 || index >= this.length) {
      throw new RangeError("scan result index is out of range");
    }
  }

  private assertAttached(): void {
    if (this.detached)
      throw batchDataError("batch storage has been transferred or detached");
  }
}

function createResultRows(batch: ScanResultBatch): ScanResultRows {
  const rows = {
    get length(): number {
      return batch.length;
    },
    at(index: number): ScanResultView | undefined {
      return batch.at(index);
    },
    materialize(): ScanResult[] {
      return batch.materialize();
    },
    [Symbol.iterator](): Iterator<ScanResultView> {
      return batch[Symbol.iterator]();
    },
  };
  return new Proxy(rows, {
    get(target, property, receiver) {
      void receiver;
      if (typeof property === "string" && /^(0|[1-9]\d*)$/.test(property)) {
        return batch.at(Number(property));
      }
      if (property === "length") return target.length;
      if (property === "at") return (index: number) => target.at(index);
      if (property === "materialize") return () => target.materialize();
      if (property === Symbol.iterator) return () => target[Symbol.iterator]();
      return undefined;
    },
  });
}

function ownedBytes(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array)) {
    throw batchDataError("batch columns must be Uint8Array values");
  }
  return Uint8Array.from(value);
}

function ownedEncodedBatch(
  value: EncodedScanResultBatch,
): EncodedScanResultBatch {
  return {
    schemaVersion: value.schemaVersion,
    rowCount: value.rowCount,
    byteOrder: value.byteOrder,
    addressBytes: ownedBytes(value.addressBytes),
    addressOffsets: ownedBytes(value.addressOffsets),
    families: ownedBytes(value.families),
    scopes: ownedBytes(value.scopes),
    probes: ownedBytes(value.probes),
    ports: ownedBytes(value.ports),
    states: ownedBytes(value.states),
    outcomes: ownedBytes(value.outcomes),
    attempts: ownedBytes(value.attempts),
    transmissions: ownedBytes(value.transmissions),
    rttNanoseconds: ownedBytes(value.rttNanoseconds),
    timestampsNanoseconds: ownedBytes(value.timestampsNanoseconds),
    routeGenerations: ownedBytes(value.routeGenerations),
    evidence: ownedBytes(value.evidence),
    metadataBytes: ownedBytes(value.metadataBytes),
    metadataOffsets: ownedBytes(value.metadataOffsets),
  };
}

function snapshotEncodedBatch(
  value: EncodedScanResultBatch,
): EncodedScanResultBatch {
  return {
    schemaVersion: value.schemaVersion,
    rowCount: value.rowCount,
    byteOrder: value.byteOrder,
    addressBytes: value.addressBytes,
    addressOffsets: value.addressOffsets,
    families: value.families,
    scopes: value.scopes,
    probes: value.probes,
    ports: value.ports,
    states: value.states,
    outcomes: value.outcomes,
    attempts: value.attempts,
    transmissions: value.transmissions,
    rttNanoseconds: value.rttNanoseconds,
    timestampsNanoseconds: value.timestampsNanoseconds,
    routeGenerations: value.routeGenerations,
    evidence: value.evidence,
    metadataBytes: value.metadataBytes,
    metadataOffsets: value.metadataOffsets,
  };
}

function batchColumns(value: ScanResultBatchColumns): readonly Uint8Array[] {
  return [
    value.addressBytes,
    value.addressOffsets,
    value.families,
    value.scopes,
    value.probes,
    value.ports,
    value.states,
    value.outcomes,
    value.attempts,
    value.transmissions,
    value.rttNanoseconds,
    value.timestampsNanoseconds,
    value.routeGenerations,
    value.evidence,
    value.metadataBytes,
    value.metadataOffsets,
  ];
}

function validateEncodedBatch(value: EncodedScanResultBatch): void {
  if (
    untrustedBatchColumns(value).some(
      (column) => !(column instanceof Uint8Array),
    )
  ) {
    throw batchDataError("batch columns must be Uint8Array values");
  }
  if (value.schemaVersion !== RESULT_BATCH_SCHEMA_VERSION) {
    throw batchDataError("unsupported scan result batch schema version");
  }
  if (value.byteOrder !== "little-endian") {
    throw batchDataError("unsupported scan result batch byte order");
  }
  if (
    !Number.isInteger(value.rowCount) ||
    value.rowCount < 1 ||
    value.rowCount > MAX_BATCH_RESULTS
  ) {
    throw batchDataError("scan result batch row count is out of range");
  }
  if (value.metadataBytes.byteLength > MAX_BATCH_METADATA_BYTES) {
    throw batchDataError("scan result batch metadata exceeds 4 MiB");
  }
  if (
    value.addressBytes.byteLength < value.rowCount * 4 ||
    value.addressBytes.byteLength > value.rowCount * 16
  ) {
    throw batchDataError("scan result address storage is out of range");
  }
  const exact: readonly [Uint8Array, number, string][] = [
    [value.families, 1, "families"],
    [value.scopes, 4, "scopes"],
    [value.probes, 1, "probes"],
    [value.ports, 2, "ports"],
    [value.states, 1, "states"],
    [value.outcomes, 1, "outcomes"],
    [value.attempts, 4, "attempts"],
    [value.transmissions, 4, "transmissions"],
    [value.rttNanoseconds, 8, "rttNanoseconds"],
    [value.timestampsNanoseconds, 8, "timestampsNanoseconds"],
    [value.routeGenerations, 8, "routeGenerations"],
    [value.evidence, 1, "evidence"],
  ];
  for (const [column, width, name] of exact) {
    if (column.byteLength !== value.rowCount * width) {
      throw batchDataError(`${name} column has an invalid length`);
    }
  }
  validateOffsets(
    value.addressOffsets,
    value.rowCount,
    value.addressBytes.length,
    "address",
  );
  validateOffsets(
    value.metadataOffsets,
    value.rowCount,
    value.metadataBytes.length,
    "metadata",
  );
}

function untrustedBatchColumns(
  value: ScanResultBatchColumns,
): readonly unknown[] {
  return [
    value.addressBytes,
    value.addressOffsets,
    value.families,
    value.scopes,
    value.probes,
    value.ports,
    value.states,
    value.outcomes,
    value.attempts,
    value.transmissions,
    value.rttNanoseconds,
    value.timestampsNanoseconds,
    value.routeGenerations,
    value.evidence,
    value.metadataBytes,
    value.metadataOffsets,
  ];
}

function validateOffsets(
  offsets: Uint8Array,
  rows: number,
  bytes: number,
  name: string,
): void {
  if (offsets.byteLength !== (rows + 1) * 4) {
    throw batchDataError(`${name} offsets have an invalid length`);
  }
  const view = new DataView(
    offsets.buffer,
    offsets.byteOffset,
    offsets.byteLength,
  );
  let previous = 0;
  for (let index = 0; index <= rows; index += 1) {
    const current = view.getUint32(index * 4, true);
    if (
      current < previous ||
      current > bytes ||
      (index === 0 && current !== 0)
    ) {
      throw batchDataError(`${name} offsets are not bounded and monotonic`);
    }
    previous = current;
  }
  if (previous !== bytes)
    throw batchDataError(`${name} offsets do not cover their storage`);
}

function decodeProbe(value: number): ScanResult["probe"] {
  const decoded = [
    undefined,
    "arp",
    "ndp",
    "icmpEchoIpv4",
    "icmpEchoIpv6",
    "tcpSyn",
    "udp",
  ][value];
  if (decoded === undefined) throw batchDataError("probe code is invalid");
  return decoded as ScanResult["probe"];
}

function decodeState(value: number): ScanNetworkState | undefined {
  const decoded = [
    undefined,
    "open",
    "closed",
    "filtered",
    "open|filtered",
    "up",
    "unreachable",
    "unknown",
    "downByPolicy",
  ][value];
  if (value !== 0 && decoded === undefined)
    throw batchDataError("network-state code is invalid");
  return decoded as ScanNetworkState | undefined;
}

function decodeOutcome(value: number): ScanResult["outcome"] {
  const decoded = [
    undefined,
    "network",
    "cancelled",
    "deadline",
    "transportFailed",
    "contextInvalidated",
  ][value];
  if (decoded === undefined) throw batchDataError("outcome code is invalid");
  return decoded as ScanResult["outcome"];
}

function decodeEvidence(value: number): ScanResult["evidence"] | undefined {
  const decoded = [
    undefined,
    "tuple",
    "truncatedQuote",
    "tcpSequence32",
    "payload128",
  ][value];
  if (value !== 0 && decoded === undefined)
    throw batchDataError("evidence code is invalid");
  return decoded as ScanResult["evidence"] | undefined;
}

function ipv4String(bytes: Uint8Array): string {
  return Array.from(bytes, String).join(".");
}

function ipv6String(bytes: Uint8Array): string {
  const groups = Array.from(
    { length: 8 },
    (_, index) => ((bytes[index * 2] ?? 0) << 8) | (bytes[index * 2 + 1] ?? 0),
  );
  let bestStart = -1;
  let bestLength = 0;
  for (let start = 0; start < groups.length;) {
    if (groups[start] !== 0) {
      start += 1;
      continue;
    }
    let end = start + 1;
    while (end < groups.length && groups[end] === 0) end += 1;
    if (end - start > bestLength && end - start >= 2) {
      bestStart = start;
      bestLength = end - start;
    }
    start = end;
  }
  if (bestStart === -1)
    return groups.map((group) => group.toString(16)).join(":");
  const left = groups
    .slice(0, bestStart)
    .map((group) => group.toString(16))
    .join(":");
  const right = groups
    .slice(bestStart + bestLength)
    .map((group) => group.toString(16))
    .join(":");
  return `${left}::${right}`;
}

function batchDataError(message: string): ScannerError {
  return new ScannerError(
    "internal",
    "ERR_INVALID_BATCH",
    "decode result batch",
    undefined,
    message,
  );
}

interface NativeTarget {
  cidr?: string;
  start?: string;
  end?: string;
}

interface NativeProbe {
  kind: string;
  family?: string;
  ports?: { start: number; end: number }[];
  payload?: number[];
}

interface NativePlan {
  targets: NativeTarget[];
  exclude?: NativeTarget[];
  probes: NativeProbe[];
  deadlineMs: number;
  rate?: ScanRateOptions;
  timing?: ScanTimingOptions;
  seed?: string;
  sourceAddress?: string;
  interface?: string;
  vlan?: ScanVlanOptions;
  sourcePortStart?: number;
  sourcePortEnd?: number;
}

interface NativeBatch {
  schemaVersion: 1;
  rowCount: number;
  byteOrder: "little-endian";
  addressBytes: Uint8Array;
  addressOffsets: Uint8Array;
  families: Uint8Array;
  scopes: Uint8Array;
  probes: Uint8Array;
  ports: Uint8Array;
  states: Uint8Array;
  outcomes: Uint8Array;
  attempts: Uint8Array;
  transmissions: Uint8Array;
  rttNanoseconds: Uint8Array;
  timestampsNanoseconds: Uint8Array;
  routeGenerations: Uint8Array;
  evidence: Uint8Array;
  metadataBytes: Uint8Array;
  metadataOffsets: Uint8Array;
}

interface NativePullResult {
  status: "batch" | "terminal" | "aborted";
  batch?: NativeBatch;
}

interface NativeProgress {
  sent: string;
  received: string;
  matched: string;
  duplicate: string;
  invalid: string;
  timedOut: string;
  retried: string;
  kernelDropped: string;
  applicationBackpressured: string;
  coalescedUpdates: string;
}

interface NativeSummary {
  state: ScanSessionState;
  logicalProbes: string;
  results: string;
  open: string;
  closed: string;
  filtered: string;
  openOrFiltered: string;
  up: string;
  unreachable: string;
  unknown: string;
  cancelled: string;
  deadline: string;
  discarded: string;
  kernelDropped: string;
  forgedOrUnrelated: string;
  duplicates: string;
  lateResponses: string;
  progress: NativeProgress;
  schedulingSeed?: string;
  accuracyTradeoff: boolean;
  error?: NativeFailure;
}

interface NativeFailure {
  kind: ScannerErrorKind;
  code: string;
  operation: string;
  errno?: number;
  message: string;
}

interface NativeSnapshot {
  generation: string;
  netnsCookie?: string;
  interfaces: (Omit<NetworkInterface, "hardwareAddress"> & {
    hardwareAddress: number[];
  })[];
  addresses: NetworkAddress[];
  routes: NetworkRoute[];
  ruleCount: number;
  neighborCount: number;
}

interface NativeScannerHandle {
  ready(): Promise<unknown>;
  start(plan: NativePlan): Promise<unknown>;
  pause(sessionId: number): Promise<unknown>;
  resume(sessionId: number): Promise<unknown>;
  cancel(sessionId: number): Promise<unknown>;
  nextBatch(
    sessionId: number,
    pullId: number,
    maximum?: number,
  ): Promise<unknown>;
  cancelPull(sessionId: number, pullId: number): Promise<unknown>;
  progress(sessionId: number): Promise<unknown>;
  summary(sessionId: number): Promise<unknown>;
  closeSession(sessionId: number): Promise<unknown>;
  state(sessionId: number): string;
  close(): Promise<unknown>;
}

interface NativeBinding {
  createNativeScanner(): NativeScannerHandle;
  inspectNetworkContext(): Promise<unknown>;
}

const require = createRequire(import.meta.url);
const native = require("../build/native/binding.cjs") as NativeBinding;

/** One environment-owned scanner control object. */
export class Scanner {
  readonly #handle: NativeScannerHandle;
  #closePromise: Promise<void> | undefined;
  #closed = false;

  constructor(handle: NativeScannerHandle) {
    this.#handle = handle;
  }

  async start(plan: ScanPlan): Promise<ScanSession> {
    if (this.#closed) {
      throw new ScannerError(
        "lifecycle",
        "ERR_INVALID_STATE",
        "start session",
        undefined,
        "scanner is closed",
      );
    }
    try {
      const id = (await this.#handle.start(nativePlan(plan))) as number;
      return new ScanSession(this.#handle, id);
    } catch (error) {
      throw normalizeError(error);
    }
  }

  close(): Promise<void> {
    if (this.#closePromise !== undefined) return this.#closePromise;
    this.#closed = true;
    this.#closePromise = this.#handle.close().then(
      () => undefined,
      (error: unknown) => Promise.reject(normalizeError(error)),
    );
    return this.#closePromise;
  }
}

/** A native scan session with pull-based bounded result delivery. */
export class ScanSession {
  readonly #handle: NativeScannerHandle;
  readonly #id: number;
  #cancelPromise: Promise<ScanSummary> | undefined;
  #summaryPromise: Promise<ScanSummary> | undefined;
  #closePromise: Promise<void> | undefined;
  #pullPending = false;
  #nextPullId = 1;
  #closed = false;

  constructor(handle: NativeScannerHandle, id: number) {
    this.#handle = handle;
    this.#id = id;
  }

  get state(): ScanSessionState {
    if (this.#closed) return "closed";
    try {
      return this.#handle.state(this.#id) as ScanSessionState;
    } catch (error) {
      throw normalizeError(error);
    }
  }

  async pause(): Promise<void> {
    await this.#control(() => this.#handle.pause(this.#id));
  }

  async resume(): Promise<void> {
    await this.#control(() => this.#handle.resume(this.#id));
  }

  cancel(reason?: string): Promise<ScanSummary> {
    void reason;
    if (this.#cancelPromise !== undefined) return this.#cancelPromise;
    this.#cancelPromise = this.#handle.cancel(this.#id).then(
      (value) => publicSummary(value as NativeSummary),
      (error: unknown) => Promise.reject(normalizeError(error)),
    );
    return this.#cancelPromise;
  }

  async nextBatch(
    options: NextBatchOptions = {},
  ): Promise<ScanResultBatch | null> {
    if (this.#closed) return null;
    if (options.signal?.aborted === true) throw abortError(options.signal);
    if (this.#pullPending) {
      throw new ScannerError(
        "resourceLimit",
        "ERR_PENDING_PULL",
        "pull result batch",
        undefined,
        "only one nextBatch operation may be pending",
      );
    }
    if (this.#nextPullId > 0xffff_ffff) {
      throw new ScannerError(
        "resourceLimit",
        "ERR_PULL_ID_EXHAUSTED",
        "pull result batch",
        undefined,
        "pull identifier space exhausted",
      );
    }
    const pullId = this.#nextPullId;
    this.#nextPullId += 1;
    this.#pullPending = true;
    const abort = (): void => {
      void this.#handle.cancelPull(this.#id, pullId).catch(() => undefined);
    };
    options.signal?.addEventListener("abort", abort, { once: true });
    try {
      const value = (await this.#handle.nextBatch(
        this.#id,
        pullId,
        options.maxResults,
      )) as NativePullResult;
      if (value.status === "terminal") return null;
      if (value.status === "aborted") {
        throw abortError(options.signal);
      }
      if (value.batch === undefined) {
        throw batchDataError("native pull returned an invalid status");
      }
      return new ScanResultBatch(value.batch);
    } catch (error) {
      if (isAbortError(error)) throw error;
      throw normalizeError(error);
    } finally {
      options.signal?.removeEventListener("abort", abort);
      this.#pullPending = false;
    }
  }

  async progress(): Promise<ScanProgress> {
    try {
      return publicProgress(
        (await this.#handle.progress(this.#id)) as NativeProgress,
      );
    } catch (error) {
      throw normalizeError(error);
    }
  }

  batches(options: ScanBatchEventEmitterOptions = {}): ScanBatchEventEmitter {
    return new ScanBatchEventEmitter(this, options);
  }

  summary(): Promise<ScanSummary> {
    if (this.#summaryPromise !== undefined) return this.#summaryPromise;
    this.#summaryPromise = this.#handle.summary(this.#id).then(
      (value) => publicSummary(value as NativeSummary),
      (error: unknown) => Promise.reject(normalizeError(error)),
    );
    return this.#summaryPromise;
  }

  close(): Promise<void> {
    if (this.#closePromise !== undefined) return this.#closePromise;
    this.#closed = true;
    this.#closePromise = this.#handle.closeSession(this.#id).then(
      () => undefined,
      (error: unknown) => Promise.reject(normalizeError(error)),
    );
    return this.#closePromise;
  }

  async #control(operation: () => Promise<unknown>): Promise<void> {
    if (this.#closed) {
      throw new ScannerError(
        "lifecycle",
        "ERR_INVALID_STATE",
        "control session",
        undefined,
        "session is closed",
      );
    }
    try {
      await operation();
    } catch (error) {
      throw normalizeError(error);
    }
  }
}

/** Optional Node-style batch events layered over one cancellable pull at a time. */
export class ScanBatchEventEmitter extends EventEmitter<ScanBatchEventMap> {
  readonly #session: ScanSession;
  readonly #maxResults: number | undefined;
  #status: ScanBatchEventEmitterStatus = "idle";
  #controller: AbortController | undefined;
  #pumpPromise: Promise<void> | undefined;
  #pausePromise: Promise<void> | undefined;
  #detachPromise: Promise<ScanSession> | undefined;
  #closePromise: Promise<void> | undefined;

  constructor(
    session: ScanSession,
    options: ScanBatchEventEmitterOptions = {},
  ) {
    super();
    validateBatchMaximum(options.maxResults);
    this.#session = session;
    this.#maxResults = options.maxResults;
  }

  get status(): ScanBatchEventEmitterStatus {
    return this.#status;
  }

  start(): this {
    if (this.#status === "running") return this;
    if (this.#status !== "idle") throw adapterStateError("start", this.#status);
    this.#status = "running";
    this.#beginPump();
    return this;
  }

  resume(): this {
    if (this.#status === "running") return this;
    if (this.#status !== "paused")
      throw adapterStateError("resume", this.#status);
    this.#status = "running";
    this.#pausePromise = undefined;
    this.#beginPump();
    return this;
  }

  pause(): Promise<void> {
    if (this.#pausePromise !== undefined) return this.#pausePromise;
    if (this.#status === "idle") {
      this.#status = "paused";
      this.#pausePromise = Promise.resolve();
      return this.#pausePromise;
    }
    if (this.#status === "paused") return Promise.resolve();
    if (this.#status !== "running") {
      return Promise.reject(adapterStateError("pause", this.#status));
    }
    this.#status = "pausing";
    this.#controller?.abort();
    this.#pausePromise = (this.#pumpPromise ?? Promise.resolve()).then(() => {
      if (this.#status === "pausing") this.#status = "paused";
    });
    return this.#pausePromise;
  }

  detach(): Promise<ScanSession> {
    if (this.#detachPromise !== undefined) return this.#detachPromise;
    if (this.#status === "closed" || this.#status === "closing") {
      return Promise.reject(adapterStateError("detach", this.#status));
    }
    this.#status = "detaching";
    this.#controller?.abort();
    this.#detachPromise = (this.#pumpPromise ?? Promise.resolve()).then(() => {
      this.#status = "detached";
      return this.#session;
    });
    return this.#detachPromise;
  }

  close(): Promise<void> {
    if (this.#closePromise !== undefined) return this.#closePromise;
    if (this.#status === "detached" || this.#status === "detaching") {
      return Promise.reject(adapterStateError("close", this.#status));
    }
    this.#status = "closing";
    this.#controller?.abort();
    this.#closePromise = (this.#pumpPromise ?? Promise.resolve())
      .then(() => this.#session.close())
      .then(() => {
        this.#status = "closed";
        this.emit("close");
      });
    return this.#closePromise;
  }

  #beginPump(): void {
    this.#pumpPromise = this.#pump();
  }

  async #pump(): Promise<void> {
    while (this.#status === "running") {
      const controller = new AbortController();
      this.#controller = controller;
      try {
        const batch = await this.#session.nextBatch({
          ...(this.#maxResults === undefined
            ? {}
            : { maxResults: this.#maxResults }),
          signal: controller.signal,
        });
        if (batch === null) {
          this.#status = "ended";
          this.emit("end");
          return;
        }
        // A pull fulfilled before its cancellation command is observable and
        // must cross the adapter boundary before pause/detach/close settles.
        this.emit("batch", batch);
      } catch (error) {
        if (isAbortError(error) && this.#isBoundaryStatus()) {
          return;
        }
        this.#status = "paused";
        this.emit(
          "error",
          error instanceof Error ? error : normalizeError(error),
        );
        return;
      } finally {
        if (this.#controller === controller) this.#controller = undefined;
      }
    }
  }

  #isBoundaryStatus(): boolean {
    return (
      this.#status === "pausing" ||
      this.#status === "detaching" ||
      this.#status === "closing"
    );
  }
}

/** Captures a complete read-only snapshot without requiring raw-socket authority. */
export async function inspectNetworkContext(): Promise<NetworkContextSnapshot> {
  try {
    const value = (await native.inspectNetworkContext()) as NativeSnapshot;
    return {
      generation: BigInt(value.generation),
      ...(value.netnsCookie === undefined
        ? {}
        : { netnsCookie: BigInt(value.netnsCookie) }),
      interfaces: value.interfaces.map((item) => ({
        ...item,
        hardwareAddress: Uint8Array.from(item.hardwareAddress),
      })),
      addresses: value.addresses,
      routes: value.routes,
      ruleCount: value.ruleCount,
      neighborCount: value.neighborCount,
    };
  } catch (error) {
    throw normalizeError(error);
  }
}

/** Creates one scanner over the environment-scoped native runtime. */
export async function createScanner(): Promise<Scanner> {
  const handle = native.createNativeScanner();
  try {
    await handle.ready();
    return new Scanner(handle);
  } catch (error) {
    await handle.close().catch(() => undefined);
    throw normalizeError(error);
  }
}

function nativePlan(plan: ScanPlan): NativePlan {
  validateControlPlan(plan);
  return {
    targets: plan.targets.map(nativeTarget),
    ...(plan.exclude === undefined
      ? {}
      : { exclude: plan.exclude.map(nativeTarget) }),
    probes: plan.probes.map(nativeProbe),
    deadlineMs: plan.deadlineMs,
    ...(plan.rate === undefined ? {} : { rate: plan.rate }),
    ...(plan.timing === undefined ? {} : { timing: plan.timing }),
    ...(plan.seed === undefined ? {} : { seed: plan.seed.toString() }),
    ...(plan.sourceAddress === undefined
      ? {}
      : { sourceAddress: plan.sourceAddress }),
    ...(plan.interface === undefined ? {} : { interface: plan.interface }),
    ...(plan.vlan === undefined ? {} : { vlan: plan.vlan }),
    ...(plan.sourcePortRange === undefined
      ? {}
      : {
          sourcePortStart: plan.sourcePortRange.start,
          sourcePortEnd: plan.sourcePortRange.end,
        }),
  };
}

function validateControlPlan(plan: ScanPlan): void {
  let items =
    plan.targets.length + (plan.exclude?.length ?? 0) + plan.probes.length;
  if (items > 65_536) throw controlItemsError();
  let bytes = 0;
  for (const targets of [plan.targets, plan.exclude ?? []]) {
    for (const target of targets) {
      if ("cidr" in target) bytes += Buffer.byteLength(target.cidr);
      else
        bytes +=
          Buffer.byteLength(target.start) + Buffer.byteLength(target.end);
    }
  }
  for (const probe of plan.probes) {
    if (probe.kind === "tcpSyn" || probe.kind === "udp") {
      items += probe.ports.length;
      if (items > 65_536) throw controlItemsError();
      if (probe.kind === "udp") bytes += probe.payload?.byteLength ?? 0;
    }
  }
  // Account for fixed object/field framing in addition to variable payloads.
  bytes += items * 32;
  if (bytes > 4 * 1_024 * 1_024) {
    throw new ScannerError(
      "resourceLimit",
      "ERR_CONTROL_BYTES",
      "validate scan plan",
      undefined,
      "one scanner control command may contain at most 4 MiB",
    );
  }
}

function controlItemsError(): ScannerError {
  return new ScannerError(
    "resourceLimit",
    "ERR_CONTROL_ITEMS",
    "validate scan plan",
    undefined,
    "one scanner control command may contain at most 65536 items",
  );
}

function nativeTarget(target: ScanTarget): NativeTarget {
  return "cidr" in target
    ? { cidr: target.cidr }
    : { start: target.start, end: target.end };
}

function nativeProbe(probe: ScanProbe): NativeProbe {
  if (probe.kind === "arp" || probe.kind === "ndp") return { kind: probe.kind };
  if (probe.kind === "icmpEcho")
    return { kind: probe.kind, family: probe.family };
  return {
    kind: probe.kind,
    ports: probe.ports.map((port) =>
      typeof port === "number"
        ? { start: port, end: port }
        : { start: port.start, end: port.end },
    ),
    ...(probe.kind === "udp" && probe.payload !== undefined
      ? { payload: Array.from(probe.payload) }
      : {}),
  };
}

function publicSummary(value: NativeSummary): ScanSummary {
  return {
    state: value.state,
    logicalProbes: BigInt(value.logicalProbes),
    results: BigInt(value.results),
    open: BigInt(value.open),
    closed: BigInt(value.closed),
    filtered: BigInt(value.filtered),
    openOrFiltered: BigInt(value.openOrFiltered),
    up: BigInt(value.up),
    unreachable: BigInt(value.unreachable),
    unknown: BigInt(value.unknown),
    cancelled: BigInt(value.cancelled),
    deadline: BigInt(value.deadline),
    discarded: BigInt(value.discarded),
    kernelDropped: BigInt(value.kernelDropped),
    forgedOrUnrelated: BigInt(value.forgedOrUnrelated),
    duplicates: BigInt(value.duplicates),
    lateResponses: BigInt(value.lateResponses),
    progress: publicProgress(value.progress),
    ...(value.schedulingSeed === undefined
      ? {}
      : { schedulingSeed: BigInt(value.schedulingSeed) }),
    accuracyTradeoff: value.accuracyTradeoff,
    ...(value.error === undefined
      ? {}
      : {
          error: new ScannerError(
            value.error.kind,
            value.error.code,
            value.error.operation,
            value.error.errno,
            value.error.message,
          ),
        }),
  };
}

function publicProgress(value: NativeProgress): ScanProgress {
  return {
    sent: BigInt(value.sent),
    received: BigInt(value.received),
    matched: BigInt(value.matched),
    duplicate: BigInt(value.duplicate),
    invalid: BigInt(value.invalid),
    timedOut: BigInt(value.timedOut),
    retried: BigInt(value.retried),
    kernelDropped: BigInt(value.kernelDropped),
    applicationBackpressured: BigInt(value.applicationBackpressured),
    coalescedUpdates: BigInt(value.coalescedUpdates),
  };
}

function validateBatchMaximum(value: number | undefined): void {
  if (
    value !== undefined &&
    (!Number.isInteger(value) || value < 1 || value > MAX_BATCH_RESULTS)
  ) {
    throw new ScannerError(
      "invalidPlan",
      "ERR_INVALID_ARGUMENT",
      "configure batch adapter",
      undefined,
      "maxResults must be from 1 through 4096",
    );
  }
}

function adapterStateError(
  operation: string,
  status: ScanBatchEventEmitterStatus,
): ScannerError {
  return new ScannerError(
    "lifecycle",
    "ERR_INVALID_STATE",
    `${operation} batch event adapter`,
    undefined,
    `batch event adapter is ${status}`,
  );
}

function abortError(signal: AbortSignal | undefined): Error {
  const reason = signal?.reason as unknown;
  if (reason instanceof Error) return reason;
  return new DOMException(
    typeof reason === "string" ? reason : "The operation was aborted",
    "AbortError",
  );
}

function isAbortError(error: unknown): error is Error {
  return error instanceof Error && error.name === "AbortError";
}

function normalizeError(error: unknown): ScannerError {
  if (error instanceof ScannerError) return error;
  const message = error instanceof Error ? error.message : String(error);
  const marker = "NODENET_SCANNER|";
  const start = message.indexOf(marker);
  if (start !== -1) {
    const [kind, code, operation, errno, ...rest] = message
      .slice(start + marker.length)
      .split("|");
    if (
      kind !== undefined &&
      code !== undefined &&
      operation !== undefined &&
      errno !== undefined
    ) {
      return new ScannerError(
        kind as ScannerErrorKind,
        code,
        operation,
        errno === "" ? undefined : Number(errno),
        rest.join("|"),
      );
    }
  }
  return new ScannerError(
    "internal",
    "ERR_SCANNER_INTERNAL",
    "native scanner",
    undefined,
    message,
  );
}
