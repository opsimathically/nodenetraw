import { EventEmitter } from "node:events";
import { createRequire } from "node:module";
import { isIPv4, isIPv6 } from "node:net";
import { EventReceiveController } from "./internal/event-controller.js";
import {
  createInternalFinalizers,
  type InternalFinalizers,
} from "./internal/finalizers.js";

const MAX_PACKET_LENGTH = 65_535;
const DEFAULT_CONTROL_CAPACITY = 4 * 1024;
const MAX_CONTROL_CAPACITY = 64 * 1024;
const MAX_SOCKET_BUFFER_SIZE = 16 * 1024 * 1024;
const OPEN_OPERATION_ID = 0;
const MAX_OPERATION_ID = 0xffff_ffff;

/** Common Linux IP protocol numbers accepted by IPv4/IPv6 raw sockets. */
export const IPPROTO_ICMP = 1;
export const IPPROTO_IGMP = 2;
export const IPPROTO_IPIP = 4;
export const IPPROTO_TCP = 6;
export const IPPROTO_UDP = 17;
export const IPPROTO_IPV6 = 41;
export const IPPROTO_GRE = 47;
export const IPPROTO_ESP = 50;
export const IPPROTO_AH = 51;
export const IPPROTO_ICMPV6 = 58;
export const IPPROTO_SCTP = 132;
export const IPPROTO_UDPLITE = 136;
export const IPPROTO_RAW = 255;

/** Common Linux Ethernet protocol identifiers accepted by packet sockets. */
export const ETH_P_ALL = 0x0003;
export const ETH_P_IP = 0x0800;
export const ETH_P_ARP = 0x0806;
export const ETH_P_8021Q = 0x8100;
export const ETH_P_IPV6 = 0x86dd;
export const ETH_P_8021AD = 0x88a8;

export type RawSocketStatus = "open" | "closing" | "closed";

export type RawSocketErrorKind =
  | "aborted"
  | "internal"
  | "invalidArgument"
  | "invalidState"
  | "queueFull"
  | "reactorClosed"
  | "receiverActive"
  | "socketClosed"
  | "system"
  | "malformedControl"
  | "unsupported";

export interface RawSocketOptions {
  /** Defaults to `ipv4` for compatibility. */
  family?: RawSocketFamily;
  /** Linux IP protocol number from 1 through 255. */
  protocol: number;
  /** Required for packet sockets; raw includes the link header, cooked omits it. */
  mode?: PacketSocketMode;
}
export type RawSocketFamily = "ipv4" | "ipv6" | "packet";

export interface RawSocketEventEmitterOptions {
  readonly dataCapacity?: number;
  readonly controlCapacity?: number;
  readonly errorQueue?: boolean;
}

export type RawSocketEventEmitterStatus =
  | "idle"
  | "running"
  | "pausing"
  | "paused"
  | "detaching"
  | "detached"
  | "closing"
  | "closed";

export interface RawSocketEventMap {
  message: [message: ReceivedMessage];
  error: [error: unknown];
  close: [];
}
export type PacketSocketMode = "raw" | "cooked";
export interface ClassicBpfInstruction {
  readonly code: number;
  readonly jumpTrue: number;
  readonly jumpFalse: number;
  readonly value: number;
}
export type PacketMembershipKind = "promiscuous" | "allMulticast" | "multicast";
export interface PacketMembership {
  readonly interfaceIndex: number;
  readonly kind: PacketMembershipKind;
  readonly address?: Uint8Array;
}
export type PacketFanoutMode =
  | "hash"
  | "loadBalance"
  | "cpu"
  | "rollover"
  | "random"
  | "queueMapping"
  | "classicBpf"
  | "ebpf";
export interface PacketStatistics {
  readonly packets: number;
  readonly drops: number;
}
export interface PacketAuxdata {
  readonly status: number;
  readonly originalLength: number;
  readonly snapshotLength: number;
  readonly macOffset: number;
  readonly networkOffset: number;
  readonly vlanTci: number;
  readonly vlanTpid: number;
}

export interface PacketRingConfig {
  readonly blockSize?: number;
  readonly blockCount?: number;
  readonly frameSize?: number;
  readonly retireTimeoutMs?: number;
}

export class PacketRingFrameLease {
  #data: Buffer | undefined;
  readonly originalLength: number;
  readonly snapshotLength: number;
  readonly timestamp: bigint;
  readonly status: number;
  readonly vlanTci: number;
  readonly vlanTpid: number;

  /** @internal Constructed by `RawSocket.receiveRingFrame()`. */
  constructor(
    data: Buffer,
    originalLength: number,
    snapshotLength: number,
    seconds: number,
    nanoseconds: number,
    status: number,
    vlanTci: number,
    vlanTpid: number,
  ) {
    this.#data = data;
    this.originalLength = originalLength;
    this.snapshotLength = snapshotLength;
    this.timestamp = BigInt(seconds) * 1_000_000_000n + BigInt(nanoseconds);
    this.status = status;
    this.vlanTci = vlanTci;
    this.vlanTpid = vlanTpid;
  }

  get released(): boolean {
    return this.#data === undefined;
  }

  read(): Buffer {
    if (this.#data === undefined)
      throw invalidArgument(
        "receiveRingFrame",
        "packet ring frame lease is released",
      );
    return Buffer.from(this.#data);
  }

  release(): void {
    this.#data = undefined;
  }
}

export interface RawSocketOptionMap {
  broadcast: boolean;
  ipTtl: number;
  ipTypeOfService: number;
  receiveBufferSize: number;
  sendBufferSize: number;
  receivePacketInfo: boolean;
  receiveTtl: boolean;
  receiveTypeOfService: boolean;
  receiveTimestampNanoseconds: boolean;
  receiveQueueOverflow: boolean;
  receiveErrors: boolean;
  bindToDevice: string | null;
  ipv6Only: boolean;
  ipv6UnicastHops: number;
  ipv6TrafficClass: number;
  ipv6MulticastHops: number;
  receiveHopLimit: boolean;
  receiveTrafficClass: boolean;
  headerIncluded: boolean;
  freebind: boolean;
  transparent: boolean;
  priority: number;
  mark: number;
  pathMtuDiscovery: number;
  multicastTtl: number;
  multicastLoop: boolean;
  ipv6ChecksumOffset: number;
  busyPollMicroseconds: number;
}

export type SendMessageFlag = "dontRoute";
export type ReceiveMessageFlag = "peek" | "errorQueue";
export type ReceivedMessageFlag = "endOfRecord" | "outOfBand" | "errorQueue";

export interface Ipv4MessageAddress {
  readonly family: "ipv4";
  readonly address: string;
}
export interface Ipv6MessageAddress {
  readonly family: "ipv6";
  readonly address: string;
  readonly scopeId?: number;
  readonly flowInfo?: number;
}
export interface PacketMessageAddress {
  readonly family: "packet";
  readonly interfaceIndex: number;
  readonly protocol: number;
  readonly address?: Uint8Array;
  readonly hardwareType?: number;
  readonly packetType?: number;
}
export type IpMessageAddress =
  Ipv4MessageAddress | Ipv6MessageAddress | PacketMessageAddress;

export type SendControlMessage =
  | {
      readonly kind: "ipv4PacketInfo";
      readonly interfaceIndex?: number;
      readonly sourceAddress?: string;
    }
  | { readonly kind: "ipv4Ttl"; readonly value: number }
  | {
      readonly kind: "ipv6PacketInfo";
      readonly interfaceIndex?: number;
      readonly sourceAddress?: string;
    }
  | {
      readonly kind: "ipv6HopLimit" | "ipv6TrafficClass";
      readonly value: number;
    };

export type ReceivedControlMessage =
  | {
      readonly kind: "ipv4PacketInfo";
      readonly interfaceIndex: number;
      readonly selectedAddress: string;
      readonly destinationAddress: string;
    }
  | { readonly kind: "ipv4Ttl" | "ipv4TypeOfService"; readonly value: number }
  | {
      readonly kind: "timestampNanoseconds";
      readonly seconds: bigint;
      readonly nanoseconds: number;
      readonly timestamp: bigint;
    }
  | { readonly kind: "receiveQueueOverflow"; readonly value: number }
  | {
      readonly kind: "ipv4ExtendedError";
      readonly errno: number;
      readonly origin: number;
      readonly type: number;
      readonly code: number;
      readonly info: number;
      readonly data: number;
      readonly offender?: string;
    }
  | {
      readonly kind: "unknown";
      readonly level: number;
      readonly type: number;
      readonly data: Buffer;
    }
  | {
      readonly kind: "ipv6PacketInfo";
      readonly interfaceIndex: number;
      readonly destinationAddress: string;
    }
  | {
      readonly kind: "ipv6HopLimit" | "ipv6TrafficClass";
      readonly value: number;
    }
  | {
      readonly kind: "ipv6ExtendedError";
      readonly errno: number;
      readonly origin: number;
      readonly type: number;
      readonly code: number;
      readonly info: number;
      readonly data: number;
      readonly offender?: string;
    };

export interface SendMessageRequest {
  readonly data: Uint8Array;
  readonly destination: IpMessageAddress;
  readonly flags?: readonly SendMessageFlag[];
  readonly control?: readonly SendControlMessage[];
  readonly signal?: AbortSignal;
}

export interface ReceiveMessageOptions {
  readonly dataCapacity?: number;
  readonly controlCapacity?: number;
  readonly flags?: readonly ReceiveMessageFlag[];
  readonly signal?: AbortSignal;
}

export interface BatchSendRequest {
  readonly data: Uint8Array;
  readonly destination: IpMessageAddress;
}

export interface SendBatchResult {
  readonly requested: number;
  readonly completed: number;
  readonly results: readonly {
    readonly index: number;
    readonly bytesSent: number;
  }[];
}

export interface ReceiveBatchOptions {
  readonly count: number;
  readonly dataCapacity?: number;
  readonly signal?: AbortSignal;
}

export interface ReceiveBatchResult {
  readonly completed: number;
  readonly messages: readonly ReceivedMessage[];
}

export interface ReceivedMessage {
  readonly data: Buffer;
  readonly source: IpMessageAddress | undefined;
  readonly dataLength: number;
  readonly dataTruncated: boolean;
  readonly controlTruncated: boolean;
  readonly flags: readonly ReceivedMessageFlag[];
  readonly control: readonly ReceivedControlMessage[];
  readonly ipv4: Ipv4PacketMetadata | undefined;
  readonly packetAuxdata: PacketAuxdata | undefined;
}

export interface AbortableOperationOptions {
  readonly signal?: AbortSignal;
}

export type RawSocketOptionName = keyof RawSocketOptionMap;

export interface Ipv4PacketMetadata {
  destinationAddress: string;
  protocol: number;
  ttl: number;
  typeOfService: number;
  headerLength: number;
  totalLength: number;
  identification: number;
  fragmentOffset: number;
  dontFragment: boolean;
  moreFragments: boolean;
}

export interface ReceivedPacket {
  /** The received IPv4 packet bytes. Raw IPv4 receives include the IP header. */
  data: Buffer;
  /** Dotted-decimal IPv4 source address reported by Linux. */
  sourceAddress: string;
  /** Original datagram length reported by Linux, before capture truncation. */
  packetLength: number;
  /** True when the packet exceeded the requested receive buffer length. */
  truncated: boolean;
  /** Parsed IPv4 header fields when the captured bytes contain a valid header. */
  ipv4: Ipv4PacketMetadata | undefined;
}

type NativeIpv4PacketMetadata = Ipv4PacketMetadata;

interface NativeErrorData {
  kind: string;
  code: string;
  operation: string;
  errno?: number;
  errnoName?: string;
  message: string;
}

interface NativeCompletion {
  operationId: number;
  kind: string;
  bytesSent?: number;
  data?: Buffer;
  sourceAddress?: string;
  packetLength?: number;
  truncated?: boolean;
  ipv4?: NativeIpv4PacketMetadata;
  localAddress?: string;
  localFamily?: string;
  localScopeId?: number;
  localFlowInfo?: number;
  optionValue?: number;
  deviceValue?: string;
  message?: NativeReceivedMessage;
  rawOption?: Buffer;
  statisticsPackets?: number;
  statisticsDrops?: number;
  batchMessages?: NativeReceivedMessage[];
  batchLengths?: number[];
  batchRequested?: number;
  ringData?: Buffer;
  ringOriginalLength?: number;
  ringSnapshotLength?: number;
  ringSeconds?: number;
  ringNanoseconds?: number;
  ringStatus?: number;
  ringVlanTci?: number;
  ringVlanTpid?: number;
  error?: NativeErrorData;
}

interface NativeSendControlMessage {
  kind: string;
  interfaceIndex?: number;
  sourceAddress?: string;
  value?: number;
}
interface NativeReceivedControlMessage {
  kind: string;
  interfaceIndex?: number;
  selectedAddress?: string;
  destinationAddress?: string;
  value?: number;
  seconds?: string;
  nanoseconds?: number;
  errno?: number;
  origin?: number;
  errorType?: number;
  errorCode?: number;
  info?: number;
  extendedData?: number;
  offender?: string;
  level?: number;
  messageType?: number;
  data?: Buffer;
}
interface NativeReceivedMessage {
  data: Buffer;
  sourceAddress?: string;
  sourceFamily?: string;
  sourceScopeId?: number;
  sourceFlowInfo?: number;
  sourceInterfaceIndex?: number;
  sourceProtocol?: number;
  sourceHardwareAddress?: Buffer;
  sourceHardwareType?: number;
  sourcePacketType?: number;
  packetAuxStatus?: number;
  packetAuxOriginalLength?: number;
  packetAuxSnapshotLength?: number;
  packetAuxMacOffset?: number;
  packetAuxNetworkOffset?: number;
  packetAuxVlanTci?: number;
  packetAuxVlanTpid?: number;
  dataLength: number;
  dataTruncated: boolean;
  controlTruncated: boolean;
  endOfRecord: boolean;
  outOfBand: boolean;
  errorQueue: boolean;
  control: NativeReceivedControlMessage[];
  ipv4?: NativeIpv4PacketMetadata;
}

interface NativeSubmitResult {
  accepted: boolean;
  error?: NativeErrorData;
}

interface NativeBatchSendMessage {
  data: Buffer;
  destination: string;
  destinationFamily: string;
  scopeId: number;
  flowInfo: number;
  packetProtocol: number;
  interfaceIndex: number;
  hardwareAddress: Buffer;
}

interface NativePacketRingConfig {
  blockSize: number;
  blockCount: number;
  frameSize: number;
  retireTimeoutMs: number;
}

type NativeHandle = object;

interface NativeBinding {
  nativeCancel(handle: NativeHandle, operationId: number): boolean;
  nativeBind(
    handle: NativeHandle,
    operationId: number,
    address: string,
  ): NativeSubmitResult;
  nativeBindIpv6(
    handle: NativeHandle,
    operationId: number,
    address: string,
    scopeId: number,
    flowInfo: number,
  ): NativeSubmitResult;
  nativeBindPacket(
    handle: NativeHandle,
    operationId: number,
    interfaceIndex: number,
    protocol: number,
  ): NativeSubmitResult;
  nativeConnectIpv6(
    handle: NativeHandle,
    operationId: number,
    address: string,
    scopeId: number,
    flowInfo: number,
  ): NativeSubmitResult;
  nativeConnectIpv4(
    handle: NativeHandle,
    operationId: number,
    address: string,
  ): NativeSubmitResult;
  nativeDisconnect(
    handle: NativeHandle,
    operationId: number,
  ): NativeSubmitResult;
  nativeClose(handle: NativeHandle, operationId: number): NativeSubmitResult;
  nativeGetOption(
    handle: NativeHandle,
    operationId: number,
    option: string,
  ): NativeSubmitResult;
  nativeGetIpv6Option(
    handle: NativeHandle,
    operationId: number,
    option: string,
  ): NativeSubmitResult;
  nativeGetBindToDevice(
    handle: NativeHandle,
    operationId: number,
  ): NativeSubmitResult;
  nativeSetBindToDevice(
    handle: NativeHandle,
    operationId: number,
    device?: string,
  ): NativeSubmitResult;
  nativeLocalAddress(
    handle: NativeHandle,
    operationId: number,
  ): NativeSubmitResult;
  nativeOpenRawSocket(
    family: string,
    mode: string | undefined,
    protocol: number,
    callback: (completion: NativeCompletion) => void,
  ): NativeHandle | NativeErrorData;
  nativeSmokeTest(): string;
  nativeSocketStatus(handle: NativeHandle): string;
  nativeSubmitReceive(
    handle: NativeHandle,
    operationId: number,
    bufferLength: number,
  ): NativeSubmitResult;
  nativeSubmitSend(
    handle: NativeHandle,
    operationId: number,
    data: Buffer,
    destination: string,
  ): NativeSubmitResult;
  nativeSubmitSendMessage(
    handle: NativeHandle,
    operationId: number,
    data: Buffer,
    destination: string,
    destinationFamily: string,
    scopeId: number,
    flowInfo: number,
    packetProtocol: number,
    interfaceIndex: number,
    hardwareAddress: Buffer,
    dontRoute: boolean,
    control: NativeSendControlMessage[],
  ): NativeSubmitResult;
  nativeInterfaceIndex(name: string): number | NativeErrorData;
  nativeInterfaceName(index: number): string | NativeErrorData;
  nativeSubmitReceiveMessage(
    handle: NativeHandle,
    operationId: number,
    bufferLength: number,
    controlCapacity: number,
    peek: boolean,
    errorQueue: boolean,
  ): NativeSubmitResult;
  nativeSubmitSendBatch(
    handle: NativeHandle,
    operationId: number,
    messages: NativeBatchSendMessage[],
  ): NativeSubmitResult;
  nativeSubmitReceiveBatch(
    handle: NativeHandle,
    operationId: number,
    count: number,
    bufferLength: number,
  ): NativeSubmitResult;
  nativeConfigurePacketRing(
    handle: NativeHandle,
    operationId: number,
    config: NativePacketRingConfig,
  ): NativeSubmitResult;
  nativeReceiveRingFrame(
    handle: NativeHandle,
    operationId: number,
  ): NativeSubmitResult;
  nativeSetOption(
    handle: NativeHandle,
    operationId: number,
    option: string,
    value: number,
  ): NativeSubmitResult;
  nativeSetIpv6Option(
    handle: NativeHandle,
    operationId: number,
    option: string,
    value: number,
  ): NativeSubmitResult;
  nativeGetRawOption(
    handle: NativeHandle,
    operationId: number,
    level: number,
    name: number,
    maximum: number,
  ): NativeSubmitResult;
  nativeSetRawOption(
    handle: NativeHandle,
    operationId: number,
    level: number,
    name: number,
    value: Buffer,
  ): NativeSubmitResult;
  nativeAttachClassicFilter(
    handle: NativeHandle,
    operationId: number,
    program: ClassicBpfInstruction[],
  ): NativeSubmitResult;
  nativeAttachEbpfFilter(
    handle: NativeHandle,
    operationId: number,
    fd: number,
  ): NativeSubmitResult;
  nativeDetachFilter(
    handle: NativeHandle,
    operationId: number,
  ): NativeSubmitResult;
  nativeLockFilter(
    handle: NativeHandle,
    operationId: number,
  ): NativeSubmitResult;
  nativePacketMembership(
    handle: NativeHandle,
    operationId: number,
    interfaceIndex: number,
    kind: string,
    address: Buffer,
    add: boolean,
  ): NativeSubmitResult;
  nativePacketAuxdata(
    handle: NativeHandle,
    operationId: number,
    enabled: boolean,
  ): NativeSubmitResult;
  nativePacketFanout(
    handle: NativeHandle,
    operationId: number,
    group: number,
    mode: number,
  ): NativeSubmitResult;
  nativePacketStatistics(
    handle: NativeHandle,
    operationId: number,
  ): NativeSubmitResult;
}

interface PendingOperation {
  resolve(completion: NativeCompletion): void;
  reject(error: RawSocketError): void;
  finalizers?: InternalFinalizers;
}

type ReceiveLane = "normal" | "errorQueue";

interface SocketCloseObserver {
  closing(): void;
  closed(error: unknown, rejected: boolean): void;
}

interface SocketState {
  readonly pending: Map<number, PendingOperation>;
  readonly directReceives: Record<ReceiveLane, number>;
  readonly eventClaims: Map<ReceiveLane, symbol>;
  readonly ringConfigurations: Set<symbol>;
  readonly closeObservers: Set<SocketCloseObserver>;
  ringFrameReceives: number;
  ringActive: boolean;
}

interface ClaimedReceiveOptions {
  readonly dataCapacity: number;
  readonly controlCapacity: number;
  readonly errorQueue: boolean;
}

interface SocketInternals {
  readonly state: SocketState;
  readonly isOpen: () => boolean;
  readonly receiveClaimed: (
    claim: symbol,
    options: ClaimedReceiveOptions,
    signal: AbortSignal,
  ) => Promise<ReceivedMessage>;
}

const socketInternals = new WeakMap<RawSocket, SocketInternals>();

const require = createRequire(import.meta.url);
const nativeBinding = require("../build/native/binding.cjs") as NativeBinding;

/** A stable error raised by the public raw-socket API. */
export class RawSocketError extends Error {
  override readonly name = "RawSocketError";
  readonly kind: RawSocketErrorKind;
  readonly code: string;
  readonly operation: string;
  readonly errno: number | undefined;
  readonly errnoName: string | undefined;

  constructor(data: NativeErrorData) {
    super(`${data.operation} failed: ${data.message}`);
    this.kind = normalizeErrorKind(data.kind);
    this.code = data.code;
    this.operation = data.operation;
    this.errno = data.errno;
    this.errnoName = data.errnoName;
  }
}

/** An owned Linux IPv4, IPv6, or packet socket. */
export class RawSocket {
  readonly #handle: NativeHandle;
  readonly #state: SocketState;
  readonly #family: RawSocketFamily;
  readonly #mode: PacketSocketMode | undefined;
  #nextOperationId = 1;
  #closed = false;
  #closePromise: Promise<void> | undefined;

  private constructor(
    handle: NativeHandle,
    state: SocketState,
    family: RawSocketFamily,
    mode: PacketSocketMode | undefined,
  ) {
    this.#handle = handle;
    this.#state = state;
    this.#family = family;
    this.#mode = mode;
  }

  /**
   * Creates a nonblocking `AF_INET` or `AF_INET6` `SOCK_RAW` socket.
   *
   * Linux normally requires `CAP_NET_RAW` in the governing user namespace.
   */
  static open(options: RawSocketOptions): Promise<RawSocket> {
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      try {
        validateProtocol(options);
      } catch (error) {
        reject(normalizeUnknownError(error, "createRawSocket"));
        return;
      }

      const state = createSocketState();
      let socket: RawSocket | undefined;
      state.pending.set(OPEN_OPERATION_ID, {
        resolve: () => {
          if (socket === undefined) {
            reject(
              internalError(
                "registerSocket",
                "native open completed without a handle",
              ),
            );
          } else {
            const openedSocket = socket;
            socketInternals.set(openedSocket, {
              state,
              isOpen: () => !openedSocket.#closed,
              receiveClaimed: (claim, options, signal) =>
                openedSocket.#receiveMessageClaimed(claim, options, signal),
            });
            resolve(openedSocket);
          }
        },
        reject,
      });

      try {
        const family = options.family ?? "ipv4";
        const result = nativeBinding.nativeOpenRawSocket(
          family,
          options.mode,
          options.protocol,
          (completion) => {
            dispatchCompletion(state, completion);
          },
        );
        if (isNativeErrorData(result)) {
          state.pending.delete(OPEN_OPERATION_ID);
          reject(new RawSocketError(result));
          return;
        }
        socket = new RawSocket(result, state, family, options.mode);
      } catch (error) {
        state.pending.delete(OPEN_OPERATION_ID);
        reject(normalizeUnknownError(error, "createRawSocket"));
      }
    });
  }

  /** Current native lifecycle state. */
  get status(): RawSocketStatus {
    const status = nativeBinding.nativeSocketStatus(this.#handle);
    return isRawSocketStatus(status) ? status : "closed";
  }

  get family(): RawSocketFamily {
    return this.#family;
  }

  get packetMode(): PacketSocketMode | undefined {
    return this.#mode;
  }

  /** Binds the socket to a local dotted-decimal IPv4 address. */
  bind(address: string | IpMessageAddress): Promise<void> {
    if (this.#closed) {
      return Promise.reject(socketClosedError("bind"));
    }
    try {
      if (this.#family === "ipv4") {
        const value =
          typeof address === "string"
            ? address
            : address.family === "ipv4"
              ? address.address
              : undefined;
        validateIpv4Address(value, "bind", "address");
      } else if (this.#family === "ipv6") {
        validateIpv6MessageAddress(address, "bind");
      } else {
        validatePacketMessageAddress(address, "bind", false);
      }
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "bind"));
    }

    return this.#submitVoid("bind", (operationId) => {
      if (this.#family === "ipv4") {
        const value =
          typeof address === "string"
            ? address
            : (address as Ipv4MessageAddress).address;
        return nativeBinding.nativeBind(this.#handle, operationId, value);
      }
      if (this.#family === "ipv6") {
        const value = address as Ipv6MessageAddress;
        return nativeBinding.nativeBindIpv6(
          this.#handle,
          operationId,
          value.address,
          value.scopeId ?? 0,
          value.flowInfo ?? 0,
        );
      }
      const value = address as PacketMessageAddress;
      return nativeBinding.nativeBindPacket(
        this.#handle,
        operationId,
        value.interfaceIndex,
        value.protocol,
      );
    });
  }

  /** Returns the currently bound local IPv4 address (`0.0.0.0` if unbound). */
  localAddress(): Promise<string> {
    if (this.#closed) {
      return Promise.reject(socketClosedError("localAddress"));
    }
    if (this.#family !== "ipv4")
      return Promise.reject(
        unsupportedError(
          "localAddress",
          this.#family === "ipv6"
            ? "use localMessageAddress() for IPv6"
            : "packet sockets use bound link addresses",
        ),
      );
    const operationId = this.#allocateOperationId();
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      this.#state.pending.set(operationId, {
        resolve: (completion) => {
          if (completion.localAddress === undefined) {
            reject(
              internalError(
                "localAddress",
                "native completion omitted local address",
              ),
            );
          } else {
            resolve(completion.localAddress);
          }
        },
        reject,
      });
      const result = callNative(
        () => nativeBinding.nativeLocalAddress(this.#handle, operationId),
        "localAddress",
      );
      this.#settleRejectedSubmission(operationId, result, reject);
    });
  }

  localMessageAddress(): Promise<IpMessageAddress> {
    if (this.#closed) return Promise.reject(socketClosedError("localAddress"));
    if (this.#family === "packet")
      return Promise.reject(
        unsupportedError(
          "localAddress",
          "packet sockets use the address supplied to bind()",
        ),
      );
    const operationId = this.#allocateOperationId();
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      this.#state.pending.set(operationId, {
        resolve: (completion) => {
          if (
            completion.localAddress === undefined ||
            completion.localFamily === undefined
          ) {
            reject(
              internalError(
                "localAddress",
                "native completion omitted address fields",
              ),
            );
            return;
          }
          resolve(
            completion.localFamily === "ipv6"
              ? {
                  family: "ipv6",
                  address: completion.localAddress,
                  scopeId: completion.localScopeId ?? 0,
                  flowInfo: completion.localFlowInfo ?? 0,
                }
              : { family: "ipv4", address: completion.localAddress },
          );
        },
        reject,
      });
      const result = callNative(
        () => nativeBinding.nativeLocalAddress(this.#handle, operationId),
        "localAddress",
      );
      this.#settleRejectedSubmission(operationId, result, reject);
    });
  }

  connect(address: Ipv4MessageAddress | Ipv6MessageAddress): Promise<void> {
    if (this.#closed) return Promise.reject(socketClosedError("connect"));
    try {
      if (this.#family === "packet")
        throw unsupportedError(
          "connect",
          "packet sockets use per-message link destinations",
        );
      if (this.#family === "ipv6")
        validateIpv6MessageAddress(address, "connect");
      else {
        if (address.family !== "ipv4")
          throw invalidArgument(
            "connect",
            "address family must match socket family",
          );
        validateIpv4Address(address.address, "connect", "address");
      }
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "connect"));
    }
    return this.#submitVoid("connect", (operationId) =>
      address.family === "ipv4"
        ? nativeBinding.nativeConnectIpv4(
            this.#handle,
            operationId,
            address.address,
          )
        : nativeBinding.nativeConnectIpv6(
            this.#handle,
            operationId,
            address.address,
            address.scopeId ?? 0,
            address.flowInfo ?? 0,
          ),
    );
  }

  disconnect(): Promise<void> {
    if (this.#closed) return Promise.reject(socketClosedError("disconnect"));
    if (this.#family === "packet")
      return Promise.reject(
        unsupportedError(
          "disconnect",
          "packet sockets use per-message link destinations",
        ),
      );
    return this.#submitVoid("disconnect", (operationId) =>
      nativeBinding.nativeDisconnect(this.#handle, operationId),
    );
  }

  /** Reads one supported typed Linux socket option. */
  getOption<Name extends RawSocketOptionName>(
    name: Name,
  ): Promise<RawSocketOptionMap[Name]> {
    if (this.#closed) {
      return Promise.reject(socketClosedError("getOption"));
    }
    try {
      validateOptionName(name, "getOption");
      validateOptionFamily(name, this.#family, "getOption");
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "getOption"));
    }

    const operationId = this.#allocateOperationId();
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      this.#state.pending.set(operationId, {
        resolve: (completion) => {
          if (name === "bindToDevice") {
            resolve(
              (completion.deviceValue ?? null) as RawSocketOptionMap[Name],
            );
            return;
          }
          if (completion.optionValue === undefined) {
            reject(
              internalError("getOption", "native completion omitted value"),
            );
          } else {
            resolve(
              (isBooleanOption(name)
                ? completion.optionValue !== 0
                : completion.optionValue) as RawSocketOptionMap[Name],
            );
          }
        },
        reject,
      });
      const result = callNative(
        () =>
          name === "bindToDevice"
            ? nativeBinding.nativeGetBindToDevice(this.#handle, operationId)
            : this.#family === "ipv6"
              ? nativeBinding.nativeGetIpv6Option(
                  this.#handle,
                  operationId,
                  name,
                )
              : nativeBinding.nativeGetOption(this.#handle, operationId, name),
        "getOption",
      );
      this.#settleRejectedSubmission(operationId, result, reject);
    });
  }

  /** Sets one supported typed Linux socket option. */
  setOption<Name extends RawSocketOptionName>(
    name: Name,
    value: RawSocketOptionMap[Name],
  ): Promise<void> {
    if (this.#closed) {
      return Promise.reject(socketClosedError("setOption"));
    }
    let encodedValue: number | undefined;
    try {
      validateOptionFamily(name, this.#family, "setOption");
      encodedValue = validateOptionValue(name, value);
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "setOption"));
    }

    return this.#submitVoid("setOption", (operationId) => {
      if (name === "bindToDevice") {
        return nativeBinding.nativeSetBindToDevice(
          this.#handle,
          operationId,
          value === null ? undefined : String(value),
        );
      }
      if (encodedValue === undefined) {
        return {
          accepted: false,
          error: errorDataFromUnknown(
            "missing encoded option value",
            "setOption",
          ),
        };
      }
      return this.#family === "ipv6"
        ? nativeBinding.nativeSetIpv6Option(
            this.#handle,
            operationId,
            name,
            encodedValue,
          )
        : nativeBinding.nativeSetOption(
            this.#handle,
            operationId,
            name,
            encodedValue,
          );
    });
  }

  getSocketOption(
    level: number,
    name: number,
    maximumLength = 256,
  ): Promise<Buffer> {
    if (this.#closed) return Promise.reject(socketClosedError("getOption"));
    try {
      validateRawOptionNumbers(level, name, maximumLength, "getOption");
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "getOption"));
    }
    const operationId = this.#allocateOperationId();
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      this.#state.pending.set(operationId, {
        resolve: (completion) => {
          if (completion.rawOption === undefined) {
            reject(
              internalError(
                "getOption",
                "native completion omitted raw option bytes",
              ),
            );
          } else {
            resolve(completion.rawOption);
          }
        },
        reject,
      });
      const result = callNative(
        () =>
          nativeBinding.nativeGetRawOption(
            this.#handle,
            operationId,
            level,
            name,
            maximumLength,
          ),
        "getOption",
      );
      this.#settleRejectedSubmission(operationId, result, reject);
    });
  }

  setSocketOption(
    level: number,
    name: number,
    value: Uint8Array,
  ): Promise<void> {
    if (this.#closed) return Promise.reject(socketClosedError("setOption"));
    try {
      if (!(value instanceof Uint8Array))
        throw invalidArgument("setOption", "value must be Uint8Array");
      validateRawOptionNumbers(
        level,
        name,
        value.byteLength,
        "setOption",
        true,
      );
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "setOption"));
    }
    return this.#submitVoid("setOption", (operationId) =>
      nativeBinding.nativeSetRawOption(
        this.#handle,
        operationId,
        level,
        name,
        Buffer.from(value),
      ),
    );
  }

  attachClassicFilter(
    program: readonly ClassicBpfInstruction[],
  ): Promise<void> {
    if (this.#closed) return Promise.reject(socketClosedError("attachFilter"));
    try {
      validateClassicFilter(program);
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "attachFilter"));
    }
    return this.#submitVoid("attachFilter", (operationId) =>
      nativeBinding.nativeAttachClassicFilter(
        this.#handle,
        operationId,
        program.map((instruction) => ({ ...instruction })),
      ),
    );
  }
  attachEbpfFilter(fd: number): Promise<void> {
    if (this.#closed) return Promise.reject(socketClosedError("attachFilter"));
    try {
      validateIntegerRange(fd, 0, 0x7fff_ffff, "attachFilter", "fd");
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "attachFilter"));
    }
    return this.#submitVoid("attachFilter", (operationId) =>
      nativeBinding.nativeAttachEbpfFilter(this.#handle, operationId, fd),
    );
  }
  detachFilter(): Promise<void> {
    return this.#closed
      ? Promise.reject(socketClosedError("attachFilter"))
      : this.#submitVoid("attachFilter", (id) =>
          nativeBinding.nativeDetachFilter(this.#handle, id),
        );
  }
  lockFilter(): Promise<void> {
    return this.#closed
      ? Promise.reject(socketClosedError("attachFilter"))
      : this.#submitVoid("attachFilter", (id) =>
          nativeBinding.nativeLockFilter(this.#handle, id),
        );
  }

  addPacketMembership(membership: PacketMembership): Promise<void> {
    return this.#packetMembership(membership, true);
  }
  dropPacketMembership(membership: PacketMembership): Promise<void> {
    return this.#packetMembership(membership, false);
  }
  setPacketAuxdata(enabled: boolean): Promise<void> {
    if (this.#closed) return Promise.reject(socketClosedError("setOption"));
    if (this.#family !== "packet")
      return Promise.reject(
        invalidArgument("setOption", "packet auxdata requires a packet socket"),
      );
    if (typeof enabled !== "boolean")
      return Promise.reject(
        invalidArgument("setOption", "enabled must be boolean"),
      );
    return this.#submitVoid("setOption", (id) =>
      nativeBinding.nativePacketAuxdata(this.#handle, id, enabled),
    );
  }
  setPacketFanout(group: number, mode: PacketFanoutMode): Promise<void> {
    if (this.#closed) return Promise.reject(socketClosedError("setOption"));
    try {
      if (this.#family !== "packet")
        throw invalidArgument(
          "setOption",
          "packet fanout requires a packet socket",
        );
      validateIntegerRange(group, 0, 0xffff, "setOption", "group");
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "setOption"));
    }
    const modes: Record<PacketFanoutMode, number> = {
      hash: 0,
      loadBalance: 1,
      cpu: 2,
      rollover: 3,
      random: 4,
      queueMapping: 5,
      classicBpf: 6,
      ebpf: 7,
    };
    if (!(mode in modes))
      return Promise.reject(
        invalidArgument("setOption", "unsupported packet fanout mode"),
      );
    return this.#submitVoid("setOption", (id) =>
      nativeBinding.nativePacketFanout(this.#handle, id, group, modes[mode]),
    );
  }
  packetStatistics(): Promise<PacketStatistics> {
    if (this.#closed)
      return Promise.reject(socketClosedError("packetStatistics"));
    if (this.#family !== "packet")
      return Promise.reject(
        invalidArgument(
          "packetStatistics",
          "statistics require a packet socket",
        ),
      );
    const operationId = this.#allocateOperationId();
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      this.#state.pending.set(operationId, {
        resolve: (completion) => {
          if (
            completion.statisticsPackets === undefined ||
            completion.statisticsDrops === undefined
          ) {
            reject(
              internalError(
                "packetStatistics",
                "native completion omitted statistics",
              ),
            );
          } else {
            resolve({
              packets: completion.statisticsPackets,
              drops: completion.statisticsDrops,
            });
          }
        },
        reject,
      });
      const result = callNative(
        () => nativeBinding.nativePacketStatistics(this.#handle, operationId),
        "packetStatistics",
      );
      this.#settleRejectedSubmission(operationId, result, reject);
    });
  }

  #packetMembership(membership: PacketMembership, add: boolean): Promise<void> {
    if (this.#closed)
      return Promise.reject(socketClosedError("packetMembership"));
    try {
      validatePacketMembership(membership, this.#family);
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "packetMembership"));
    }
    return this.#submitVoid("packetMembership", (id) =>
      nativeBinding.nativePacketMembership(
        this.#handle,
        id,
        membership.interfaceIndex,
        membership.kind,
        Buffer.from(membership.address ?? new Uint8Array()),
        add,
      ),
    );
  }

  /**
   * Sends one owned copy of `data` to a dotted-decimal IPv4 address.
   *
   * Linux constructs the IPv4 header unless header-included mode is added by a
   * later API phase.
   */
  send(
    data: Uint8Array,
    destination: string,
    options: AbortableOperationOptions = {},
  ): Promise<number> {
    if (this.#closed) {
      return Promise.reject(socketClosedError("send"));
    }
    if (this.#family !== "ipv4")
      return Promise.reject(
        unsupportedError("send", "use sendMessage() for IPv6"),
      );
    try {
      validatePacketData(data);
      validateDestination(destination);
      validateSignal(options.signal, "send");
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "send"));
    }

    const operationId = this.#allocateOperationId();
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      this.#state.pending.set(operationId, {
        resolve: (completion) => {
          if (completion.bytesSent === undefined) {
            reject(
              internalError(
                "send",
                "native send completion omitted byte count",
              ),
            );
          } else {
            resolve(completion.bytesSent);
          }
        },
        reject,
      });
      if (this.#attachAbort(operationId, options.signal, reject, "send"))
        return;
      const result = callNative(
        () =>
          nativeBinding.nativeSubmitSend(
            this.#handle,
            operationId,
            Buffer.from(data),
            destination,
          ),
        "send",
      );
      this.#settleRejectedSubmission(operationId, result, reject);
    });
  }

  /** Sends one IP message using Linux `sendmsg(2)` flags and control data. */
  sendMessage(request: SendMessageRequest): Promise<number> {
    if (this.#closed) return Promise.reject(socketClosedError("sendMessage"));
    try {
      validateSendMessageRequest(request, this.#family);
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "sendMessage"));
    }
    const operationId = this.#allocateOperationId();
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      this.#state.pending.set(operationId, {
        resolve: (completion) => {
          if (completion.bytesSent === undefined) {
            reject(
              internalError(
                "sendMessage",
                "native completion omitted byte count",
              ),
            );
          } else {
            resolve(completion.bytesSent);
          }
        },
        reject,
      });
      if (this.#attachAbort(operationId, request.signal, reject, "sendMessage"))
        return;
      const controls: NativeSendControlMessage[] = (request.control ?? []).map(
        (control) =>
          control.kind === "ipv4PacketInfo" || control.kind === "ipv6PacketInfo"
            ? {
                kind: control.kind,
                ...(control.interfaceIndex === undefined
                  ? {}
                  : { interfaceIndex: control.interfaceIndex }),
                ...(control.sourceAddress === undefined
                  ? {}
                  : { sourceAddress: control.sourceAddress }),
              }
            : { kind: control.kind, value: control.value },
      );
      const result = callNative(
        () =>
          nativeBinding.nativeSubmitSendMessage(
            this.#handle,
            operationId,
            Buffer.from(request.data),
            request.destination.family === "packet"
              ? ""
              : request.destination.address,
            request.destination.family,
            request.destination.family === "ipv6"
              ? (request.destination.scopeId ?? 0)
              : 0,
            request.destination.family === "ipv6"
              ? (request.destination.flowInfo ?? 0)
              : 0,
            request.destination.family === "packet"
              ? request.destination.protocol
              : 0,
            request.destination.family === "packet"
              ? request.destination.interfaceIndex
              : 0,
            Buffer.from(
              request.destination.family === "packet"
                ? (request.destination.address ?? new Uint8Array())
                : new Uint8Array(),
            ),
            request.flags?.includes("dontRoute") ?? false,
            controls,
          ),
        "sendMessage",
      );
      this.#settleRejectedSubmission(operationId, result, reject);
    });
  }

  /** Sends a bounded same-family vector with one nonblocking `sendmmsg(2)`. */
  sendBatch(
    requests: readonly BatchSendRequest[],
    options: AbortableOperationOptions = {},
  ): Promise<SendBatchResult> {
    if (this.#closed) return Promise.reject(socketClosedError("sendBatch"));
    try {
      validateSendBatch(requests, this.#family);
      validateSignal(options.signal, "sendBatch");
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "sendBatch"));
    }
    const operationId = this.#allocateOperationId();
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      this.#state.pending.set(operationId, {
        resolve: (completion) => {
          if (
            completion.batchLengths === undefined ||
            completion.batchRequested === undefined
          ) {
            reject(
              internalError(
                "sendBatch",
                "native completion omitted batch results",
              ),
            );
            return;
          }
          resolve({
            requested: completion.batchRequested,
            completed: completion.batchLengths.length,
            results: completion.batchLengths.map((bytesSent, index) => ({
              index,
              bytesSent,
            })),
          });
        },
        reject,
      });
      if (this.#attachAbort(operationId, options.signal, reject, "sendBatch"))
        return;
      const messages: NativeBatchSendMessage[] = requests.map((request) => ({
        data: Buffer.from(request.data),
        destination:
          request.destination.family === "packet"
            ? ""
            : request.destination.address,
        destinationFamily: request.destination.family,
        scopeId:
          request.destination.family === "ipv6"
            ? (request.destination.scopeId ?? 0)
            : 0,
        flowInfo:
          request.destination.family === "ipv6"
            ? (request.destination.flowInfo ?? 0)
            : 0,
        packetProtocol:
          request.destination.family === "packet"
            ? request.destination.protocol
            : 0,
        interfaceIndex:
          request.destination.family === "packet"
            ? request.destination.interfaceIndex
            : 0,
        hardwareAddress: Buffer.from(
          request.destination.family === "packet"
            ? (request.destination.address ?? new Uint8Array())
            : new Uint8Array(),
        ),
      }));
      const result = callNative(
        () =>
          nativeBinding.nativeSubmitSendBatch(
            this.#handle,
            operationId,
            messages,
          ),
        "sendBatch",
      );
      this.#settleRejectedSubmission(operationId, result, reject);
    });
  }

  /** Receives one IPv4 packet, waiting off the Node.js event-loop thread. */
  receive(
    maxLength = MAX_PACKET_LENGTH,
    options: AbortableOperationOptions = {},
  ): Promise<ReceivedPacket> {
    if (this.#closed) {
      return Promise.reject(socketClosedError("receive"));
    }
    if (this.#family !== "ipv4")
      return Promise.reject(
        unsupportedError("receive", "use receiveMessage() for IPv6"),
      );
    try {
      validatePacketLength(maxLength, "maxLength");
      validateSignal(options.signal, "receive");
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "receive"));
    }

    if (this.#state.eventClaims.has("normal")) {
      return Promise.reject(
        receiverActive(
          "receive",
          "the normal receive lane is owned by an event source",
        ),
      );
    }

    const operationId = this.#allocateOperationId();
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      this.#state.pending.set(operationId, {
        resolve: (completion) => {
          if (
            completion.data === undefined ||
            completion.sourceAddress === undefined ||
            completion.packetLength === undefined ||
            completion.truncated === undefined
          ) {
            reject(
              internalError(
                "receive",
                "native receive completion was incomplete",
              ),
            );
          } else {
            resolve({
              data: completion.data,
              sourceAddress: completion.sourceAddress,
              packetLength: completion.packetLength,
              truncated: completion.truncated,
              ipv4: completion.ipv4,
            });
          }
        },
        reject,
      });
      this.#trackDirectReceive(operationId, "normal");
      if (this.#attachAbort(operationId, options.signal, reject, "receive"))
        return;
      const result = callNative(
        () =>
          nativeBinding.nativeSubmitReceive(
            this.#handle,
            operationId,
            maxLength,
          ),
        "receive",
      );
      this.#settleRejectedSubmission(operationId, result, reject);
    });
  }

  /** Receives one IPv4 message and its typed Linux ancillary metadata. */
  receiveMessage(
    options: ReceiveMessageOptions = {},
  ): Promise<ReceivedMessage> {
    return this.#receiveMessageInternal(options);
  }

  #receiveMessageClaimed(
    claim: symbol,
    options: ClaimedReceiveOptions,
    signal: AbortSignal,
  ): Promise<ReceivedMessage> {
    return this.#receiveMessageInternal(
      {
        dataCapacity: options.dataCapacity,
        controlCapacity: options.controlCapacity,
        flags: options.errorQueue ? ["errorQueue"] : [],
        signal,
      },
      claim,
    );
  }

  #receiveMessageInternal(
    options: ReceiveMessageOptions,
    eventClaim?: symbol,
  ): Promise<ReceivedMessage> {
    if (this.#closed)
      return Promise.reject(socketClosedError("receiveMessage"));
    try {
      validateReceiveMessageOptions(options);
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "receiveMessage"));
    }
    const flags = options.flags ?? [];
    const lane: ReceiveLane = flags.includes("errorQueue")
      ? "errorQueue"
      : "normal";
    if (eventClaim === undefined) {
      if (this.#state.eventClaims.has(lane)) {
        return Promise.reject(
          receiverActive(
            "receiveMessage",
            `the ${lane} receive lane is owned by an event source`,
          ),
        );
      }
    } else if (this.#state.eventClaims.get(lane) !== eventClaim) {
      return Promise.reject(
        receiverActive(
          "receiveMessage",
          `the ${lane} event receive claim is no longer active`,
        ),
      );
    }
    const operationId = this.#allocateOperationId();
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      this.#state.pending.set(operationId, {
        resolve: (completion) => {
          try {
            if (completion.message === undefined)
              throw internalError(
                "receiveMessage",
                "native completion omitted message",
              );
            resolve(convertReceivedMessage(completion.message));
          } catch (error) {
            reject(normalizeUnknownError(error, "receiveMessage"));
          }
        },
        reject,
      });
      if (eventClaim === undefined) {
        this.#trackDirectReceive(operationId, lane);
      }
      if (
        this.#attachAbort(operationId, options.signal, reject, "receiveMessage")
      )
        return;
      const result = callNative(
        () =>
          nativeBinding.nativeSubmitReceiveMessage(
            this.#handle,
            operationId,
            options.dataCapacity ?? MAX_PACKET_LENGTH,
            options.controlCapacity ?? DEFAULT_CONTROL_CAPACITY,
            flags.includes("peek"),
            flags.includes("errorQueue"),
          ),
        "receiveMessage",
      );
      this.#settleRejectedSubmission(operationId, result, reject);
    });
  }

  /** Receives one productive bounded `recvmmsg(2)` vector. */
  receiveBatch(options: ReceiveBatchOptions): Promise<ReceiveBatchResult> {
    if (this.#closed) return Promise.reject(socketClosedError("receiveBatch"));
    try {
      validateReceiveBatchOptions(options);
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "receiveBatch"));
    }
    if (this.#state.eventClaims.has("normal")) {
      return Promise.reject(
        receiverActive(
          "receiveBatch",
          "the normal receive lane is owned by an event source",
        ),
      );
    }
    const operationId = this.#allocateOperationId();
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      this.#state.pending.set(operationId, {
        resolve: (completion) => {
          try {
            if (completion.batchMessages === undefined)
              throw internalError(
                "receiveBatch",
                "native completion omitted batch messages",
              );
            const messages = completion.batchMessages.map(
              convertReceivedMessage,
            );
            resolve({ completed: messages.length, messages });
          } catch (error) {
            reject(normalizeUnknownError(error, "receiveBatch"));
          }
        },
        reject,
      });
      this.#trackDirectReceive(operationId, "normal");
      if (
        this.#attachAbort(operationId, options.signal, reject, "receiveBatch")
      )
        return;
      const result = callNative(
        () =>
          nativeBinding.nativeSubmitReceiveBatch(
            this.#handle,
            operationId,
            options.count,
            options.dataCapacity ?? MAX_PACKET_LENGTH,
          ),
        "receiveBatch",
      );
      this.#settleRejectedSubmission(operationId, result, reject);
    });
  }

  /** Configures one bounded receive-only TPACKET_V3 ring. */
  configurePacketRing(config: PacketRingConfig = {}): Promise<void> {
    if (this.#closed)
      return Promise.reject(socketClosedError("configurePacketRing"));
    let nativeConfig: NativePacketRingConfig;
    try {
      nativeConfig = validatePacketRingConfig(config, this.#family);
    } catch (error) {
      return Promise.reject(
        normalizeUnknownError(error, "configurePacketRing"),
      );
    }
    if (this.#state.eventClaims.size > 0) {
      return Promise.reject(
        receiverActive(
          "configurePacketRing",
          "packet-ring mode conflicts with attached event sources",
        ),
      );
    }
    const token = Symbol("packetRingConfiguration");
    this.#state.ringConfigurations.add(token);
    const operationId = this.#allocateOperationId();
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      this.#state.pending.set(operationId, {
        resolve: () => {
          this.#state.ringActive = true;
          resolve();
        },
        reject,
      });
      addPendingFinalizer(this.#state, operationId, () => {
        this.#state.ringConfigurations.delete(token);
      });
      const result = callNative(
        () =>
          nativeBinding.nativeConfigurePacketRing(
            this.#handle,
            operationId,
            nativeConfig,
          ),
        "configurePacketRing",
      );
      this.#settleRejectedSubmission(operationId, result, reject);
    });
  }

  /** Waits for and leases one copied frame from the configured packet ring. */
  receiveRingFrame(
    options: AbortableOperationOptions = {},
  ): Promise<PacketRingFrameLease> {
    if (this.#closed)
      return Promise.reject(socketClosedError("receiveRingFrame"));
    try {
      if (this.#family !== "packet")
        throw invalidArgument(
          "receiveRingFrame",
          "packet ring frames require a packet socket",
        );
      validateSignal(options.signal, "receiveRingFrame");
    } catch (error) {
      return Promise.reject(normalizeUnknownError(error, "receiveRingFrame"));
    }
    if (this.#state.eventClaims.size > 0) {
      return Promise.reject(
        receiverActive(
          "receiveRingFrame",
          "packet-ring receives conflict with attached event sources",
        ),
      );
    }
    const operationId = this.#allocateOperationId();
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      this.#state.pending.set(operationId, {
        resolve: (completion) => {
          if (
            completion.ringData === undefined ||
            completion.ringOriginalLength === undefined ||
            completion.ringSnapshotLength === undefined ||
            completion.ringSeconds === undefined ||
            completion.ringNanoseconds === undefined ||
            completion.ringStatus === undefined ||
            completion.ringVlanTci === undefined ||
            completion.ringVlanTpid === undefined
          ) {
            reject(
              internalError(
                "receiveRingFrame",
                "native completion omitted ring frame fields",
              ),
            );
            return;
          }
          resolve(
            new PacketRingFrameLease(
              completion.ringData,
              completion.ringOriginalLength,
              completion.ringSnapshotLength,
              completion.ringSeconds,
              completion.ringNanoseconds,
              completion.ringStatus,
              completion.ringVlanTci,
              completion.ringVlanTpid,
            ),
          );
        },
        reject,
      });
      this.#state.ringFrameReceives += 1;
      addPendingFinalizer(this.#state, operationId, () => {
        this.#state.ringFrameReceives -= 1;
      });
      if (
        this.#attachAbort(
          operationId,
          options.signal,
          reject,
          "receiveRingFrame",
        )
      )
        return;
      const result = callNative(
        () => nativeBinding.nativeReceiveRingFrame(this.#handle, operationId),
        "receiveRingFrame",
      );
      this.#settleRejectedSubmission(operationId, result, reject);
    });
  }

  /**
   * Idempotently closes the socket and cancels pending sends/receives.
   *
   * The Promise resolves after reactor deregistration and descriptor release.
   */
  close(): Promise<void> {
    if (this.#closePromise !== undefined) {
      return this.#closePromise;
    }
    this.#closed = true;
    const operationId = this.#allocateOperationId();
    let resolveClose!: () => void;
    let rejectClose!: (error: RawSocketError) => void;
    this.#closePromise = new Promise<void>((resolve, reject) => {
      resolveClose = resolve;
      rejectClose = reject;
    });
    void this.#closePromise.then(
      () => {
        this.#notifyCloseOutcome(undefined, false);
      },
      (error: unknown) => {
        this.#notifyCloseOutcome(error, true);
      },
    );
    this.#notifyClosing();
    this.#state.pending.set(operationId, {
      resolve: () => {
        resolveClose();
      },
      reject: rejectClose,
    });
    const result = callNative(
      () => nativeBinding.nativeClose(this.#handle, operationId),
      "close",
    );
    if (!result.accepted && result.error === undefined) {
      takePendingOperation(this.#state, operationId);
      resolveClose();
      return this.#closePromise;
    }
    this.#settleRejectedSubmission(operationId, result, rejectClose);
    return this.#closePromise;
  }

  #notifyClosing(): void {
    for (const observer of [...this.#state.closeObservers]) {
      try {
        observer.closing();
      } catch {
        // Lifecycle observers are internal and isolated from RawSocket.close().
      }
    }
  }

  #notifyCloseOutcome(error: unknown, rejected: boolean): void {
    for (const observer of [...this.#state.closeObservers]) {
      try {
        observer.closed(error, rejected);
      } catch {
        // One adapter cannot prevent sibling close settlement.
      }
    }
  }

  #submitVoid(
    operation: string,
    submit: (operationId: number) => NativeSubmitResult,
  ): Promise<void> {
    const operationId = this.#allocateOperationId();
    return new Promise((resolve, reject: (error: RawSocketError) => void) => {
      this.#state.pending.set(operationId, {
        resolve: () => {
          resolve();
        },
        reject,
      });
      const result = callNative(() => submit(operationId), operation);
      this.#settleRejectedSubmission(operationId, result, reject);
    });
  }

  #allocateOperationId(): number {
    for (;;) {
      const candidate = this.#nextOperationId;
      this.#nextOperationId =
        candidate === MAX_OPERATION_ID ? 1 : candidate + 1;
      if (!this.#state.pending.has(candidate)) {
        return candidate;
      }
    }
  }

  #trackDirectReceive(operationId: number, lane: ReceiveLane): void {
    this.#state.directReceives[lane] += 1;
    addPendingFinalizer(this.#state, operationId, () => {
      this.#state.directReceives[lane] -= 1;
    });
  }

  #settleRejectedSubmission(
    operationId: number,
    result: NativeSubmitResult,
    reject: (error: RawSocketError) => void,
  ): void {
    if (result.accepted) {
      return;
    }
    takePendingOperation(this.#state, operationId);
    reject(
      result.error === undefined
        ? internalError("submitOperation", "native operation was not accepted")
        : new RawSocketError(result.error),
    );
  }

  #attachAbort(
    operationId: number,
    signal: AbortSignal | undefined,
    reject: (error: RawSocketError) => void,
    operation: string,
  ): boolean {
    if (signal === undefined) return false;
    const abort = (): void => {
      try {
        nativeBinding.nativeCancel(this.#handle, operationId);
      } catch (error) {
        const pending = takePendingOperation(this.#state, operationId);
        pending?.reject(normalizeUnknownError(error, operation));
      }
    };
    try {
      if (signal.aborted) {
        takePendingOperation(this.#state, operationId);
        reject(abortedError(operation));
        return true;
      }
      signal.addEventListener("abort", abort, { once: true });
      addPendingFinalizer(this.#state, operationId, () => {
        signal.removeEventListener("abort", abort);
      });
    } catch (error) {
      try {
        signal.removeEventListener("abort", abort);
      } catch {
        // A hostile AbortSignal-like value cannot prevent operation cleanup.
      }
      takePendingOperation(this.#state, operationId);
      reject(normalizeUnknownError(error, operation));
      return true;
    }
    return false;
  }
}

/** A Node-style, bounded event adapter over one RawSocket receive lane. */
export class RawSocketEventEmitter extends EventEmitter<RawSocketEventMap> {
  readonly #socket: RawSocket;
  readonly #controller: EventReceiveController<ReceivedMessage, RawSocket>;

  constructor(socket: RawSocket, options: RawSocketEventEmitterOptions = {}) {
    super();
    const internals = socketInternals.get(socket);
    if (internals === undefined) {
      throw invalidArgument(
        "createRawSocketEventEmitter",
        "socket must be a RawSocket returned by this module",
      );
    }
    let configured: ClaimedReceiveOptions;
    try {
      configured = validateRawSocketEventEmitterOptions(options, socket.family);
    } catch (error) {
      throw normalizeUnknownError(error, "createRawSocketEventEmitter");
    }
    if (!internals.isOpen()) {
      throw socketClosedError("createRawSocketEventEmitter");
    }

    const lane: ReceiveLane = configured.errorQueue ? "errorQueue" : "normal";
    const state = internals.state;
    if (state.ringActive) {
      throw unsupportedError(
        "createRawSocketEventEmitter",
        "message events are unavailable after packet-ring configuration",
      );
    }
    if (state.ringConfigurations.size > 0 || state.ringFrameReceives > 0) {
      throw receiverActive(
        "createRawSocketEventEmitter",
        "packet-ring receive mode is currently active",
      );
    }
    if (state.directReceives[lane] > 0 || state.eventClaims.has(lane)) {
      throw receiverActive(
        "createRawSocketEventEmitter",
        `the ${lane} receive lane already has an active receiver`,
      );
    }

    this.#socket = socket;
    const claim = Symbol(`eventReceive:${lane}`);
    let controller!: EventReceiveController<ReceivedMessage, RawSocket>;
    const observer: SocketCloseObserver = {
      closing: () => {
        controller.notifyClosing();
      },
      closed: (error, rejected) => {
        controller.notifyCloseOutcome(error, rejected);
      },
    };
    state.eventClaims.set(lane, claim);
    state.closeObservers.add(observer);
    try {
      controller = new EventReceiveController({
        receive: (signal) =>
          internals.receiveClaimed(claim, configured, signal),
        close: () => socket.close(),
        releaseClaim: () => {
          if (state.eventClaims.get(lane) === claim) {
            state.eventClaims.delete(lane);
          }
        },
        removeCloseObserver: () => {
          state.closeObservers.delete(observer);
        },
        detachValue: () => socket,
        dispatchMessage: (message) => {
          this.#emitMessage(message);
        },
        dispatchError: (error) => {
          this.#emitError(error);
        },
        dispatchClose: () => {
          this.#emitClose();
        },
        invalidState: (operation) =>
          invalidState(
            operation,
            `cannot ${operation} an event source while it is ${controller.status}`,
          ),
        socketClosed: (operation) => socketClosedError(operation),
        isAborted: (error) => isRawSocketErrorKind(error, "aborted"),
        isSocketClosed: (error) => isRawSocketErrorKind(error, "socketClosed"),
        isReactorClosed: (error) =>
          isRawSocketErrorKind(error, "reactorClosed"),
      });
      this.#controller = controller;
    } catch (error) {
      if (state.eventClaims.get(lane) === claim) {
        state.eventClaims.delete(lane);
      }
      state.closeObservers.delete(observer);
      throw normalizeUnknownError(error, "createRawSocketEventEmitter");
    }
  }

  get socket(): RawSocket {
    return this.#socket;
  }

  get status(): RawSocketEventEmitterStatus {
    return this.#controller.status;
  }

  start(): this {
    this.#controller.start();
    return this;
  }

  pause(): Promise<void> {
    return this.#controller.pause();
  }

  resume(): this {
    this.#controller.resume();
    return this;
  }

  detach(): Promise<RawSocket> {
    return this.#controller.detach();
  }

  close(): Promise<void> {
    return this.#controller.close();
  }

  #emitMessage(message: ReceivedMessage): void {
    super.emit("message", message);
  }

  #emitError(error: unknown): void {
    super.emit("error", error);
  }

  #emitClose(): void {
    super.emit("close");
  }
}

/**
 * Confirms that the TypeScript package can call into the Rust Node-API addon.
 *
 * This bootstrap-only diagnostic does not perform network operations.
 */
export function nativeSmokeTest(): string {
  return nativeBinding.nativeSmokeTest();
}

/** Resolves a Linux interface name to its current nonzero index. */
export function interfaceIndex(name: string): number {
  const result = nativeBinding.nativeInterfaceIndex(name);
  if (isNativeErrorData(result)) throw new RawSocketError(result);
  return result;
}

/** Resolves a Linux interface index to its current name. */
export function interfaceName(index: number): string {
  const result = nativeBinding.nativeInterfaceName(index);
  if (isNativeErrorData(result)) throw new RawSocketError(result);
  return result;
}

function dispatchCompletion(
  state: SocketState,
  completion: NativeCompletion,
): void {
  const pending = takePendingOperation(state, completion.operationId);
  if (pending === undefined) {
    return;
  }
  if (completion.error === undefined) {
    pending.resolve(completion);
  } else {
    pending.reject(new RawSocketError(completion.error));
  }
}

function takePendingOperation(
  state: SocketState,
  operationId: number,
): PendingOperation | undefined {
  const pending = state.pending.get(operationId);
  if (pending === undefined) return undefined;
  state.pending.delete(operationId);
  pending.finalizers?.run();
  return pending;
}

function addPendingFinalizer(
  state: SocketState,
  operationId: number,
  finalizer: () => void,
): void {
  const pending = state.pending.get(operationId);
  if (pending === undefined) {
    throw internalError(
      "registerOperationFinalizer",
      "pending operation was not registered",
    );
  }
  const finalizers =
    pending.finalizers ?? (pending.finalizers = createInternalFinalizers());
  finalizers.add(finalizer);
}

function createSocketState(): SocketState {
  return {
    pending: new Map(),
    directReceives: { normal: 0, errorQueue: 0 },
    eventClaims: new Map(),
    ringConfigurations: new Set(),
    closeObservers: new Set(),
    ringFrameReceives: 0,
    ringActive: false,
  };
}

function callNative(
  operation: () => NativeSubmitResult,
  operationName: string,
): NativeSubmitResult {
  try {
    return operation();
  } catch (error) {
    return {
      accepted: false,
      error: errorDataFromUnknown(error, operationName),
    };
  }
}

function validateProtocol(options: RawSocketOptions): void {
  const candidate: unknown = options;
  if (typeof candidate !== "object" || candidate === null) {
    throw invalidArgument("createRawSocket", "options must be an object");
  }
  const family = (candidate as { family?: unknown }).family;
  if (
    family !== undefined &&
    family !== "ipv4" &&
    family !== "ipv6" &&
    family !== "packet"
  )
    throw invalidArgument(
      "createRawSocket",
      "family must be ipv4, ipv6, or packet",
    );
  const resolvedFamily = family ?? "ipv4";
  const mode = (candidate as { mode?: unknown }).mode;
  if (resolvedFamily === "packet") {
    if (mode !== "raw" && mode !== "cooked")
      throw invalidArgument(
        "createPacketSocket",
        "packet mode must be raw or cooked",
      );
  } else if (mode !== undefined)
    throw invalidArgument(
      "createRawSocket",
      "mode is valid only for packet sockets",
    );
  validatePacketLength(
    (candidate as { protocol?: unknown }).protocol,
    "protocol",
    resolvedFamily === "packet" ? 0xffff : 255,
  );
}

function validatePacketData(data: Uint8Array): void {
  if (!(data instanceof Uint8Array)) {
    throw invalidArgument("send", "data must be a Uint8Array");
  }
  validatePacketLength(data.byteLength, "data.byteLength");
}

function validateDestination(destination: string): void {
  validateIpv4Address(destination, "send", "destination");
}

function validateSignal(signal: unknown, operation: string): void {
  if (signal !== undefined && !(signal instanceof AbortSignal))
    throw invalidArgument(operation, "signal must be an AbortSignal");
}

function validateSendMessageRequest(
  request: unknown,
  socketFamily: RawSocketFamily,
): asserts request is SendMessageRequest {
  if (typeof request !== "object" || request === null)
    throw invalidArgument("sendMessage", "request must be an object");
  const candidate = request as Record<string, unknown>;
  validatePacketData(candidate.data as Uint8Array);
  if (
    typeof candidate.destination !== "object" ||
    candidate.destination === null ||
    ((candidate.destination as Record<string, unknown>).family !== "ipv4" &&
      (candidate.destination as Record<string, unknown>).family !== "ipv6" &&
      (candidate.destination as Record<string, unknown>).family !== "packet")
  ) {
    throw invalidArgument(
      "sendMessage",
      "destination must be an IP message address",
    );
  }
  const destination = candidate.destination as Record<string, unknown>;
  if (destination.family !== socketFamily)
    throw invalidArgument(
      "sendMessage",
      "destination family must match socket family",
    );
  if (socketFamily === "ipv4")
    validateIpv4Address(
      destination.address,
      "sendMessage",
      "destination.address",
    );
  else if (socketFamily === "ipv6")
    validateIpv6MessageAddress(destination, "sendMessage");
  else validatePacketMessageAddress(destination, "sendMessage", true);
  validateFlagList(candidate.flags, ["dontRoute"], "sendMessage");
  validateSignal(candidate.signal, "sendMessage");
  const control: unknown = candidate.control ?? [];
  if (!Array.isArray(control) || control.length > 64)
    throw invalidArgument(
      "sendMessage",
      "control must contain at most 64 messages",
    );
  if (socketFamily === "packet" && control.length !== 0) {
    throw invalidArgument(
      "sendMessage",
      "packet controls are deferred to Phase 8",
    );
  }
  const kinds = new Set<string>();
  for (const rawMessage of control) {
    if (typeof rawMessage !== "object" || rawMessage === null)
      throw invalidArgument(
        "sendMessage",
        "control messages must be valid and unique by kind",
      );
    const message = rawMessage as Record<string, unknown>;
    if (typeof message.kind !== "string" || kinds.has(message.kind)) {
      throw invalidArgument(
        "sendMessage",
        "control messages must have unique string kinds",
      );
    }
    kinds.add(message.kind);
    if (
      message.kind === "ipv4Ttl" ||
      message.kind === "ipv6HopLimit" ||
      message.kind === "ipv6TrafficClass"
    ) {
      validateIntegerRange(
        message.value,
        1,
        255,
        "sendMessage",
        `${message.kind}.value`,
      );
      if ((socketFamily === "ipv4") !== message.kind.startsWith("ipv4"))
        throw invalidArgument(
          "sendMessage",
          "control family must match socket family",
        );
    } else if (
      message.kind === "ipv4PacketInfo" ||
      message.kind === "ipv6PacketInfo"
    ) {
      if (message.interfaceIndex !== undefined)
        validateIntegerRange(
          message.interfaceIndex,
          0,
          0x7fff_ffff,
          "sendMessage",
          "interfaceIndex",
        );
      if ((socketFamily === "ipv4") !== message.kind.startsWith("ipv4"))
        throw invalidArgument(
          "sendMessage",
          "control family must match socket family",
        );
      if (message.sourceAddress !== undefined) {
        if (socketFamily === "ipv4")
          validateIpv4Address(
            message.sourceAddress,
            "sendMessage",
            "sourceAddress",
          );
        else
          validateIpv6Address(
            message.sourceAddress,
            "sendMessage",
            "sourceAddress",
          );
      }
    } else
      throw invalidArgument("sendMessage", "unsupported control message kind");
  }
}

function validateSendBatch(
  requests: unknown,
  family: RawSocketFamily,
): asserts requests is readonly BatchSendRequest[] {
  if (!Array.isArray(requests) || requests.length < 1 || requests.length > 64)
    throw invalidArgument(
      "sendBatch",
      "requests must contain 1 through 64 messages",
    );
  let bytes = 0;
  for (const request of requests) {
    if (typeof request !== "object" || request === null)
      throw invalidArgument("sendBatch", "each request must be an object");
    const candidate = request as Record<string, unknown>;
    validateSendMessageRequest(
      {
        data: candidate.data,
        destination: candidate.destination,
      },
      family,
    );
    bytes += (candidate.data as Uint8Array).byteLength;
    if (bytes > 1024 * 1024)
      throw invalidArgument(
        "sendBatch",
        "combined batch data must not exceed 1048576 bytes",
      );
  }
}

function validateReceiveMessageOptions(
  options: unknown,
): asserts options is ReceiveMessageOptions {
  if (typeof options !== "object" || options === null)
    throw invalidArgument("receiveMessage", "options must be an object");
  const candidate = options as Record<string, unknown>;
  validatePacketLength(
    candidate.dataCapacity ?? MAX_PACKET_LENGTH,
    "dataCapacity",
  );
  validateIntegerRange(
    candidate.controlCapacity ?? DEFAULT_CONTROL_CAPACITY,
    0,
    MAX_CONTROL_CAPACITY,
    "receiveMessage",
    "controlCapacity",
  );
  validateFlagList(candidate.flags, ["peek", "errorQueue"], "receiveMessage");
  validateSignal(candidate.signal, "receiveMessage");
}

function validateRawSocketEventEmitterOptions(
  options: unknown,
  family: RawSocketFamily,
): ClaimedReceiveOptions {
  if (typeof options !== "object" || options === null) {
    throw invalidArgument(
      "createRawSocketEventEmitter",
      "options must be an object",
    );
  }
  const candidate = options as Record<string, unknown>;
  const dataCapacity = candidate.dataCapacity ?? MAX_PACKET_LENGTH;
  const controlCapacity = candidate.controlCapacity ?? DEFAULT_CONTROL_CAPACITY;
  const errorQueue = candidate.errorQueue ?? false;
  validateIntegerRange(
    dataCapacity,
    1,
    MAX_PACKET_LENGTH,
    "createRawSocketEventEmitter",
    "dataCapacity",
  );
  validateIntegerRange(
    controlCapacity,
    0,
    MAX_CONTROL_CAPACITY,
    "createRawSocketEventEmitter",
    "controlCapacity",
  );
  if (typeof errorQueue !== "boolean") {
    throw invalidArgument(
      "createRawSocketEventEmitter",
      "errorQueue must be a boolean",
    );
  }
  if (errorQueue && family === "packet") {
    throw unsupportedError(
      "createRawSocketEventEmitter",
      "Linux packet sockets do not support the IP error queue",
    );
  }
  return { dataCapacity, controlCapacity, errorQueue };
}

function validateReceiveBatchOptions(
  options: unknown,
): asserts options is ReceiveBatchOptions {
  if (typeof options !== "object" || options === null)
    throw invalidArgument("receiveBatch", "options must be an object");
  const candidate = options as Record<string, unknown>;
  validateIntegerRange(candidate.count, 1, 64, "receiveBatch", "count");
  const capacity = candidate.dataCapacity ?? MAX_PACKET_LENGTH;
  validateIntegerRange(
    capacity,
    1,
    MAX_PACKET_LENGTH,
    "receiveBatch",
    "dataCapacity",
  );
  if (candidate.count * capacity > 1024 * 1024)
    throw invalidArgument(
      "receiveBatch",
      "combined receive batch allocation must not exceed 1048576 bytes",
    );
  validateSignal(candidate.signal, "receiveBatch");
}

function validatePacketRingConfig(
  config: unknown,
  family: RawSocketFamily,
): NativePacketRingConfig {
  if (family !== "packet")
    throw invalidArgument(
      "configurePacketRing",
      "packet rings require a packet socket",
    );
  if (typeof config !== "object" || config === null)
    throw invalidArgument(
      "configurePacketRing",
      "ring configuration must be an object",
    );
  const candidate = config as Record<string, unknown>;
  const blockSize = candidate.blockSize ?? 1024 * 1024;
  const blockCount = candidate.blockCount ?? 4;
  const frameSize = candidate.frameSize ?? 2048;
  const retireTimeoutMs = candidate.retireTimeoutMs ?? 64;
  validateIntegerRange(
    blockSize,
    4096,
    64 * 1024 * 1024,
    "configurePacketRing",
    "blockSize",
  );
  validateIntegerRange(
    blockCount,
    1,
    16_384,
    "configurePacketRing",
    "blockCount",
  );
  validateIntegerRange(
    frameSize,
    256,
    65_536,
    "configurePacketRing",
    "frameSize",
  );
  validateIntegerRange(
    retireTimeoutMs,
    1,
    60_000,
    "configurePacketRing",
    "retireTimeoutMs",
  );
  if (
    blockSize % frameSize !== 0 ||
    frameSize % 16 !== 0 ||
    blockSize * blockCount > 64 * 1024 * 1024
  )
    throw invalidArgument(
      "configurePacketRing",
      "ring geometry is misaligned or exceeds 64 MiB",
    );
  return {
    blockSize,
    blockCount,
    frameSize,
    retireTimeoutMs,
  };
}

function validateFlagList(
  value: unknown,
  allowed: readonly string[],
  operation: string,
): void {
  if (value === undefined) return;
  if (
    !Array.isArray(value) ||
    new Set(value).size !== value.length ||
    value.some(
      (flag: unknown) => typeof flag !== "string" || !allowed.includes(flag),
    )
  ) {
    throw invalidArgument(
      operation,
      "flags must contain unique supported values",
    );
  }
}

function validateIntegerRange(
  value: unknown,
  minimum: number,
  maximum: number,
  operation: string,
  name: string,
): asserts value is number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw invalidArgument(
      operation,
      `${name} must be an integer from ${String(minimum)} through ${String(maximum)}`,
    );
  }
}

function validateRawOptionNumbers(
  level: unknown,
  name: unknown,
  length: unknown,
  operation: string,
  allowZero = false,
): void {
  validateIntegerRange(level, 0, 0x7fff_ffff, operation, "level");
  validateIntegerRange(name, 0, 0x7fff_ffff, operation, "name");
  validateIntegerRange(
    length,
    allowZero ? 0 : 1,
    4096,
    operation,
    "option length",
  );
}

function validateClassicFilter(
  program: unknown,
): asserts program is readonly ClassicBpfInstruction[] {
  if (!Array.isArray(program) || program.length < 1 || program.length > 4096)
    throw invalidArgument(
      "attachFilter",
      "program must contain 1 through 4096 instructions",
    );
  for (const raw of program) {
    if (typeof raw !== "object" || raw === null)
      throw invalidArgument(
        "attachFilter",
        "each instruction must be an object",
      );
    const instruction = raw as Record<string, unknown>;
    validateIntegerRange(instruction.code, 0, 0xffff, "attachFilter", "code");
    validateIntegerRange(
      instruction.jumpTrue,
      0,
      0xff,
      "attachFilter",
      "jumpTrue",
    );
    validateIntegerRange(
      instruction.jumpFalse,
      0,
      0xff,
      "attachFilter",
      "jumpFalse",
    );
    validateIntegerRange(
      instruction.value,
      0,
      0xffff_ffff,
      "attachFilter",
      "value",
    );
  }
}

function validatePacketMembership(
  value: unknown,
  family: RawSocketFamily,
): asserts value is PacketMembership {
  if (family !== "packet")
    throw invalidArgument(
      "packetMembership",
      "membership requires a packet socket",
    );
  if (typeof value !== "object" || value === null)
    throw invalidArgument("packetMembership", "membership must be an object");
  const candidate = value as Record<string, unknown>;
  validateIntegerRange(
    candidate.interfaceIndex,
    1,
    0x7fff_ffff,
    "packetMembership",
    "interfaceIndex",
  );
  if (
    candidate.kind !== "promiscuous" &&
    candidate.kind !== "allMulticast" &&
    candidate.kind !== "multicast"
  )
    throw invalidArgument("packetMembership", "unsupported membership kind");
  if (
    candidate.address !== undefined &&
    (!(candidate.address instanceof Uint8Array) ||
      candidate.address.byteLength > 8)
  )
    throw invalidArgument(
      "packetMembership",
      "membership address must contain at most eight bytes",
    );
  if (
    candidate.kind === "multicast" &&
    (!(candidate.address instanceof Uint8Array) ||
      candidate.address.byteLength === 0)
  )
    throw invalidArgument(
      "packetMembership",
      "multicast membership requires an address",
    );
}

function convertReceivedMessage(
  message: NativeReceivedMessage,
): ReceivedMessage {
  const flags: ReceivedMessageFlag[] = [];
  if (message.endOfRecord) flags.push("endOfRecord");
  if (message.outOfBand) flags.push("outOfBand");
  if (message.errorQueue) flags.push("errorQueue");
  return {
    data: message.data,
    source: convertReceivedSource(message),
    dataLength: message.dataLength,
    dataTruncated: message.dataTruncated,
    controlTruncated: message.controlTruncated,
    flags,
    control: message.control.map(convertReceivedControl),
    ipv4: message.ipv4,
    packetAuxdata: convertPacketAuxdata(message),
  };
}

function convertPacketAuxdata(
  message: NativeReceivedMessage,
): PacketAuxdata | undefined {
  if (message.packetAuxStatus === undefined) return undefined;
  if (
    message.packetAuxOriginalLength === undefined ||
    message.packetAuxSnapshotLength === undefined ||
    message.packetAuxMacOffset === undefined ||
    message.packetAuxNetworkOffset === undefined ||
    message.packetAuxVlanTci === undefined ||
    message.packetAuxVlanTpid === undefined
  ) {
    throw internalError(
      "receiveMessage",
      "native PACKET_AUXDATA completion was incomplete",
    );
  }
  return {
    status: message.packetAuxStatus,
    originalLength: message.packetAuxOriginalLength,
    snapshotLength: message.packetAuxSnapshotLength,
    macOffset: message.packetAuxMacOffset,
    networkOffset: message.packetAuxNetworkOffset,
    vlanTci: message.packetAuxVlanTci,
    vlanTpid: message.packetAuxVlanTpid,
  };
}

function convertReceivedSource(
  message: NativeReceivedMessage,
): IpMessageAddress | undefined {
  if (message.sourceFamily === "packet") {
    if (
      message.sourceInterfaceIndex === undefined ||
      message.sourceProtocol === undefined ||
      message.sourceHardwareAddress === undefined ||
      message.sourceHardwareType === undefined ||
      message.sourcePacketType === undefined
    ) {
      throw internalError(
        "receiveMessage",
        "native packet source metadata was incomplete",
      );
    }
    return {
      family: "packet",
      interfaceIndex: message.sourceInterfaceIndex,
      protocol: message.sourceProtocol,
      address: message.sourceHardwareAddress,
      hardwareType: message.sourceHardwareType,
      packetType: message.sourcePacketType,
    };
  }
  if (message.sourceAddress === undefined) return undefined;
  return message.sourceFamily === "ipv6"
    ? {
        family: "ipv6",
        address: message.sourceAddress,
        scopeId: message.sourceScopeId ?? 0,
        flowInfo: message.sourceFlowInfo ?? 0,
      }
    : { family: "ipv4", address: message.sourceAddress };
}

function convertReceivedControl(
  message: NativeReceivedControlMessage,
): ReceivedControlMessage {
  switch (message.kind) {
    case "ipv4PacketInfo":
      if (
        message.interfaceIndex === undefined ||
        message.selectedAddress === undefined ||
        message.destinationAddress === undefined
      )
        break;
      return {
        kind: message.kind,
        interfaceIndex: message.interfaceIndex,
        selectedAddress: message.selectedAddress,
        destinationAddress: message.destinationAddress,
      };
    case "ipv6PacketInfo":
      if (
        message.interfaceIndex === undefined ||
        message.destinationAddress === undefined
      )
        break;
      return {
        kind: message.kind,
        interfaceIndex: message.interfaceIndex,
        destinationAddress: message.destinationAddress,
      };
    case "ipv4Ttl":
    case "ipv4TypeOfService":
    case "ipv6HopLimit":
    case "ipv6TrafficClass":
    case "receiveQueueOverflow":
      if (message.value === undefined) break;
      return { kind: message.kind, value: message.value };
    case "timestampNanoseconds": {
      if (message.seconds === undefined || message.nanoseconds === undefined)
        break;
      const seconds = BigInt(message.seconds);
      return {
        kind: message.kind,
        seconds,
        nanoseconds: message.nanoseconds,
        timestamp: seconds * 1_000_000_000n + BigInt(message.nanoseconds),
      };
    }
    case "ipv4ExtendedError":
    case "ipv6ExtendedError":
      if (
        message.errno === undefined ||
        message.origin === undefined ||
        message.errorType === undefined ||
        message.errorCode === undefined ||
        message.info === undefined ||
        message.extendedData === undefined
      )
        break;
      return {
        kind: message.kind,
        errno: message.errno,
        origin: message.origin,
        type: message.errorType,
        code: message.errorCode,
        info: message.info,
        data: message.extendedData,
        ...(message.offender === undefined
          ? {}
          : { offender: message.offender }),
      };
    case "unknown":
      if (
        message.level === undefined ||
        message.messageType === undefined ||
        message.data === undefined
      )
        break;
      return {
        kind: message.kind,
        level: message.level,
        type: message.messageType,
        data: message.data,
      };
  }
  throw internalError(
    "receiveMessage",
    "native control message was incomplete or unknown",
  );
}

function validateIpv4Address(
  value: unknown,
  operation: string,
  name: string,
): asserts value is string {
  if (typeof value !== "string" || !isIPv4(value)) {
    throw invalidArgument(
      operation,
      `${name} must be a dotted-decimal IPv4 address`,
    );
  }
}

function validateIpv6Address(
  value: unknown,
  operation: string,
  name: string,
): asserts value is string {
  if (typeof value !== "string" || value.includes("%") || !isIPv6(value)) {
    throw invalidArgument(
      operation,
      `${name} must be an IPv6 address without a zone suffix`,
    );
  }
}

function validateIpv6MessageAddress(
  value: unknown,
  operation: string,
): asserts value is Ipv6MessageAddress {
  if (typeof value !== "object" || value === null)
    throw invalidArgument(operation, "address must be an IPv6 message address");
  const candidate = value as Record<string, unknown>;
  if (candidate.family !== "ipv6")
    throw invalidArgument(operation, "address family must be ipv6");
  validateIpv6Address(candidate.address, operation, "address");
  validateIntegerRange(
    candidate.scopeId ?? 0,
    0,
    0xffff_ffff,
    operation,
    "scopeId",
  );
  validateIntegerRange(
    candidate.flowInfo ?? 0,
    0,
    0x000f_ffff,
    operation,
    "flowInfo",
  );
  const first = Number.parseInt(candidate.address.split(":", 1)[0] ?? "", 16);
  if ((first & 0xffc0) === 0xfe80 && (candidate.scopeId ?? 0) === 0) {
    throw invalidArgument(
      operation,
      "link-local IPv6 addresses require a nonzero scopeId",
    );
  }
}

function validatePacketMessageAddress(
  value: unknown,
  operation: string,
  outbound: boolean,
): asserts value is PacketMessageAddress {
  if (typeof value !== "object" || value === null)
    throw invalidArgument(
      operation,
      "address must be a packet message address",
    );
  const candidate = value as Record<string, unknown>;
  if (candidate.family !== "packet")
    throw invalidArgument(operation, "address family must be packet");
  validateIntegerRange(
    candidate.interfaceIndex,
    1,
    0x7fff_ffff,
    operation,
    "interfaceIndex",
  );
  validateIntegerRange(candidate.protocol, 1, 0xffff, operation, "protocol");
  if (
    candidate.address !== undefined &&
    (!(candidate.address instanceof Uint8Array) ||
      candidate.address.byteLength > 8)
  ) {
    throw invalidArgument(
      operation,
      "packet hardware address must be a Uint8Array of at most eight bytes",
    );
  }
  if (outbound && candidate.hardwareType !== undefined)
    throw invalidArgument(operation, "hardwareType is receive metadata only");
  if (outbound && candidate.packetType !== undefined)
    throw invalidArgument(operation, "packetType is receive metadata only");
}

function validateOptionName(
  value: unknown,
  operation: string,
): asserts value is RawSocketOptionName {
  if (
    value !== "broadcast" &&
    value !== "ipTtl" &&
    value !== "ipTypeOfService" &&
    value !== "receiveBufferSize" &&
    value !== "sendBufferSize" &&
    value !== "receivePacketInfo" &&
    value !== "receiveTtl" &&
    value !== "receiveTypeOfService" &&
    value !== "receiveTimestampNanoseconds" &&
    value !== "receiveQueueOverflow" &&
    value !== "receiveErrors" &&
    value !== "bindToDevice" &&
    value !== "ipv6Only" &&
    value !== "ipv6UnicastHops" &&
    value !== "ipv6TrafficClass" &&
    value !== "ipv6MulticastHops" &&
    value !== "receiveHopLimit" &&
    value !== "receiveTrafficClass" &&
    value !== "headerIncluded" &&
    value !== "freebind" &&
    value !== "transparent" &&
    value !== "priority" &&
    value !== "mark" &&
    value !== "pathMtuDiscovery" &&
    value !== "multicastTtl" &&
    value !== "multicastLoop" &&
    value !== "ipv6ChecksumOffset" &&
    value !== "busyPollMicroseconds"
  ) {
    throw invalidArgument(operation, "unsupported raw socket option");
  }
}

function validateOptionFamily(
  name: RawSocketOptionName,
  family: RawSocketFamily,
  operation: string,
): void {
  if (
    family === "packet" &&
    name !== "receiveBufferSize" &&
    name !== "sendBufferSize" &&
    name !== "busyPollMicroseconds"
  ) {
    throw unsupportedError(
      operation,
      `option ${name} is not a typed packet option`,
    );
  }
  const ipv4Only: readonly RawSocketOptionName[] = [
    "broadcast",
    "ipTtl",
    "ipTypeOfService",
    "receiveTtl",
    "receiveTypeOfService",
    "headerIncluded",
    "freebind",
    "transparent",
    "multicastTtl",
  ];
  const ipv6Only: readonly RawSocketOptionName[] = [
    "ipv6Only",
    "ipv6UnicastHops",
    "ipv6TrafficClass",
    "ipv6MulticastHops",
    "receiveHopLimit",
    "receiveTrafficClass",
    "ipv6ChecksumOffset",
  ];
  if (
    (family === "ipv4" && ipv6Only.includes(name)) ||
    (family === "ipv6" && ipv4Only.includes(name))
  ) {
    throw invalidArgument(
      operation,
      `option ${name} is incompatible with ${family}`,
    );
  }
  if (operation === "setOption" && name === "ipv6Only") {
    throw unsupportedError(
      operation,
      "Linux raw IPv6 sockets expose ipv6Only as an effective read-only value",
    );
  }
}

function validateOptionValue(
  name: unknown,
  value: unknown,
): number | undefined {
  validateOptionName(name, "setOption");
  if (name === "bindToDevice") {
    if (value === null) return undefined;
    if (
      typeof value !== "string" ||
      Buffer.byteLength(value) < 1 ||
      Buffer.byteLength(value) > 15 ||
      value.includes("\0")
    ) {
      throw invalidArgument(
        "setOption",
        "bindToDevice must be null or a 1 through 15 byte non-NUL string",
      );
    }
    return undefined;
  }
  if (isBooleanOption(name)) {
    if (typeof value !== "boolean") {
      throw invalidArgument("setOption", `${name} must be a boolean`);
    }
    return value ? 1 : 0;
  }

  const minimum =
    name === "ipTypeOfService" ||
    name.startsWith("ipv6") ||
    name === "priority" ||
    name === "mark" ||
    name === "pathMtuDiscovery" ||
    name === "busyPollMicroseconds"
      ? 0
      : 1;
  const maximum =
    name === "receiveBufferSize" || name === "sendBufferSize"
      ? MAX_SOCKET_BUFFER_SIZE
      : name === "mark"
        ? 0xffff_ffff
        : name === "priority"
          ? 0x7fff_ffff
          : name === "busyPollMicroseconds"
            ? 1_000_000
            : name === "pathMtuDiscovery"
              ? 3
              : name === "ipv6ChecksumOffset"
                ? 65_535
                : 255;
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < minimum ||
    value > maximum
  ) {
    throw invalidArgument(
      "setOption",
      `${name} must be an integer from ${String(minimum)} through ${String(maximum)}`,
    );
  }
  return value;
}

function isBooleanOption(name: RawSocketOptionName): boolean {
  return (
    name === "broadcast" ||
    name === "receivePacketInfo" ||
    name === "receiveTtl" ||
    name === "receiveTypeOfService" ||
    name === "receiveTimestampNanoseconds" ||
    name === "receiveQueueOverflow" ||
    name === "receiveErrors" ||
    name === "ipv6Only" ||
    name === "receiveHopLimit" ||
    name === "receiveTrafficClass" ||
    name === "headerIncluded" ||
    name === "freebind" ||
    name === "transparent" ||
    name === "multicastLoop"
  );
}

function validatePacketLength(
  value: unknown,
  name: string,
  maximum = MAX_PACKET_LENGTH,
): void {
  if (
    typeof value !== "number" ||
    !Number.isInteger(value) ||
    value < 1 ||
    value > maximum
  ) {
    throw invalidArgument(
      "validatePacketBufferLength",
      `${name} must be an integer from 1 through ${String(maximum)}`,
    );
  }
}

function isNativeErrorData(value: unknown): value is NativeErrorData {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Partial<NativeErrorData>;
  return (
    typeof candidate.kind === "string" &&
    typeof candidate.code === "string" &&
    typeof candidate.operation === "string" &&
    typeof candidate.message === "string"
  );
}

function isRawSocketStatus(value: string): value is RawSocketStatus {
  return value === "open" || value === "closing" || value === "closed";
}

function isRawSocketErrorKind(
  error: unknown,
  kind: RawSocketErrorKind,
): error is RawSocketError {
  return error instanceof RawSocketError && error.kind === kind;
}

function normalizeErrorKind(value: string): RawSocketErrorKind {
  switch (value) {
    case "aborted":
    case "internal":
    case "invalidArgument":
    case "invalidState":
    case "queueFull":
    case "reactorClosed":
    case "receiverActive":
    case "socketClosed":
    case "system":
    case "malformedControl":
    case "unsupported":
      return value;
    default:
      return "internal";
  }
}

function abortedError(operation: string): RawSocketError {
  return new RawSocketError({
    kind: "aborted",
    code: "ERR_ABORTED",
    operation,
    message: "the operation was aborted",
  });
}

function invalidArgument(operation: string, message: string): RawSocketError {
  return new RawSocketError({
    kind: "invalidArgument",
    code: "ERR_INVALID_ARGUMENT",
    operation,
    message,
  });
}

function invalidState(operation: string, message: string): RawSocketError {
  return new RawSocketError({
    kind: "invalidState",
    code: "ERR_INVALID_STATE",
    operation,
    message,
  });
}

function receiverActive(operation: string, message: string): RawSocketError {
  return new RawSocketError({
    kind: "receiverActive",
    code: "ERR_RECEIVER_ACTIVE",
    operation,
    message,
  });
}

function internalError(operation: string, message: string): RawSocketError {
  return new RawSocketError({
    kind: "internal",
    code: "ERR_INTERNAL",
    operation,
    message,
  });
}

function socketClosedError(operation: string): RawSocketError {
  return new RawSocketError({
    kind: "socketClosed",
    code: "ERR_SOCKET_CLOSED",
    operation,
    message: "the socket is closing or closed",
  });
}

function unsupportedError(operation: string, message: string): RawSocketError {
  return new RawSocketError({
    kind: "unsupported",
    code: "ERR_UNSUPPORTED",
    operation,
    message,
  });
}

function normalizeUnknownError(
  error: unknown,
  operation: string,
): RawSocketError {
  return error instanceof RawSocketError
    ? error
    : new RawSocketError(errorDataFromUnknown(error, operation));
}

function errorDataFromUnknown(
  error: unknown,
  operation: string,
): NativeErrorData {
  return {
    kind: "internal",
    code: "ERR_NATIVE_BOUNDARY",
    operation,
    message:
      error instanceof Error
        ? error.message
        : "unknown native boundary failure",
  };
}
