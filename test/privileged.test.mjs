import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createSocket as createDatagramSocket } from "node:dgram";
import { once } from "node:events";
import { closeSync, fstatSync, openSync } from "node:fs";
import { env } from "node:process";
import test from "node:test";
import { setImmediate, setTimeout as delay } from "node:timers/promises";
import { URL } from "node:url";
import { Worker } from "node:worker_threads";

import {
  IPPROTO_ICMP,
  IPPROTO_ICMPV6,
  IPPROTO_UDP,
  RawSocket,
  RawSocketEventEmitter,
  interfaceIndex,
  interfaceName,
} from "../dist/index.js";

const privilegedTestsEnabled = env.NODENETRAW_PRIVILEGED_TESTS === "1";

test(
  "settles completion bursts larger than the native callback queue",
  { skip: !privilegedTestsEnabled, timeout: 5_000 },
  async () => {
    const socket = await RawSocket.open({ protocol: 1 });
    try {
      const operations = [];
      const sleeper = new Int32Array(new SharedArrayBuffer(4));
      for (let batch = 0; batch < 3; batch += 1) {
        for (let index = 0; index < 32; index += 1) {
          operations.push(socket.getOption("ipTtl"));
        }
        // Keep JavaScript from draining the thread-safe callback while the
        // reactor completes this batch. Three batches exceed its capacity.
        Atomics.wait(sleeper, 0, 0, 100);
      }
      const result = await Promise.race([
        Promise.all(operations),
        delay(2_000, "timed out", { ref: false }),
      ]);
      assert.notEqual(result, "timed out");
      assert.equal(result.length, 96);
    } finally {
      await socket.close();
    }
  },
);

test(
  "sends and receives an ICMP echo packet on loopback",
  { skip: !privilegedTestsEnabled, timeout: 5_000 },
  async () => {
    const socket = await RawSocket.open({ protocol: 1 });
    try {
      assert.equal(await socket.localAddress(), "0.0.0.0");
      await socket.bind("127.0.0.1");
      assert.equal(await socket.localAddress(), "127.0.0.1");
      await socket.setOption("ipTtl", 37);
      assert.equal(await socket.getOption("ipTtl"), 37);
      await socket.setOption("ipTypeOfService", 0xb8);
      assert.equal(await socket.getOption("ipTypeOfService"), 0xb8);
      await socket.setOption("broadcast", true);
      assert.equal(await socket.getOption("broadcast"), true);
      await socket.setOption("receiveBufferSize", 65_536);
      assert.ok((await socket.getOption("receiveBufferSize")) >= 65_536);
      await socket.setOption("sendBufferSize", 65_536);
      assert.ok((await socket.getOption("sendBufferSize")) >= 65_536);
      await socket.setOption("headerIncluded", false);
      assert.equal(await socket.getOption("headerIncluded"), false);
      await socket.setOption("freebind", true);
      assert.equal(await socket.getOption("freebind"), true);
      await socket.setOption("priority", 4);
      assert.equal(await socket.getOption("priority"), 4);
      await socket.setOption("pathMtuDiscovery", 2);
      assert.equal(await socket.getOption("pathMtuDiscovery"), 2);
      await socket.setOption("multicastTtl", 9);
      assert.equal(await socket.getOption("multicastTtl"), 9);
      await socket.setOption("multicastLoop", true);
      assert.equal(await socket.getOption("multicastLoop"), true);
      await socket.setOption("busyPollMicroseconds", 0);
      assert.equal(await socket.getOption("busyPollMicroseconds"), 0);

      const receivePromise = socket.receive();
      await setImmediate();
      const request = createEchoRequest();
      assert.equal(await socket.send(request, "127.0.0.1"), request.byteLength);

      const packet = await receivePromise;
      assert.equal(packet.sourceAddress, "127.0.0.1");
      assert.equal(packet.truncated, false);
      assert.equal(packet.packetLength, packet.data.byteLength);
      assert.ok(packet.data.byteLength >= 28);
      assert.equal(packet.data[9], 1);
      assert.equal(packet.ipv4?.destinationAddress, "127.0.0.1");
      assert.equal(packet.ipv4?.protocol, 1);
      assert.equal(packet.ipv4?.ttl, 37);
      assert.equal(packet.ipv4?.typeOfService, 0xb8);
      assert.equal(packet.ipv4?.headerLength, 20);
      assert.equal(packet.ipv4?.totalLength, packet.packetLength);

      const batchReceive = socket.receiveBatch({ count: 4, dataCapacity: 256 });
      await setImmediate();
      const batchSend = await socket.sendBatch([
        {
          data: createEchoRequest(),
          destination: { family: "ipv4", address: "127.0.0.1" },
        },
        {
          data: createEchoRequest(),
          destination: { family: "ipv4", address: "127.0.0.1" },
        },
      ]);
      assert.equal(batchSend.requested, 2);
      assert.equal(batchSend.completed, 2);
      assert.deepEqual(
        batchSend.results.map((result) => result.index),
        [0, 1],
      );
      const receivedBatch = await batchReceive;
      assert.ok(receivedBatch.completed >= 1);
      assert.equal(receivedBatch.completed, receivedBatch.messages.length);
      assert.equal(receivedBatch.messages[0].source?.family, "ipv4");

      await socket.connect({ family: "ipv4", address: "127.0.0.1" });
      await socket.disconnect();
    } finally {
      await socket.close();
    }
  },
);

test(
  "injects and captures raw and cooked AF_PACKET frames across veth",
  { skip: !privilegedTestsEnabled, timeout: 5_000 },
  async () => {
    const protocol = 0x88b5;
    const firstIndex = interfaceIndex("nr-veth0");
    const secondIndex = interfaceIndex("nr-veth1");
    assert.equal(interfaceName(firstIndex), "nr-veth0");
    assert.equal(interfaceName(secondIndex), "nr-veth1");
    const firstMac = Uint8Array.of(2, 0, 0, 0, 0, 1);
    const secondMac = Uint8Array.of(2, 0, 0, 0, 0, 2);

    const rawReceiver = await RawSocket.open({
      family: "packet",
      mode: "raw",
      protocol,
    });
    const cookedSender = await RawSocket.open({
      family: "packet",
      mode: "cooked",
      protocol,
    });
    try {
      assert.equal(rawReceiver.packetMode, "raw");
      assert.equal(cookedSender.packetMode, "cooked");
      await rawReceiver.bind({
        family: "packet",
        interfaceIndex: secondIndex,
        protocol,
      });
      await rawReceiver.addPacketMembership({
        interfaceIndex: secondIndex,
        kind: "promiscuous",
      });
      await rawReceiver.setPacketAuxdata(true);
      await rawReceiver.attachClassicFilter([
        { code: 0x06, jumpTrue: 0, jumpFalse: 0, value: 0xffff_ffff },
      ]);
      // A second attachment atomically replaces the first kernel-owned copy.
      await rawReceiver.attachClassicFilter([
        { code: 0x06, jumpTrue: 0, jumpFalse: 0, value: 0xffff_ffff },
      ]);
      await rawReceiver.setPacketFanout(0x4e52, "hash");
      await cookedSender.bind({
        family: "packet",
        interfaceIndex: firstIndex,
        protocol,
      });
      const payload = Buffer.from("cooked-to-raw");
      const waiting = rawReceiver.receiveMessage();
      await cookedSender.sendMessage({
        data: payload,
        destination: {
          family: "packet",
          interfaceIndex: firstIndex,
          protocol,
          address: secondMac,
        },
      });
      const frame = await waiting;
      assert.equal(frame.source?.family, "packet");
      assert.equal(frame.source?.interfaceIndex, secondIndex);
      assert.equal(frame.source?.protocol, protocol);
      assert.deepEqual(frame.data.subarray(0, 6), Buffer.from(secondMac));
      assert.deepEqual(frame.data.subarray(6, 12), Buffer.from(firstMac));
      assert.equal(frame.data.readUInt16BE(12), protocol);
      assert.deepEqual(frame.data.subarray(14), payload);
      assert.ok(frame.packetAuxdata !== undefined);
      assert.equal(frame.packetAuxdata.originalLength, frame.dataLength);

      assert.throws(
        () => new RawSocketEventEmitter(rawReceiver, { errorQueue: true }),
        { code: "ERR_UNSUPPORTED" },
      );
      const packetEvents = new RawSocketEventEmitter(rawReceiver);
      const eventPayloads = [
        Buffer.from("event-cooked-to-raw-1"),
        Buffer.from("event-cooked-to-raw-2"),
      ];
      const eventFrames = collectMessages(
        packetEvents,
        eventPayloads.length,
        (message) =>
          message.source?.family === "packet" &&
          eventPayloads.some((candidate) =>
            message.data.subarray(-candidate.length).equals(candidate),
          ),
      );
      packetEvents.start();
      await setImmediate();
      for (const eventPayload of eventPayloads) {
        await cookedSender.sendMessage({
          data: eventPayload,
          destination: {
            family: "packet",
            interfaceIndex: firstIndex,
            protocol,
            address: secondMac,
          },
        });
      }
      const deliveredFrames = await withDeadline(
        eventFrames,
        "packet event delivery",
      );
      assert.equal(deliveredFrames.length, 2);
      assert.deepEqual(
        deliveredFrames.map((message) =>
          eventPayloads.findIndex((candidate) =>
            message.data.subarray(-candidate.length).equals(candidate),
          ),
        ),
        [0, 1],
      );
      for (const delivered of deliveredFrames) {
        assert.equal(delivered.source?.family, "packet");
        assert.equal(delivered.source?.interfaceIndex, secondIndex);
        assert.ok(delivered.packetAuxdata !== undefined);
      }
      await packetEvents.pause();
      assert.equal(packetEvents.status, "paused");
      assert.equal(await packetEvents.detach(), rawReceiver);

      const cookedReceiver = await RawSocket.open({
        family: "packet",
        mode: "cooked",
        protocol,
      });
      const rawSender = await RawSocket.open({
        family: "packet",
        mode: "raw",
        protocol,
      });
      try {
        await cookedReceiver.bind({
          family: "packet",
          interfaceIndex: firstIndex,
          protocol,
        });
        await rawSender.bind({
          family: "packet",
          interfaceIndex: secondIndex,
          protocol,
        });
        const reversePayload = Buffer.from("raw-to-cooked");
        const outbound = Buffer.concat([
          Buffer.from(firstMac),
          Buffer.from(secondMac),
          Buffer.from([0x88, 0xb5]),
          reversePayload,
        ]);
        const reverseWaiting = cookedReceiver.receiveMessage();
        await rawSender.sendMessage({
          data: outbound,
          destination: {
            family: "packet",
            interfaceIndex: secondIndex,
            protocol,
            address: firstMac,
          },
        });
        const cooked = await reverseWaiting;
        assert.deepEqual(cooked.data, reversePayload);

        const truncatedWaiting = cookedReceiver.receiveMessage({
          dataCapacity: 4,
        });
        await rawSender.sendMessage({
          data: outbound,
          destination: {
            family: "packet",
            interfaceIndex: secondIndex,
            protocol,
            address: firstMac,
          },
        });
        const truncated = await truncatedWaiting;
        assert.equal(truncated.data.byteLength, 4);
        assert.equal(truncated.dataLength, reversePayload.byteLength);
        assert.equal(truncated.dataTruncated, true);
      } finally {
        await rawSender.close();
        await cookedReceiver.close();
      }
      const statistics = await rawReceiver.packetStatistics();
      assert.ok(statistics.packets >= 1);
      assert.ok(statistics.drops >= 0);
      await rawReceiver.detachFilter();
      await rawReceiver.dropPacketMembership({
        interfaceIndex: secondIndex,
        kind: "promiscuous",
      });
    } finally {
      await cookedSender.close();
      await rawReceiver.close();
    }

    const cancellationSocket = await RawSocket.open({
      family: "packet",
      mode: "cooked",
      protocol: 0x88b6,
    });
    await cancellationSocket.bind({
      family: "packet",
      interfaceIndex: firstIndex,
      protocol: 0x88b6,
    });
    await cancellationSocket.attachClassicFilter([
      { code: 0x06, jumpTrue: 0, jumpFalse: 0, value: 0xffff_ffff },
    ]);
    await cancellationSocket.lockFilter();
    await assert.rejects(cancellationSocket.detachFilter(), {
      code: "ERR_SYSTEM",
    });
    const nonBpfFd = openSync("/dev/null", "r");
    try {
      await assert.rejects(cancellationSocket.attachEbpfFilter(nonBpfFd), {
        code: "ERR_SYSTEM",
      });
      assert.ok(fstatSync(nonBpfFd).isCharacterDevice());
    } finally {
      closeSync(nonBpfFd);
    }
    const controller = new globalThis.AbortController();
    const waiting = cancellationSocket.receiveMessage({
      signal: controller.signal,
    });
    controller.abort();
    await assert.rejects(waiting, { code: "ERR_ABORTED" });
    await cancellationSocket.close();

    const ringReceiver = await RawSocket.open({
      family: "packet",
      mode: "raw",
      protocol: 0x88b7,
    });
    const ringSender = await RawSocket.open({
      family: "packet",
      mode: "cooked",
      protocol: 0x88b7,
    });
    try {
      await ringReceiver.bind({
        family: "packet",
        interfaceIndex: secondIndex,
        protocol: 0x88b7,
      });
      const prematureRingReceive = ringReceiver.receiveRingFrame();
      assert.throws(() => new RawSocketEventEmitter(ringReceiver), {
        code: "ERR_RECEIVER_ACTIVE",
      });
      await assert.rejects(prematureRingReceive, { code: "ERR_UNSUPPORTED" });

      const preRingEvents = new RawSocketEventEmitter(ringReceiver);
      await assert.rejects(
        ringReceiver.configurePacketRing({
          blockSize: 4096,
          blockCount: 2,
          frameSize: 2048,
          retireTimeoutMs: 16,
        }),
        { code: "ERR_RECEIVER_ACTIVE" },
      );
      await preRingEvents.detach();
      const firstRingConfiguration = ringReceiver.configurePacketRing({
        blockSize: 4096,
        blockCount: 2,
        frameSize: 2048,
        retireTimeoutMs: 16,
      });
      const secondRingConfiguration = ringReceiver.configurePacketRing({
        blockSize: 4096,
        blockCount: 2,
        frameSize: 2048,
        retireTimeoutMs: 16,
      });
      assert.throws(() => new RawSocketEventEmitter(ringReceiver), {
        code: "ERR_RECEIVER_ACTIVE",
      });
      const configurationOutcomes = await Promise.allSettled([
        firstRingConfiguration,
        secondRingConfiguration,
      ]);
      assert.equal(
        configurationOutcomes.filter(
          (outcome) => outcome.status === "fulfilled",
        ).length,
        1,
      );
      assert.equal(
        configurationOutcomes.filter(
          (outcome) =>
            outcome.status === "rejected" &&
            outcome.reason?.code === "ERR_UNSUPPORTED",
        ).length,
        1,
      );
      assert.throws(() => new RawSocketEventEmitter(ringReceiver), {
        code: "ERR_UNSUPPORTED",
      });
      await ringSender.bind({
        family: "packet",
        interfaceIndex: firstIndex,
        protocol: 0x88b7,
      });
      const waitingForRing = ringReceiver.receiveRingFrame();
      const ringPayload = Buffer.from("tpacket-v3-frame");
      await ringSender.sendMessage({
        data: ringPayload,
        destination: {
          family: "packet",
          interfaceIndex: firstIndex,
          protocol: 0x88b7,
          address: secondMac,
        },
      });
      const lease = await waitingForRing;
      const ringFrame = lease.read();
      assert.deepEqual(ringFrame.subarray(-ringPayload.length), ringPayload);
      assert.ok(lease.originalLength >= ringPayload.length);
      assert.equal(lease.snapshotLength, ringFrame.length);
      assert.equal(lease.released, false);
      lease.release();
      assert.equal(lease.released, true);
      assert.throws(() => lease.read(), { code: "ERR_INVALID_ARGUMENT" });

      const ringWaits = Array.from({ length: 16 }, () =>
        ringReceiver.receiveRingFrame(),
      );
      const ringBatch = await ringSender.sendBatch(
        Array.from({ length: 16 }, (_, index) => ({
          data: Buffer.from(`ring-stress-${String(index).padStart(2, "0")}`),
          destination: {
            family: "packet",
            interfaceIndex: firstIndex,
            protocol: 0x88b7,
            address: secondMac,
          },
        })),
      );
      assert.equal(ringBatch.completed, 16);
      const leases = await Promise.all(ringWaits);
      for (const frameLease of leases) {
        assert.ok(frameLease.read().length >= 14);
        frameLease.release();
      }

      const ringAbort = new globalThis.AbortController();
      const cancelledRing = ringReceiver.receiveRingFrame({
        signal: ringAbort.signal,
      });
      ringAbort.abort();
      await assert.rejects(cancelledRing, { code: "ERR_ABORTED" });
      await assert.rejects(ringReceiver.receiveMessage(), {
        code: "ERR_UNSUPPORTED",
      });
    } finally {
      await ringSender.close();
      await ringReceiver.close();
    }
  },
);

test(
  "sends and receives an ICMPv6 message with IPv6 ancillary metadata",
  { skip: !privilegedTestsEnabled, timeout: 5_000 },
  async () => {
    const socket = await RawSocket.open({ family: "ipv6", protocol: 58 });
    try {
      assert.equal(socket.family, "ipv6");
      await assert.rejects(
        socket.bind({ family: "ipv6", address: "fe80::1" }),
        {
          code: "ERR_INVALID_ARGUMENT",
        },
      );
      await socket.bind({ family: "ipv6", address: "::1" });
      assert.deepEqual(await socket.localMessageAddress(), {
        family: "ipv6",
        address: "::1",
        scopeId: 0,
        flowInfo: 0,
      });
      await socket.setOption("ipv6UnicastHops", 37);
      await socket.setOption("ipv6TrafficClass", 0xb8);
      await socket.setOption("ipv6MulticastHops", 12);
      await socket.setOption("receivePacketInfo", true);
      await socket.setOption("receiveHopLimit", true);
      await socket.setOption("receiveTrafficClass", true);
      await socket.setOption("receiveTimestampNanoseconds", true);
      await socket.setOption("receiveErrors", true);
      assert.equal(await socket.getOption("ipv6UnicastHops"), 37);
      assert.equal(await socket.getOption("ipv6TrafficClass"), 0xb8);
      assert.equal(await socket.getOption("ipv6MulticastHops"), 12);

      const receive = socket.receiveMessage();
      await setImmediate();
      const request = createEchoRequestV6();
      assert.equal(
        await socket.sendMessage({
          data: request,
          destination: { family: "ipv6", address: "::1" },
          control: [
            { kind: "ipv6HopLimit", value: 41 },
            { kind: "ipv6TrafficClass", value: 0x2e },
          ],
        }),
        request.byteLength,
      );
      const message = await receive;
      assert.equal(message.source?.family, "ipv6");
      assert.equal(message.source?.address, "::1");
      assert.equal(message.ipv4, undefined);
      assert.equal(message.data[0], 128);
      assert.ok(message.control.some((item) => item.kind === "ipv6PacketInfo"));
      assert.ok(message.control.some((item) => item.kind === "ipv6HopLimit"));
      assert.ok(
        message.control.some((item) => item.kind === "ipv6TrafficClass"),
      );

      const truncatedReceive = socket.receiveMessage({ dataCapacity: 4 });
      await socket.sendMessage({
        data: createEchoRequestV6(),
        destination: { family: "ipv6", address: "::1" },
      });
      const truncated = await truncatedReceive;
      assert.equal(truncated.data.byteLength, 4);
      assert.ok(truncated.dataLength >= 8);
      assert.equal(truncated.dataTruncated, true);

      await assert.rejects(
        socket.sendMessage({
          data: request,
          destination: { family: "ipv6", address: "::1" },
          control: [{ kind: "ipv4Ttl", value: 1 }],
        }),
        { code: "ERR_INVALID_ARGUMENT" },
      );

      await socket.connect({ family: "ipv6", address: "::1" });
      await socket.disconnect();
      await assert.rejects(socket.localAddress(), { code: "ERR_UNSUPPORTED" });
      await assert.rejects(socket.send(Uint8Array.of(1), "127.0.0.1"), {
        code: "ERR_UNSUPPORTED",
      });

      const cancellationSocket = await RawSocket.open({
        family: "ipv6",
        protocol: 253,
      });
      const controller = new globalThis.AbortController();
      const waiting = cancellationSocket.receiveMessage({
        signal: controller.signal,
      });
      controller.abort();
      await assert.rejects(waiting, { code: "ERR_ABORTED" });
      await cancellationSocket.close();
    } finally {
      await socket.close();
    }
  },
);

test(
  "exposes message control data, device binding, and AbortSignal cancellation",
  { skip: !privilegedTestsEnabled, timeout: 5_000 },
  async () => {
    const socket = await RawSocket.open({ protocol: 1 });
    try {
      await socket.setOption("bindToDevice", "lo");
      assert.equal(await socket.getOption("bindToDevice"), "lo");
      await socket.setOption("receivePacketInfo", true);
      await socket.setOption("receiveTtl", true);
      await socket.setOption("receiveTypeOfService", true);
      await socket.setOption("receiveTimestampNanoseconds", true);
      await socket.setOption("receiveQueueOverflow", true);
      assert.equal(await socket.getOption("receivePacketInfo"), true);
      assert.equal(await socket.getOption("receiveTtl"), true);
      assert.equal(await socket.getOption("receiveTypeOfService"), true);
      assert.equal(await socket.getOption("receiveTimestampNanoseconds"), true);
      assert.equal(await socket.getOption("receiveQueueOverflow"), true);

      const receive = socket.receiveMessage();
      await setImmediate();
      const request = createEchoRequest();
      assert.equal(
        await socket.sendMessage({
          data: request,
          destination: { family: "ipv4", address: "127.0.0.1" },
          control: [{ kind: "ipv4Ttl", value: 41 }],
        }),
        request.byteLength,
      );
      const message = await receive;
      assert.equal(message.source?.family, "ipv4");
      assert.equal(message.source?.address, "127.0.0.1");
      assert.equal(message.dataTruncated, false);
      assert.equal(message.controlTruncated, false);
      assert.ok(message.control.some((item) => item.kind === "ipv4PacketInfo"));
      assert.ok(message.control.some((item) => item.kind === "ipv4Ttl"));
      assert.ok(
        message.control.some((item) => item.kind === "ipv4TypeOfService"),
      );
      const timestamp = message.control.find(
        (item) => item.kind === "timestampNanoseconds",
      );
      assert.equal(typeof timestamp?.timestamp, "bigint");

      await socket.setOption("bindToDevice", null);
      assert.equal(await socket.getOption("bindToDevice"), null);

      const cancellationSocket = await RawSocket.open({ protocol: 253 });
      try {
        await cancellationSocket.setOption("receiveErrors", true);
        assert.equal(await cancellationSocket.getOption("receiveErrors"), true);
        const controller = new globalThis.AbortController();
        const waiting = cancellationSocket.receiveMessage({
          flags: ["errorQueue"],
          signal: controller.signal,
        });
        controller.abort();
        await assert.rejects(waiting, {
          code: "ERR_ABORTED",
          kind: "aborted",
        });
      } finally {
        await cancellationSocket.close();
      }
    } finally {
      await socket.close();
    }
  },
);

test(
  "bounds pending receives and cancels admitted work on close",
  { skip: !privilegedTestsEnabled, timeout: 5_000 },
  async () => {
    const socket = await RawSocket.open({ protocol: 1 });
    const outcomes = Array.from({ length: 17 }, () =>
      socket.receive(64).then(
        (packet) => ({ packet }),
        (error) => ({ error }),
      ),
    );

    const overflow = await outcomes[16];
    assert.equal(overflow.error?.code, "ERR_QUEUE_FULL");

    const closePromise = socket.close();
    const cancelled = await Promise.all(outcomes.slice(0, 16));
    for (const outcome of cancelled) {
      assert.equal(outcome.error?.code, "ERR_SOCKET_CLOSED");
    }
    await closePromise;
    assert.equal(socket.status, "closed");
  },
);

test(
  "reports original packet length when capture truncates the IPv4 header",
  { skip: !privilegedTestsEnabled, timeout: 5_000 },
  async () => {
    const socket = await RawSocket.open({ protocol: 1 });
    try {
      await socket.bind("127.0.0.1");
      const receivePromise = socket.receive(8);
      await setImmediate();
      const request = createEchoRequest();
      await socket.send(request, "127.0.0.1");

      const packet = await receivePromise;
      assert.equal(packet.data.byteLength, 8);
      assert.ok(packet.packetLength >= 28);
      assert.equal(packet.truncated, true);
      assert.equal(packet.ipv4, undefined);
    } finally {
      await socket.close();
    }
  },
);

test(
  "delivers ordered IPv4 message events across pause, resume, detach, and close",
  { skip: !privilegedTestsEnabled, timeout: 5_000 },
  async () => {
    const socket = await RawSocket.open({ protocol: IPPROTO_ICMP });
    await socket.bind("127.0.0.1");
    for (const options of [
      null,
      { dataCapacity: 0 },
      { dataCapacity: 65_536 },
      { controlCapacity: -1 },
      { controlCapacity: 65_537 },
      { errorQueue: "yes" },
    ]) {
      assert.throws(() => new RawSocketEventEmitter(socket, options), {
        code: "ERR_INVALID_ARGUMENT",
        operation: "createRawSocketEventEmitter",
      });
    }
    assert.throws(
      () =>
        new RawSocketEventEmitter(
          socket,
          new Proxy(
            {},
            {
              get() {
                throw new Error("hostile options getter");
              },
            },
          ),
        ),
      {
        code: "ERR_NATIVE_BOUNDARY",
        operation: "createRawSocketEventEmitter",
      },
    );

    const hostileRegistrationController = new globalThis.AbortController();
    Object.defineProperty(
      hostileRegistrationController.signal,
      "addEventListener",
      {
        value() {
          throw new Error("hostile signal registration");
        },
      },
    );
    await assert.rejects(
      socket.receiveMessage({ signal: hostileRegistrationController.signal }),
      {
        code: "ERR_NATIVE_BOUNDARY",
        operation: "receiveMessage",
      },
    );
    const registrationProbe = new RawSocketEventEmitter(socket);
    await registrationProbe.detach();

    const hostileAbortedController = new globalThis.AbortController();
    Object.defineProperty(hostileAbortedController.signal, "aborted", {
      get() {
        throw new Error("hostile signal state");
      },
    });
    await assert.rejects(
      socket.receiveMessage({ signal: hostileAbortedController.signal }),
      {
        code: "ERR_NATIVE_BOUNDARY",
        operation: "receiveMessage",
      },
    );
    const abortedProbe = new RawSocketEventEmitter(socket);
    await abortedProbe.detach();

    const hostileRemovalController = new globalThis.AbortController();
    Object.defineProperty(
      hostileRemovalController.signal,
      "removeEventListener",
      {
        value() {
          throw new Error("hostile signal removal");
        },
      },
    );
    const hostileRemovalReceive = socket.receiveMessage({
      signal: hostileRemovalController.signal,
    });
    hostileRemovalController.abort();
    await assert.rejects(hostileRemovalReceive, { code: "ERR_ABORTED" });
    const removalProbe = new RawSocketEventEmitter(socket);
    await removalProbe.detach();

    const directAbort = new globalThis.AbortController();
    const directReceive = socket.receiveMessage({ signal: directAbort.signal });
    const independentErrorLane = new RawSocketEventEmitter(socket, {
      errorQueue: true,
    });
    assert.throws(() => new RawSocketEventEmitter(socket), {
      code: "ERR_RECEIVER_ACTIVE",
    });
    await independentErrorLane.detach();
    directAbort.abort();
    await assert.rejects(directReceive, { code: "ERR_ABORTED" });

    const source = new RawSocketEventEmitter(socket);
    assert.equal(source.socket, socket);
    assert.throws(() => new RawSocketEventEmitter(socket), {
      code: "ERR_RECEIVER_ACTIVE",
    });
    await assert.rejects(socket.receiveMessage(), {
      code: "ERR_RECEIVER_ACTIVE",
    });
    await assert.rejects(socket.receive(), { code: "ERR_RECEIVER_ACTIVE" });
    await assert.rejects(socket.receiveBatch({ count: 1 }), {
      code: "ERR_RECEIVER_ACTIVE",
    });
    await assert.rejects(socket.receiveMessage({ dataCapacity: 0 }), {
      code: "ERR_INVALID_ARGUMENT",
    });
    await assert.rejects(socket.receive(0), { code: "ERR_INVALID_ARGUMENT" });
    await assert.rejects(socket.receiveBatch({ count: 0 }), {
      code: "ERR_INVALID_ARGUMENT",
    });
    const alreadyAbortedConflict = new globalThis.AbortController();
    alreadyAbortedConflict.abort();
    await assert.rejects(
      socket.receiveMessage({ signal: alreadyAbortedConflict.signal }),
      { code: "ERR_RECEIVER_ACTIVE" },
    );

    const sequences = [];
    let pauseBoundary;
    let firstResolve;
    let firstReject;
    let secondResolve;
    let secondReject;
    const first = new Promise((resolve, reject) => {
      firstResolve = resolve;
      firstReject = reject;
    });
    const second = new Promise((resolve, reject) => {
      secondResolve = resolve;
      secondReject = reject;
    });
    source.on("error", (error) => {
      firstReject(error);
      secondReject(error);
    });
    source.on("message", (message) => {
      const sequence = icmpv4EchoSequence(message);
      if (sequence === undefined || sequence < 11 || sequence > 12) return;
      sequences.push(sequence);
      if (sequences.length === 1) {
        pauseBoundary = source.pause();
        firstResolve();
      } else if (sequences.length === 2) {
        secondResolve();
      }
    });
    const sameTurnPause = source.start().pause();
    assert.equal(source.status, "paused");
    source.resume();
    await sameTurnPause;
    assert.equal(source.status, "running");
    assert.equal(source.start(), source);
    await setImmediate();
    await socket.send(createEchoRequest(11), "127.0.0.1");
    await withDeadline(first, "first IPv4 event");
    await pauseBoundary;
    assert.equal(source.status, "paused");

    await socket.send(createEchoRequest(12), "127.0.0.1");
    await delay(20, undefined, { ref: false });
    assert.deepEqual(sequences, [11]);
    assert.equal(source.resume(), source);
    await withDeadline(second, "resumed IPv4 event");
    assert.deepEqual(sequences, [11, 12]);

    await source.pause();
    const detach = source.detach();
    const closingSource = new RawSocketEventEmitter(socket);
    assert.equal(await detach, socket);
    assert.equal(source.status, "detached");

    let closeEvents = 0;
    let libraryCloseResolve;
    const libraryCloseEvent = new Promise((resolve) => {
      libraryCloseResolve = resolve;
    });
    closingSource.on("close", () => {
      closeEvents += 1;
      if (closeEvents === 2) libraryCloseResolve();
    });
    assert.equal(closingSource.emit("close"), true);
    assert.equal(closingSource.status, "idle");
    assert.equal(closeEvents, 1);
    let adapterClose;
    const finalMessage = new Promise((resolve, reject) => {
      closingSource.on("error", reject);
      closingSource.on("message", (message) => {
        if (icmpv4EchoSequence(message) !== 13) return;
        adapterClose = closingSource.close();
        resolve();
      });
    });
    closingSource.start();
    await setImmediate();
    await socket.send(createEchoRequest(13), "127.0.0.1");
    await withDeadline(finalMessage, "closing IPv4 event");
    await withDeadline(libraryCloseEvent, "IPv4 close event");
    await adapterClose;
    assert.equal(closeEvents, 2);
    assert.equal(closingSource.status, "closed");
    assert.equal(socket.status, "closed");
  },
);

test(
  "delivers repeated IPv6 message events with ancillary metadata",
  { skip: !privilegedTestsEnabled, timeout: 5_000 },
  async () => {
    const socket = await RawSocket.open({
      family: "ipv6",
      protocol: IPPROTO_ICMPV6,
    });
    try {
      await socket.bind({ family: "ipv6", address: "::1" });
      await socket.setOption("receivePacketInfo", true);
      await socket.setOption("receiveHopLimit", true);
      const source = new RawSocketEventEmitter(socket);
      const messages = collectMessages(source, 3, (message) => {
        const sequence = icmpv6EchoSequence(message);
        return sequence !== undefined && sequence >= 21 && sequence <= 23;
      });
      source.start();
      await setImmediate();
      for (const sequence of [21, 22, 23]) {
        await socket.sendMessage({
          data: createEchoRequestV6(sequence),
          destination: { family: "ipv6", address: "::1" },
        });
      }
      const delivered = await withDeadline(messages, "IPv6 event delivery");
      assert.deepEqual(delivered.map(icmpv6EchoSequence), [21, 22, 23]);
      for (const message of delivered) {
        assert.equal(message.source?.family, "ipv6");
        assert.ok(
          message.control.some((control) => control.kind === "ipv6PacketInfo"),
        );
        assert.ok(
          message.control.some((control) => control.kind === "ipv6HopLimit"),
        );
      }
      await source.pause();
      await source.detach();
    } finally {
      await socket.close();
    }
  },
);

test(
  "keeps normal and Linux error-queue event lanes independent",
  { skip: !privilegedTestsEnabled, timeout: 5_000 },
  async () => {
    const socket = await RawSocket.open({ protocol: IPPROTO_UDP });
    const udpReceiver = createDatagramSocket("udp4");
    let udpReceiverOpen = true;
    try {
      await socket.bind("127.0.0.1");
      await socket.setOption("receiveErrors", true);
      await new Promise((resolve, reject) => {
        udpReceiver.once("error", reject);
        udpReceiver.bind(49_271, "127.0.0.1", resolve);
      });

      const directErrorAbort = new globalThis.AbortController();
      const directErrorReceive = socket.receiveMessage({
        flags: ["errorQueue"],
        signal: directErrorAbort.signal,
      });
      const independentNormalLane = new RawSocketEventEmitter(socket);
      assert.throws(
        () => new RawSocketEventEmitter(socket, { errorQueue: true }),
        { code: "ERR_RECEIVER_ACTIVE" },
      );
      await independentNormalLane.detach();
      directErrorAbort.abort();
      await assert.rejects(directErrorReceive, { code: "ERR_ABORTED" });

      const normal = new RawSocketEventEmitter(socket);
      const errors = new RawSocketEventEmitter(socket, { errorQueue: true });
      assert.throws(() => new RawSocketEventEmitter(socket), {
        code: "ERR_RECEIVER_ACTIVE",
      });
      assert.throws(
        () => new RawSocketEventEmitter(socket, { errorQueue: true }),
        { code: "ERR_RECEIVER_ACTIVE" },
      );
      await assert.rejects(socket.receiveMessage({ flags: ["errorQueue"] }), {
        code: "ERR_RECEIVER_ACTIVE",
      });

      const sourcePort = 45_271;
      const destinationPort = 49_271;
      const normalMessage = firstMessage(normal, (message) =>
        isIpv4UdpPorts(message, sourcePort, destinationPort),
      );
      const errorMessage = firstMessage(
        errors,
        (message) =>
          message.flags.includes("errorQueue") &&
          message.control.some(
            (control) => control.kind === "ipv4ExtendedError",
          ),
      );
      normal.start();
      errors.start();
      await setImmediate();
      await socket.sendMessage({
        data: createUdpHeader(sourcePort, destinationPort),
        destination: { family: "ipv4", address: "127.0.0.1" },
      });
      const outbound = await withDeadline(normalMessage, "normal UDP delivery");

      await new Promise((resolve) => udpReceiver.close(resolve));
      udpReceiverOpen = false;
      await socket.sendMessage({
        data: createUdpHeader(sourcePort, destinationPort),
        destination: { family: "ipv4", address: "127.0.0.1" },
      });

      const queuedError = await withDeadline(
        errorMessage,
        "error-queue delivery",
      );
      assert.equal(outbound.flags.includes("errorQueue"), false);
      assert.equal(queuedError.flags.includes("errorQueue"), true);
      const extended = queuedError.control.find(
        (control) => control.kind === "ipv4ExtendedError",
      );
      assert.equal(extended?.errno, 111);
      assert.equal(extended?.type, 3);
      assert.equal(extended?.code, 3);

      const siblingClose = once(errors, "close");
      await normal.close();
      await withDeadline(siblingClose, "shared error-lane close");
      assert.equal(normal.status, "closed");
      assert.equal(errors.status, "closed");
    } finally {
      if (udpReceiverOpen) udpReceiver.close();
      await socket.close();
    }
  },
);

test(
  "cleans up event sources during cooperative and forced Worker teardown",
  { skip: !privilegedTestsEnabled, timeout: 5_000 },
  async () => {
    const externallyClosedSocket = await RawSocket.open({ protocol: 253 });
    const externallyClosedSource = new RawSocketEventEmitter(
      externallyClosedSocket,
    );
    const externalCloseEvent = once(externallyClosedSource, "close");
    externallyClosedSource.start();
    const rawClose = externallyClosedSocket.close();
    const adapterClose = externallyClosedSource.close();
    assert.equal(adapterClose, externallyClosedSource.close());
    await rawClose;
    await adapterClose;
    await withDeadline(externalCloseEvent, "external raw-socket close event");
    assert.equal(externallyClosedSource.status, "closed");

    const retainedSocket = await RawSocket.open({ protocol: 253 });
    new RawSocketEventEmitter(retainedSocket);
    await assert.rejects(retainedSocket.receiveMessage(), {
      code: "ERR_RECEIVER_ACTIVE",
    });
    await retainedSocket.close();

    const fixture = new URL("./fixtures/event-worker.mjs", import.meta.url);
    const cooperative = new Worker(fixture);
    const cooperativeExit = once(cooperative, "exit");
    const [ready] = await withDeadline(
      once(cooperative, "message"),
      "cooperative Worker startup",
    );
    assert.deepEqual(ready, { ready: true });
    cooperative.postMessage("close");
    const [closed] = await withDeadline(
      once(cooperative, "message"),
      "cooperative Worker close",
    );
    assert.deepEqual(closed, { closed: true });
    assert.equal((await cooperativeExit)[0], 0);

    const forced = new Worker(fixture);
    const [forcedReady] = await withDeadline(
      once(forced, "message"),
      "forced Worker startup",
    );
    assert.deepEqual(forcedReady, { ready: true });
    assert.equal(await forced.terminate(), 1);
  },
);

function createEchoRequest(sequence = 1) {
  const packet = Buffer.alloc(12);
  packet[0] = 8;
  packet.writeUInt16BE(0x4e52, 4);
  packet.writeUInt16BE(sequence, 6);
  packet.writeUInt32BE(0x6e6f6465, 8);
  packet.writeUInt16BE(internetChecksum(packet), 2);
  return packet;
}

function createEchoRequestV6(sequence = 1) {
  const packet = Buffer.alloc(12);
  packet[0] = 128;
  packet.writeUInt16BE(0x4e52, 4);
  packet.writeUInt16BE(sequence, 6);
  packet.writeUInt32BE(0x76366e72, 8);
  return packet;
}

function createUdpHeader(sourcePort, destinationPort) {
  const packet = Buffer.alloc(8);
  packet.writeUInt16BE(sourcePort, 0);
  packet.writeUInt16BE(destinationPort, 2);
  packet.writeUInt16BE(packet.length, 4);
  return packet;
}

function icmpv4EchoSequence(message) {
  if (message.data.length < 28 || message.data[9] !== IPPROTO_ICMP) {
    return undefined;
  }
  const headerLength = (message.data[0] & 0x0f) * 4;
  if (
    headerLength < 20 ||
    message.data.length < headerLength + 8 ||
    message.data[headerLength] !== 8 ||
    message.data.readUInt16BE(headerLength + 4) !== 0x4e52
  ) {
    return undefined;
  }
  return message.data.readUInt16BE(headerLength + 6);
}

function icmpv6EchoSequence(message) {
  if (
    message.data.length < 8 ||
    message.data[0] !== 128 ||
    message.data.readUInt16BE(4) !== 0x4e52
  ) {
    return undefined;
  }
  return message.data.readUInt16BE(6);
}

function isIpv4UdpPorts(message, sourcePort, destinationPort) {
  if (message.data.length < 28 || message.data[9] !== IPPROTO_UDP) return false;
  const headerLength = (message.data[0] & 0x0f) * 4;
  return (
    message.data.length >= headerLength + 8 &&
    message.data.readUInt16BE(headerLength) === sourcePort &&
    message.data.readUInt16BE(headerLength + 2) === destinationPort
  );
}

function firstMessage(source, predicate) {
  return new Promise((resolve, reject) => {
    source.on("error", reject);
    source.on("message", (message) => {
      if (predicate(message)) resolve(message);
    });
  });
}

function collectMessages(source, count, predicate = () => true) {
  return new Promise((resolve, reject) => {
    const messages = [];
    source.on("error", reject);
    source.on("message", (message) => {
      if (!predicate(message)) return;
      messages.push(message);
      if (messages.length === count) resolve(messages);
    });
  });
}

async function withDeadline(promise, description) {
  return Promise.race([
    promise,
    delay(2_000, undefined, { ref: false }).then(() => {
      throw new Error(`timed out waiting for ${description}`);
    }),
  ]);
}

function internetChecksum(bytes) {
  let sum = 0;
  for (let offset = 0; offset < bytes.length; offset += 2) {
    sum += bytes.readUInt16BE(offset);
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  return ~sum & 0xffff;
}
