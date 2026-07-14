import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";

import { ETH_P_ALL, RawSocket, interfaceIndex } from "../dist/index.js";

const enabled = process.env.NODENETRAW_PROTOCOL_NAMESPACE_TESTS === "1";

test(
  "captures Phase 17 ARP, IPv4, and IPv6 builder output byte-for-byte",
  { skip: !enabled, timeout: 10_000 },
  async () => {
    const vectors = parseVectors(process.env.NODENETRAW_PROTOCOL_VECTORS);
    assert.deepEqual(
      vectors.map((vector) => vector.name),
      ["arp", "ipv4", "ipv6"],
    );

    const senderIndex = interfaceIndex("nr-veth0");
    const receiverIndex = interfaceIndex("nr-veth1");
    const receiver = await RawSocket.open({
      family: "packet",
      mode: "raw",
      protocol: ETH_P_ALL,
    });
    const sender = await RawSocket.open({
      family: "packet",
      mode: "raw",
      protocol: ETH_P_ALL,
    });
    try {
      await receiver.bind({
        family: "packet",
        interfaceIndex: receiverIndex,
        protocol: ETH_P_ALL,
      });
      await sender.bind({
        family: "packet",
        interfaceIndex: senderIndex,
        protocol: ETH_P_ALL,
      });

      for (const vector of vectors) {
        const capture = receiveExact(receiver, vector.bytes);
        const bytesSent = await sender.sendMessage({
          data: vector.bytes,
          destination: {
            family: "packet",
            interfaceIndex: senderIndex,
            protocol: vector.protocol,
            address: vector.bytes.subarray(0, 6),
          },
        });
        assert.equal(bytesSent, vector.bytes.byteLength);
        const message = await capture;
        assert.equal(message.source?.family, "packet");
        assert.equal(message.source?.interfaceIndex, receiverIndex);
        assert.equal(message.source?.protocol, vector.protocol);
        assert.deepEqual(message.data, vector.bytes, vector.name);
      }
    } finally {
      await sender.close();
      await receiver.close();
    }
  },
);

function parseVectors(value) {
  assert.ok(value, "the protocol vector generator did not produce output");
  return value
    .trim()
    .split("\n")
    .map((line) => {
      const [name, protocolText, hex, ...extra] = line.trim().split(/\s+/u);
      assert.equal(extra.length, 0, `invalid vector line: ${line}`);
      assert.match(name, /^(?:arp|ipv4|ipv6)$/u);
      assert.match(protocolText, /^\d+$/u);
      assert.match(hex, /^(?:[\da-f]{2})+$/u);
      const protocol = Number(protocolText);
      assert.ok(
        Number.isInteger(protocol) && protocol >= 0 && protocol <= 0xffff,
      );
      return { name, protocol, bytes: Buffer.from(hex, "hex") };
    });
}

async function receiveExact(socket, expected) {
  const signal = globalThis.AbortSignal.timeout(5_000);
  for (;;) {
    const message = await socket.receiveMessage({
      dataCapacity: 65_535,
      signal,
    });
    if (message.data.equals(expected)) return message;
  }
}
