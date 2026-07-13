import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { memoryUsage, stdout } from "node:process";
import { setImmediate } from "node:timers/promises";

import {
  IPPROTO_RAW,
  RawSocket,
  RawSocketEventEmitter,
} from "../dist/index.js";

const ITERATIONS = 256;
const LIFECYCLE_CYCLES = 4;

async function cycle(index) {
  const socket = await RawSocket.open({ protocol: IPPROTO_RAW });
  let source = new RawSocketEventEmitter(socket);
  source.on("error", (error) => {
    throw error;
  });
  const sameTurnPause = source.start().pause();
  source.resume();
  await sameTurnPause;
  await setImmediate();
  for (let lifecycle = 0; lifecycle < LIFECYCLE_CYCLES; lifecycle += 1) {
    source.start();
    await setImmediate();
    const firstPause = source.pause();
    assert.equal(firstPause, source.pause());
    await firstPause;
    assert.equal(source.status, "paused");
    source.resume();
  }

  if (index % 2 === 0) {
    await source.pause();
    const detached = await source.detach();
    assert.equal(detached, socket);
    source = new RawSocketEventEmitter(socket);
  }
  await source.close();
  assert.equal(source.status, "closed");
}

await cycle(-1);
await setImmediate();
const descriptorsBefore = readdirSync("/proc/self/fd").length;
const rssBefore = memoryUsage.rss();

for (let index = 0; index < ITERATIONS; index += 1) await cycle(index);
await setImmediate();

const descriptorsAfter = readdirSync("/proc/self/fd").length;
const rssAfter = memoryUsage.rss();
assert.equal(descriptorsAfter, descriptorsBefore);
assert.ok(rssAfter - rssBefore < 32 * 1024 * 1024);

stdout.write(
  `${JSON.stringify({
    iterations: ITERATIONS,
    sameTurnCyclesPerIteration: 1,
    lifecycleCyclesPerIteration: LIFECYCLE_CYCLES,
    descriptorsBefore,
    descriptorsAfter,
    rssDeltaBytes: rssAfter - rssBefore,
  })}\n`,
);
