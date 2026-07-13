import { EventEmitter, errorMonitor } from "node:events";
import { setImmediate } from "node:timers";

import { EventReceiveController } from "../../dist/internal/event-controller.js";

const mode = process.argv[2];
const events = new EventEmitter();
let receives = 0;
let controller;
let closePromise;
let errorMonitored = false;

function report(channel, value) {
  process.stdout.write(
    `${JSON.stringify({ channel, status: controller.status, value })}\n`,
  );
  process.exit(0);
}

const driver = {
  receive() {
    receives += 1;
    if (receives > 1) return new Promise(() => undefined);
    if (
      mode === "missing-error" ||
      mode === "error-listener-throw" ||
      mode === "monitor-only-error"
    ) {
      return Promise.reject({ kind: "system", marker: "receive-failure" });
    }
    return Promise.resolve("message");
  },
  close() {
    return Promise.resolve();
  },
  releaseClaim() {
    return undefined;
  },
  removeCloseObserver() {
    return undefined;
  },
  detachValue() {
    return "socket";
  },
  dispatchMessage(message) {
    events.emit("message", message);
  },
  dispatchError(error) {
    events.emit("error", error);
  },
  dispatchClose() {
    events.emit("close");
  },
  invalidState(operation) {
    return new Error(`invalid ${operation}`);
  },
  socketClosed(operation) {
    return new Error(`closed ${operation}`);
  },
  isAborted() {
    return false;
  },
  isSocketClosed() {
    return false;
  },
  isReactorClosed() {
    return false;
  },
};

if (mode === "message-throw") {
  events.on("message", () => {
    throw new Error("listener-threw");
  });
  process.once("uncaughtException", (error) => {
    report("uncaughtException", error.message);
  });
} else if (mode === "missing-error") {
  process.once("uncaughtException", (error) => {
    report("uncaughtException", error.context?.marker ?? error.marker);
  });
} else if (mode === "default-rejection") {
  events.on("message", async () => {
    throw "listener-rejected";
  });
  process.once("unhandledRejection", (reason) => {
    report("unhandledRejection", reason);
  });
} else if (mode === "captured-rejection") {
  EventEmitter.captureRejections = true;
  const capturedEvents = new EventEmitter();
  driver.dispatchMessage = (message) => {
    capturedEvents.emit("message", message);
  };
  driver.dispatchError = (error) => {
    capturedEvents.emit("error", error);
  };
  capturedEvents.on("message", async () => {
    throw "captured-listener-rejection";
  });
  capturedEvents.on("error", (reason) => {
    report("error", reason);
  });
} else if (mode === "error-listener-throw") {
  events.on("error", () => {
    throw new Error("error-listener-threw");
  });
  process.once("uncaughtException", (error) => {
    report("uncaughtException", error.message);
  });
} else if (mode === "monitor-only-error") {
  events.on(errorMonitor, () => {
    errorMonitored = true;
  });
  process.once("uncaughtException", (error) => {
    report(
      "uncaughtException",
      `${String(errorMonitored)}:${String(error.context?.marker)}`,
    );
  });
} else if (mode === "close-listener-throw") {
  events.on("close", () => {
    throw new Error("close-listener-threw");
  });
  process.once("uncaughtException", (error) => {
    setImmediate(() => {
      void closePromise.then(() => {
        report("uncaughtException", error.message);
      });
    });
  });
} else {
  throw new Error(`unknown mode: ${mode}`);
}

controller = new EventReceiveController(driver);
if (mode === "close-listener-throw") closePromise = controller.close();
else controller.start();
