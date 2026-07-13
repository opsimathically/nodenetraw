export type EventControllerStatus =
  | "idle"
  | "running"
  | "pausing"
  | "paused"
  | "detaching"
  | "detached"
  | "closing"
  | "closed";

export interface EventControllerDriver<Message, DetachValue> {
  receive(signal: AbortSignal): Promise<Message>;
  close(): Promise<void>;
  releaseClaim(): void;
  removeCloseObserver(): void;
  detachValue(): DetachValue;
  dispatchMessage(message: Message): void;
  dispatchError(error: unknown): void;
  dispatchClose(): void;
  invalidState(operation: string): unknown;
  socketClosed(operation: string): unknown;
  isAborted(error: unknown): boolean;
  isSocketClosed(error: unknown): boolean;
  isReactorClosed(error: unknown): boolean;
}

interface Deferred<Value> {
  readonly promise: Promise<Value>;
  resolve(value: Value): void;
  reject(error: unknown): void;
  settled: boolean;
}

function deferred<Value>(): Deferred<Value> {
  let resolvePromise!: (value: Value) => void;
  let rejectPromise!: (error: unknown) => void;
  const result: Deferred<Value> = {
    promise: new Promise<Value>((resolve, reject) => {
      resolvePromise = resolve;
      rejectPromise = reject;
    }),
    resolve(value): void {
      if (result.settled) return;
      result.settled = true;
      resolvePromise(value);
    },
    reject(error): void {
      if (result.settled) return;
      result.settled = true;
      rejectPromise(error);
    },
    settled: false,
  };
  return result;
}

/** Native-free lifecycle and one-turn receive pump used by the public adapter. */
export class EventReceiveController<Message, DetachValue> {
  readonly #driver: EventControllerDriver<Message, DetachValue>;
  #status: EventControllerStatus = "idle";
  #generation = 0;
  // Identity, rather than a boolean, lets a same-turn resume replace a stale
  // queued pump without allowing that stale task to clear the replacement.
  #scheduledPump: symbol | undefined;
  #turnActive = false;
  #turnController: AbortController | undefined;
  #pauseDeferred: Deferred<undefined> | undefined;
  #pausePromise: Promise<void> = Promise.resolve();
  #detachDeferred: Deferred<DetachValue> | undefined;
  #detachPromise: Promise<DetachValue> | undefined;
  #closeDeferred: Deferred<undefined> | undefined;
  #closePromise: Promise<void> | undefined;
  #rawCloseSettled = false;
  #rawCloseRejected = false;
  #rawCloseError: unknown;
  #closeDispatchScheduled = false;
  #claimReleased = false;
  #observerRemoved = false;

  constructor(driver: EventControllerDriver<Message, DetachValue>) {
    this.#driver = driver;
  }

  get status(): EventControllerStatus {
    return this.#status;
  }

  start(): this {
    switch (this.#status) {
      case "idle":
        this.#status = "running";
        this.#schedulePump();
        return this;
      case "running":
        return this;
      case "closing":
      case "closed":
        throw this.#driver.socketClosed("start");
      case "pausing":
      case "paused":
      case "detaching":
      case "detached":
        throw this.#driver.invalidState("start");
    }
  }

  resume(): this {
    switch (this.#status) {
      case "running":
        return this;
      case "paused":
        this.#status = "running";
        this.#schedulePump();
        return this;
      case "closing":
      case "closed":
        throw this.#driver.socketClosed("resume");
      case "idle":
      case "pausing":
      case "detaching":
      case "detached":
        throw this.#driver.invalidState("resume");
    }
  }

  pause(): Promise<void> {
    switch (this.#status) {
      case "idle":
        this.#status = "paused";
        this.#pausePromise = Promise.resolve();
        return this.#pausePromise;
      case "running":
        this.#status = "pausing";
        this.#invalidatePump();
        this.#pauseDeferred = deferred<undefined>();
        this.#pausePromise = this.#pauseDeferred.promise;
        this.#turnController?.abort();
        if (!this.#turnActive) this.#finishQuiescence();
        return this.#pausePromise;
      case "pausing":
      case "paused":
        return this.#pausePromise;
      case "detaching":
      case "detached":
        return Promise.reject(this.#driver.invalidState("pause"));
      case "closing":
      case "closed":
        return Promise.reject(this.#driver.socketClosed("pause"));
    }
  }

  detach(): Promise<DetachValue> {
    switch (this.#status) {
      case "detaching":
      case "detached":
        return this.#requireDetachPromise();
      case "closing":
      case "closed":
        return Promise.reject(this.#driver.socketClosed("detach"));
      case "idle":
      case "paused":
      case "running":
      case "pausing":
        this.#detachDeferred = deferred<DetachValue>();
        this.#detachPromise = this.#detachDeferred.promise;
        this.#status = "detaching";
        this.#invalidatePump();
        this.#turnController?.abort();
        if (!this.#turnActive) this.#finishQuiescence();
        return this.#detachPromise;
    }
  }

  close(): Promise<void> {
    switch (this.#status) {
      case "closing":
      case "closed":
        return this.#requireClosePromise();
      case "detached":
        return Promise.reject(this.#driver.invalidState("close"));
      case "idle":
      case "running":
      case "pausing":
      case "paused":
      case "detaching":
        this.#beginClosing();
        return this.#requireClosePromise();
    }
  }

  /** Synchronous notification made before RawSocket submits native close. */
  notifyClosing(): void {
    if (this.#status === "detached" || this.#status === "closed") return;
    this.#prepareClosePromise();
    this.#status = "closing";
    this.#invalidatePump();
    this.#turnController?.abort();
    if (!this.#turnActive) this.#finishQuiescence();
  }

  /** Asynchronous notification carrying the terminal RawSocket close outcome. */
  notifyCloseOutcome(error?: unknown, rejected = false): void {
    if (this.#status === "detached") return;
    if (this.#rawCloseSettled) return;
    this.#prepareClosePromise();
    if (this.#status !== "closing" && this.#status !== "closed") {
      this.#status = "closing";
      this.#invalidatePump();
      this.#turnController?.abort();
    }
    this.#rawCloseSettled = true;
    this.#rawCloseRejected = rejected;
    this.#rawCloseError = error;
    if (!this.#turnActive) this.#finishQuiescence();
  }

  #beginClosing(): void {
    this.#prepareClosePromise();
    this.#status = "closing";
    this.#invalidatePump();
    this.#turnController?.abort();
    let closeResult: Promise<void>;
    try {
      closeResult = this.#driver.close();
    } catch (error) {
      closeResult = Promise.reject(error);
    }
    void closeResult.then(
      () => {
        this.notifyCloseOutcome();
      },
      (error: unknown) => {
        this.notifyCloseOutcome(error, true);
      },
    );
    if (!this.#turnActive) this.#finishQuiescence();
  }

  #prepareClosePromise(): void {
    if (this.#closeDeferred !== undefined) return;
    this.#closeDeferred = deferred<undefined>();
    this.#closePromise = this.#closeDeferred.promise;
  }

  #schedulePump(): void {
    if (
      this.#status !== "running" ||
      this.#turnActive ||
      this.#scheduledPump !== undefined
    ) {
      return;
    }
    const scheduledPump = Symbol("scheduledEventReceivePump");
    this.#scheduledPump = scheduledPump;
    const generation = this.#generation;
    queueMicrotask(() => {
      if (this.#scheduledPump !== scheduledPump) return;
      this.#scheduledPump = undefined;
      if (
        generation !== this.#generation ||
        this.#status !== "running" ||
        this.#turnActive
      ) {
        return;
      }
      this.#admitTurn();
    });
  }

  #invalidatePump(): void {
    this.#generation += 1;
    this.#scheduledPump = undefined;
  }

  #admitTurn(): void {
    this.#turnActive = true;
    const controller = new AbortController();
    this.#turnController = controller;
    let receive: Promise<Message>;
    try {
      receive = this.#driver.receive(controller.signal);
    } catch (error) {
      receive = Promise.reject(error);
    }
    void receive.then(
      (message) => {
        this.#queueMessage(message);
      },
      (error: unknown) => {
        this.#handleReceiveError(error);
      },
    );
  }

  #queueMessage(message: Message): void {
    queueMicrotask(() => {
      try {
        this.#driver.dispatchMessage(message);
      } finally {
        this.#finishTurn();
      }
    });
  }

  #handleReceiveError(error: unknown): void {
    if (
      this.#driver.isAborted(error) &&
      (this.#status === "pausing" ||
        this.#status === "detaching" ||
        this.#status === "closing")
    ) {
      this.#finishTurn();
      return;
    }

    if (this.#driver.isSocketClosed(error)) {
      if (this.#status !== "closing" && this.#status !== "closed") {
        this.#beginClosing();
      }
      this.#finishTurn();
      return;
    }

    if (this.#driver.isReactorClosed(error)) {
      if (this.#status !== "closing" && this.#status !== "closed") {
        this.#beginClosing();
      }
      this.#queueError(error);
      return;
    }

    if (this.#status === "closing" || this.#status === "closed") {
      this.#queueError(error);
      return;
    }

    if (this.#status === "detaching") {
      // Detach still owns the quiescence boundary when cancellation loses to
      // a real receive failure. Dispatch the failure, then finish detaching.
      this.#queueError(error);
      return;
    }

    if (this.#status === "pausing") {
      // Preserve the existing pause deferred; replacing it would strand the
      // Promise returned before this receive failure won the abort race.
      this.#status = "paused";
    } else {
      this.#status = "paused";
      this.#pauseDeferred = deferred<undefined>();
      this.#pausePromise = this.#pauseDeferred.promise;
    }
    this.#queueError(error);
  }

  #queueError(error: unknown): void {
    queueMicrotask(() => {
      try {
        this.#driver.dispatchError(error);
      } finally {
        this.#finishTurn();
      }
    });
  }

  #finishTurn(): void {
    this.#turnActive = false;
    this.#turnController = undefined;
    this.#finishQuiescence();
  }

  #finishQuiescence(): void {
    if (this.#turnActive) return;

    if (this.#pauseDeferred !== undefined) {
      const pause = this.#pauseDeferred;
      this.#pauseDeferred = undefined;
      pause.resolve(undefined);
      if (this.#status === "pausing") this.#status = "paused";
    }

    if (this.#detachDeferred !== undefined) {
      this.#releaseClaim();
      const detach = this.#detachDeferred;
      this.#detachDeferred = undefined;
      try {
        detach.resolve(this.#driver.detachValue());
      } catch (error) {
        detach.reject(error);
      }
      if (this.#status === "detaching") {
        this.#status = "detached";
        this.#removeObserver();
        return;
      }
    }

    if (this.#status === "closing") {
      this.#releaseClaim();
      this.#maybeDispatchClose();
      return;
    }

    if (this.#status === "running") this.#schedulePump();
  }

  #maybeDispatchClose(): void {
    if (
      !this.#rawCloseSettled ||
      this.#turnActive ||
      this.#closeDispatchScheduled
    ) {
      return;
    }
    this.#closeDispatchScheduled = true;
    this.#status = "closed";
    this.#removeObserver();
    queueMicrotask(() => {
      try {
        this.#driver.dispatchClose();
      } finally {
        const close = this.#requireCloseDeferred();
        if (this.#rawCloseRejected) close.reject(this.#rawCloseError);
        else close.resolve(undefined);
      }
    });
  }

  #releaseClaim(): void {
    if (this.#claimReleased) return;
    this.#claimReleased = true;
    try {
      this.#driver.releaseClaim();
    } catch {
      // Claim release is specified nonthrowing; preserve lifecycle settlement.
    }
  }

  #removeObserver(): void {
    if (this.#observerRemoved) return;
    this.#observerRemoved = true;
    try {
      this.#driver.removeCloseObserver();
    } catch {
      // Observer removal is specified nonthrowing; preserve close settlement.
    }
  }

  #requireDetachPromise(): Promise<DetachValue> {
    if (this.#detachPromise === undefined) {
      throw new Error("event controller detach promise invariant failed");
    }
    return this.#detachPromise;
  }

  #requireClosePromise(): Promise<void> {
    if (this.#closePromise === undefined) {
      throw new Error("event controller close promise invariant failed");
    }
    return this.#closePromise;
  }

  #requireCloseDeferred(): Deferred<undefined> {
    if (this.#closeDeferred === undefined) {
      throw new Error("event controller close settlement invariant failed");
    }
    return this.#closeDeferred;
  }
}
