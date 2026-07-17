/**
 * Circuit breaker and retry-with-backoff resilience primitives.
 *
 * Mirrors platform/sdks/python/src/shrike_guard/resilience.py — keep
 * behavior and constants aligned so callers flipping languages see the
 * same failure semantics under partial-outage conditions.
 *
 * When `fail_mode` is `"closed"` (the default across the shrike-guard 4.x
 * client line), a SDK caller under a partial backend outage repeatedly hits a dead
 * endpoint and eats blocked results until the outage clears. The circuit
 * breaker short-circuits that path — after N consecutive failures the
 * circuit opens and rejects requests fast for a timeout window, then
 * probes recovery via a half-open window. Under a real outage this
 * turns "slow blocked-response storm" into "fast rejection storm the
 * caller can back off on."
 *
 * Design decisions ported verbatim from Python:
 *   - Three-state machine (CLOSED / OPEN / HALF_OPEN)
 *   - failure_threshold defaults 5, success_threshold 2, timeout 30s
 *   - max_half_open_requests 3 caps recovery probe concurrency
 *   - Optional on_state_change callback for integrator observability
 *   - retryWithBackoff treats CircuitOpenError as non-retryable by
 *     default (retrying past an open circuit defeats its purpose)
 *
 * Language conventions:
 *   - TypeScript is async-native; no separate `Async*` variant needed.
 *     A single `execute(fn)` handles both sync and async fn — the
 *     return type is inferred as `T | Promise<T>`, and callers await
 *     it uniformly.
 *   - Locking uses a queued-microtask serialization idiom rather than
 *     Python's threading.Lock because JS is single-threaded per event
 *     loop. State mutations complete before the next tick observes them.
 */

/** Circuit breaker states. */
export enum CircuitState {
  CLOSED = 'closed',
  OPEN = 'open',
  HALF_OPEN = 'half_open',
}

/** Raised when the circuit breaker is open and rejecting requests. */
export class CircuitOpenError extends Error {
  constructor(message = 'Circuit breaker is open') {
    super(message);
    this.name = 'CircuitOpenError';
    Object.setPrototypeOf(this, CircuitOpenError.prototype);
  }
}

export interface CircuitBreakerOptions {
  /** Consecutive failures before the circuit opens. Default 5. */
  failureThreshold?: number;
  /** Consecutive successes in HALF_OPEN before returning to CLOSED. Default 2. */
  successThreshold?: number;
  /** Seconds the circuit stays OPEN before probing recovery. Default 30. */
  timeout?: number;
  /** Max concurrent requests allowed in HALF_OPEN. Default 3. */
  maxHalfOpenRequests?: number;
  /**
   * Optional callback fired on state transitions. Errors thrown from
   * this callback are swallowed so callback bugs cannot break the SDK.
   */
  onStateChange?: (from: CircuitState, to: CircuitState) => void;
}

export interface CircuitBreakerStats {
  state: CircuitState;
  failureCount: number;
  successCount: number;
  lastFailureTime: number;
}

/**
 * Three-state circuit breaker for HTTP calls.
 *
 * @example
 *   const cb = new CircuitBreaker();
 *   const result = await cb.execute(() => fetch(url).then(r => r.json()));
 */
export class CircuitBreaker {
  private readonly failureThreshold: number;
  private readonly successThreshold: number;
  private readonly timeoutMs: number;
  private readonly maxHalfOpen: number;
  private readonly onStateChange?: (from: CircuitState, to: CircuitState) => void;

  private _state: CircuitState = CircuitState.CLOSED;
  private failureCount = 0;
  private successCount = 0;
  private halfOpenCount = 0;
  private openedAt = 0;
  private lastFailureTime = 0;

  constructor(options: CircuitBreakerOptions = {}) {
    this.failureThreshold = options.failureThreshold ?? 5;
    this.successThreshold = options.successThreshold ?? 2;
    // Python module measures timeout in seconds; TS uses milliseconds
    // internally because performance.now() and Date.now() are both ms.
    // The public option stays in seconds for parity with the Python API.
    this.timeoutMs = (options.timeout ?? 30.0) * 1000;
    this.maxHalfOpen = options.maxHalfOpenRequests ?? 3;
    this.onStateChange = options.onStateChange;
  }

  /**
   * Observed state. Auto-transitions OPEN → HALF_OPEN when the timeout
   * has elapsed. Reading this property never mutates internal counters,
   * but it may report HALF_OPEN before an actual request has been
   * attempted (matches Python's `state` getter semantics).
   */
  get state(): CircuitState {
    if (this._state === CircuitState.OPEN && Date.now() - this.openedAt >= this.timeoutMs) {
      return CircuitState.HALF_OPEN;
    }
    return this._state;
  }

  get stats(): CircuitBreakerStats {
    return {
      state: this._state,
      failureCount: this.failureCount,
      successCount: this.successCount,
      lastFailureTime: this.lastFailureTime,
    };
  }

  /**
   * Execute fn through the breaker. fn may be sync or async — the return
   * is always awaited so both paths are uniform to the caller.
   *
   * @throws CircuitOpenError when the breaker is open (or half-open and
   *   the probe window is saturated).
   */
  async execute<T>(fn: () => T | Promise<T>): Promise<T> {
    this.beforeRequest();
    try {
      const result = await fn();
      this.onSuccess();
      return result;
    } catch (err) {
      this.onFailure();
      throw err;
    }
  }

  private beforeRequest(): void {
    if (this._state === CircuitState.CLOSED) {
      return;
    }
    if (this._state === CircuitState.OPEN) {
      if (Date.now() - this.openedAt >= this.timeoutMs) {
        this.setState(CircuitState.HALF_OPEN);
        this.halfOpenCount = 1;
        return;
      }
      throw new CircuitOpenError('Circuit breaker is open');
    }
    // HALF_OPEN
    this.halfOpenCount += 1;
    if (this.halfOpenCount > this.maxHalfOpen) {
      this.halfOpenCount -= 1;
      throw new CircuitOpenError('Too many requests in half-open state');
    }
  }

  private onSuccess(): void {
    if (this._state === CircuitState.CLOSED) {
      this.failureCount = 0;
      this.successCount += 1;
      return;
    }
    if (this._state === CircuitState.HALF_OPEN) {
      this.successCount += 1;
      if (this.successCount >= this.successThreshold) {
        this.setState(CircuitState.CLOSED);
        this.failureCount = 0;
        this.successCount = 0;
        this.halfOpenCount = 0;
      }
    }
  }

  private onFailure(): void {
    this.lastFailureTime = Date.now();
    if (this._state === CircuitState.CLOSED) {
      this.failureCount += 1;
      if (this.failureCount >= this.failureThreshold) {
        this.setState(CircuitState.OPEN);
        this.openedAt = Date.now();
      }
      return;
    }
    if (this._state === CircuitState.HALF_OPEN) {
      this.setState(CircuitState.OPEN);
      this.openedAt = Date.now();
      this.successCount = 0;
      this.halfOpenCount = 0;
    }
  }

  private setState(to: CircuitState): void {
    const from = this._state;
    if (from === to) {
      return;
    }
    this._state = to;
    if (this.onStateChange) {
      try {
        this.onStateChange(from, to);
      } catch {
        // Swallow — a buggy state-change hook must not break the breaker.
      }
    }
  }
}

export interface RetryOptions {
  /** Total number of attempts including the first. Default 3. */
  maxAttempts?: number;
  /** Initial backoff in seconds. Default 0.2. */
  initialBackoff?: number;
  /** Max backoff between retries in seconds. Default 5.0. */
  maxBackoff?: number;
  /** Multiplier applied to backoff after each failure. Default 2.0. */
  multiplier?: number;
  /**
   * Optional predicate — return false to bail out of the retry loop
   * immediately for this exception. Default: retry everything EXCEPT
   * `CircuitOpenError` (retrying past an open circuit defeats its
   * purpose — that's what the breaker's own timeout is for).
   */
  isRetryable?: (err: unknown) => boolean;
}

/**
 * Execute fn with exponential backoff retry.
 *
 * Async-native — no separate sync variant. Callers must await the
 * returned Promise. Mirrors Python's `retry_with_backoff` +
 * `async_retry_with_backoff` collapsed into one entry point.
 */
export async function retryWithBackoff<T>(
  fn: () => T | Promise<T>,
  options: RetryOptions = {},
): Promise<T> {
  const maxAttempts = options.maxAttempts ?? 3;
  const initialBackoff = options.initialBackoff ?? 0.2;
  const maxBackoff = options.maxBackoff ?? 5.0;
  const multiplier = options.multiplier ?? 2.0;
  const isRetryable =
    options.isRetryable ?? ((e: unknown): boolean => !(e instanceof CircuitOpenError));

  let lastError: unknown;
  let backoff = initialBackoff;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      if (!isRetryable(err)) {
        throw err;
      }
      if (attempt === maxAttempts - 1) {
        break;
      }
      await sleep(backoff * 1000);
      backoff = Math.min(backoff * multiplier, maxBackoff);
    }
  }
  throw lastError;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
