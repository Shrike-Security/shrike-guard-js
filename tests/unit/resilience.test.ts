/**
 * Tests for src/resilience.ts — CircuitBreaker + retryWithBackoff.
 *
 * Mirrors the semantics verified by the Python resilience tests. Keep
 * parity when either module changes — SDK parity is a launch
 * requirement and any drift in failure semantics will surface as
 * different customer outage behavior between languages.
 */

import {
  CircuitBreaker,
  CircuitOpenError,
  CircuitState,
  retryWithBackoff,
} from '../../src/resilience';

describe('CircuitBreaker', () => {
  describe('CLOSED state', () => {
    it('starts in CLOSED', () => {
      const cb = new CircuitBreaker();
      expect(cb.state).toBe(CircuitState.CLOSED);
    });

    it('passes successful calls through untouched', async () => {
      const cb = new CircuitBreaker();
      const result = await cb.execute(() => 42);
      expect(result).toBe(42);
      expect(cb.state).toBe(CircuitState.CLOSED);
    });

    it('does not open until failureThreshold consecutive failures', async () => {
      const cb = new CircuitBreaker({ failureThreshold: 3 });
      for (let i = 0; i < 2; i++) {
        await expect(cb.execute(() => { throw new Error('fail'); })).rejects.toThrow('fail');
      }
      // Under threshold — still CLOSED.
      expect(cb.state).toBe(CircuitState.CLOSED);
    });

    it('opens after failureThreshold consecutive failures', async () => {
      const cb = new CircuitBreaker({ failureThreshold: 3 });
      for (let i = 0; i < 3; i++) {
        await expect(cb.execute(() => { throw new Error('fail'); })).rejects.toThrow('fail');
      }
      expect(cb.state).toBe(CircuitState.OPEN);
    });

    it('resets failure count on a single success', async () => {
      const cb = new CircuitBreaker({ failureThreshold: 3 });
      await expect(cb.execute(() => { throw new Error('a'); })).rejects.toThrow();
      await expect(cb.execute(() => { throw new Error('b'); })).rejects.toThrow();
      await cb.execute(() => 'ok');
      // Next failure should not trip the breaker — counter reset.
      await expect(cb.execute(() => { throw new Error('c'); })).rejects.toThrow();
      expect(cb.state).toBe(CircuitState.CLOSED);
    });
  });

  describe('OPEN state', () => {
    it('rejects requests with CircuitOpenError when open', async () => {
      const cb = new CircuitBreaker({ failureThreshold: 1 });
      await expect(cb.execute(() => { throw new Error('trip'); })).rejects.toThrow();
      // Now open — the next execute must fail fast without invoking fn.
      let invoked = false;
      await expect(
        cb.execute(() => {
          invoked = true;
          return 'nope';
        }),
      ).rejects.toBeInstanceOf(CircuitOpenError);
      expect(invoked).toBe(false);
    });

    it('transitions OPEN → HALF_OPEN after timeout elapses', async () => {
      const cb = new CircuitBreaker({ failureThreshold: 1, timeout: 0.05 });
      await expect(cb.execute(() => { throw new Error('trip'); })).rejects.toThrow();
      expect(cb.state).toBe(CircuitState.OPEN);
      await new Promise((r) => setTimeout(r, 60));
      // After timeout, state reads as HALF_OPEN.
      expect(cb.state).toBe(CircuitState.HALF_OPEN);
    });
  });

  describe('HALF_OPEN state', () => {
    it('closes after successThreshold consecutive successes', async () => {
      const cb = new CircuitBreaker({
        failureThreshold: 1,
        successThreshold: 2,
        timeout: 0.05,
      });
      await expect(cb.execute(() => { throw new Error('trip'); })).rejects.toThrow();
      await new Promise((r) => setTimeout(r, 60));

      await cb.execute(() => 'probe-1');
      await cb.execute(() => 'probe-2');
      expect(cb.state).toBe(CircuitState.CLOSED);
    });

    it('reopens on failure during HALF_OPEN', async () => {
      const cb = new CircuitBreaker({
        failureThreshold: 1,
        successThreshold: 2,
        timeout: 0.05,
      });
      await expect(cb.execute(() => { throw new Error('trip'); })).rejects.toThrow();
      await new Promise((r) => setTimeout(r, 60));

      await expect(cb.execute(() => { throw new Error('probe-fails'); })).rejects.toThrow();
      expect(cb.state).toBe(CircuitState.OPEN);
    });

    it('caps concurrent probes at maxHalfOpenRequests', async () => {
      const cb = new CircuitBreaker({
        failureThreshold: 1,
        successThreshold: 5, // never close — stays half-open
        timeout: 0.05,
        maxHalfOpenRequests: 2,
      });
      await expect(cb.execute(() => { throw new Error('trip'); })).rejects.toThrow();
      await new Promise((r) => setTimeout(r, 60));

      // Fire off 4 probes; 2 should be admitted and 2 should be rejected.
      // Each probe returns synchronously so we don't actually race — we're
      // verifying the counter cap on entry.
      await cb.execute(() => 'p1');
      await cb.execute(() => 'p2');
      await expect(cb.execute(() => 'p3')).rejects.toBeInstanceOf(CircuitOpenError);
    });
  });

  describe('onStateChange callback', () => {
    it('fires on transitions', async () => {
      const transitions: Array<[CircuitState, CircuitState]> = [];
      const cb = new CircuitBreaker({
        failureThreshold: 1,
        timeout: 0.05,
        onStateChange: (from, to) => transitions.push([from, to]),
      });
      await expect(cb.execute(() => { throw new Error('trip'); })).rejects.toThrow();
      expect(transitions).toEqual([[CircuitState.CLOSED, CircuitState.OPEN]]);
    });

    it('swallows errors thrown by the callback', async () => {
      const cb = new CircuitBreaker({
        failureThreshold: 1,
        onStateChange: () => { throw new Error('callback boom'); },
      });
      // Must not surface the callback error to the caller.
      await expect(cb.execute(() => { throw new Error('trip'); })).rejects.toThrow('trip');
      expect(cb.state).toBe(CircuitState.OPEN);
    });
  });
});

describe('retryWithBackoff', () => {
  it('returns the value on first-attempt success', async () => {
    const result = await retryWithBackoff(() => 42);
    expect(result).toBe(42);
  });

  it('retries up to maxAttempts on retryable failures', async () => {
    let attempts = 0;
    const result = await retryWithBackoff(
      () => {
        attempts += 1;
        if (attempts < 3) throw new Error('flaky');
        return 'done';
      },
      { maxAttempts: 3, initialBackoff: 0.001, maxBackoff: 0.001 },
    );
    expect(result).toBe('done');
    expect(attempts).toBe(3);
  });

  it('throws the last error after exhausting attempts', async () => {
    let attempts = 0;
    await expect(
      retryWithBackoff(
        () => {
          attempts += 1;
          throw new Error(`attempt-${attempts}`);
        },
        { maxAttempts: 3, initialBackoff: 0.001 },
      ),
    ).rejects.toThrow('attempt-3');
    expect(attempts).toBe(3);
  });

  it('does not retry CircuitOpenError by default', async () => {
    let attempts = 0;
    await expect(
      retryWithBackoff(
        () => {
          attempts += 1;
          throw new CircuitOpenError();
        },
        { maxAttempts: 5, initialBackoff: 0.001 },
      ),
    ).rejects.toBeInstanceOf(CircuitOpenError);
    // No retry — retrying past an open circuit defeats its purpose.
    expect(attempts).toBe(1);
  });

  it('respects a custom isRetryable predicate', async () => {
    let attempts = 0;
    class NoRetry extends Error {}
    await expect(
      retryWithBackoff(
        () => {
          attempts += 1;
          throw new NoRetry('bail');
        },
        {
          maxAttempts: 5,
          initialBackoff: 0.001,
          isRetryable: (err) => !(err instanceof NoRetry),
        },
      ),
    ).rejects.toBeInstanceOf(NoRetry);
    expect(attempts).toBe(1);
  });
});
