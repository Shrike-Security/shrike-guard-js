/**
 * Unit tests for Shrike Guard configuration.
 */

import {
  FailMode,
  DEFAULT_ENDPOINT,
  DEFAULT_SCAN_TIMEOUT,
  DEFAULT_FAIL_MODE,
  SDK_NAME,
  SDK_USER_AGENT,
} from '../../src/config';

describe('FailMode', () => {
  it('should have OPEN and CLOSED values', () => {
    expect(FailMode.OPEN).toBe('open');
    expect(FailMode.CLOSED).toBe('closed');
  });

  it('should be usable as string values', () => {
    const mode: FailMode = FailMode.OPEN;
    expect(mode === 'open').toBe(true);
  });
});

describe('Configuration Constants', () => {
  it('should have correct default endpoint', () => {
    expect(DEFAULT_ENDPOINT).toBe(
      'https://api.shrikesecurity.com/agent'
    );
  });

  it('should have correct default timeout', () => {
    expect(DEFAULT_SCAN_TIMEOUT).toBe(10000);
  });

  it('should default to fail-open mode', () => {
    expect(DEFAULT_FAIL_MODE).toBe(FailMode.OPEN);
  });

  it('should have SDK identification', () => {
    expect(SDK_NAME).toBe('typescript');
    expect(SDK_USER_AGENT).toBe('shrike-guard-typescript');
  });
});
