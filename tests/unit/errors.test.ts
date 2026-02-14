/**
 * Unit tests for Shrike Guard error classes.
 */

import {
  ShrikeError,
  ShrikeScanError,
  ShrikeBlockedError,
  ShrikeConfigError,
} from '../../src/errors';

describe('ShrikeError', () => {
  it('should create an error with message', () => {
    const error = new ShrikeError('Test error');
    expect(error.message).toBe('Test error');
    expect(error.name).toBe('ShrikeError');
    expect(error.details).toEqual({});
  });

  it('should create an error with details', () => {
    const details = { code: 'ERR001', extra: 'info' };
    const error = new ShrikeError('Test error', details);
    expect(error.details).toEqual(details);
  });

  it('should be an instance of Error', () => {
    const error = new ShrikeError('Test');
    expect(error).toBeInstanceOf(Error);
    expect(error).toBeInstanceOf(ShrikeError);
  });
});

describe('ShrikeScanError', () => {
  it('should create a scan error', () => {
    const error = new ShrikeScanError('Scan failed');
    expect(error.message).toBe('Scan failed');
    expect(error.name).toBe('ShrikeScanError');
  });

  it('should be an instance of ShrikeError', () => {
    const error = new ShrikeScanError('Scan failed');
    expect(error).toBeInstanceOf(ShrikeError);
    expect(error).toBeInstanceOf(ShrikeScanError);
  });
});

describe('ShrikeBlockedError', () => {
  it('should create a blocked error with all properties', () => {
    const violations = [{ type: 'sql_injection', pattern: 'DROP TABLE' }];
    const error = new ShrikeBlockedError(
      'Request blocked',
      'sql_injection',
      0.95,
      violations
    );

    expect(error.message).toBe('Request blocked');
    expect(error.name).toBe('ShrikeBlockedError');
    expect(error.threatType).toBe('sql_injection');
    expect(error.confidence).toBe(0.95);
    expect(error.violations).toEqual(violations);
  });

  it('should create a blocked error with minimal properties', () => {
    const error = new ShrikeBlockedError('Request blocked');
    expect(error.threatType).toBeUndefined();
    expect(error.confidence).toBeUndefined();
    expect(error.violations).toEqual([]);
  });

  it('should include properties in details', () => {
    const error = new ShrikeBlockedError('Blocked', 'pii', 0.8, ['ssn']);
    expect(error.details).toEqual({
      threat_type: 'pii',
      confidence: 0.8,
      violations: ['ssn'],
    });
  });
});

describe('ShrikeConfigError', () => {
  it('should create a config error', () => {
    const error = new ShrikeConfigError('Invalid API key');
    expect(error.message).toBe('Invalid API key');
    expect(error.name).toBe('ShrikeConfigError');
  });

  it('should be an instance of ShrikeError', () => {
    const error = new ShrikeConfigError('Config issue');
    expect(error).toBeInstanceOf(ShrikeError);
    expect(error).toBeInstanceOf(ShrikeConfigError);
  });
});
