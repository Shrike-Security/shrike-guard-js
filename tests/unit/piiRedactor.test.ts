/**
 * Unit tests for the PII redactor — roundtrip parity with MCP server.
 */

import {
  redactPII,
  rehydratePII,
  getRedactionSummary,
  updatePIIPatterns,
  getPIIPatternCount,
  PIIPattern,
} from '../../src/piiRedactor';

// Snapshot defaults so tests that mutate _PII_PATTERNS don't pollute siblings.
let defaultPatterns: PIIPattern[];
beforeAll(() => {
  // Trigger a no-op redact to ensure module init has run, then snapshot
  // by re-importing the defaults via a fresh module reference.
  // The simplest cross-test isolation is restoring the canonical default list
  // we reproduce here (matches piiRedactor.ts).
  defaultPatterns = [
    { name: 'aws_key', regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, prefix: 'AWSKEY' },
    { name: 'private_key', regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g, prefix: 'PRIVKEY' },
    {
      name: 'credit_card',
      regex: /\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5}|6(?:011|5[0-9]{2})[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4})\b/g,
      prefix: 'CARD',
    },
    { name: 'ssn', regex: /\b\d{3}-?\d{2}-?\d{4}\b/g, prefix: 'SSN' },
    { name: 'email', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, prefix: 'EMAIL' },
    { name: 'phone', regex: /\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, prefix: 'PHONE' },
    { name: 'api_key', regex: /\b(?:api[_-]?key|apikey|access[_-]?token)[:\s=]+[A-Za-z0-9_\-]{20,}\b/gi, prefix: 'APIKEY' },
    { name: 'medical_record', regex: /\b(?:MRN|Medical Record)[:\s#]*[A-Z0-9]{6,12}\b/gi, prefix: 'MRN' },
    {
      name: 'dob',
      regex: /\b(?:DOB|D\.O\.B\.|Date of Birth|Birth Date)[:\s]+(?:\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}[-/]\d{1,2}[-/]\d{1,2})\b/gi,
      prefix: 'DOB',
    },
    { name: 'bank_account', regex: /\b(?:Account|Acct)[:\s#]*\d{8,17}\b/gi, prefix: 'ACCOUNT' },
    { name: 'routing_number', regex: /\b(?:Routing|ABA)[:\s#]*\d{9}\b/gi, prefix: 'ROUTING' },
    { name: 'ip_address', regex: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, prefix: 'IP' },
    {
      name: 'address',
      regex: /\b\d+\s+[A-Za-z0-9\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr)\b/gi,
      prefix: 'ADDR',
    },
  ];
});

afterEach(() => {
  updatePIIPatterns(defaultPatterns);
});

describe('redactPII', () => {
  it('returns unchanged text when no PII is found', () => {
    const result = redactPII('Hello, this is a normal message.');
    expect(result.piiDetected).toBe(false);
    expect(result.redactedText).toBe('Hello, this is a normal message.');
    expect(result.redactionCount).toBe(0);
    expect(result.redactions).toHaveLength(0);
  });

  it('redacts a single email address', () => {
    const result = redactPII('Contact john@acme.com for details.');
    expect(result.piiDetected).toBe(true);
    expect(result.redactedText).toBe('Contact [EMAIL_1] for details.');
    expect(result.redactionCount).toBe(1);
    expect(result.redactions[0].token).toBe('[EMAIL_1]');
    expect(result.redactions[0].original).toBe('john@acme.com');
    expect(result.redactions[0].type).toBe('email');
  });

  it('redacts multiple emails with unique tokens', () => {
    const result = redactPII('Email john@acme.com and jane@acme.com about the meeting.');
    expect(result.redactedText).toBe('Email [EMAIL_1] and [EMAIL_2] about the meeting.');
    expect(result.redactionCount).toBe(2);
  });

  it('redacts phone numbers', () => {
    const result = redactPII('Call me at 555-123-4567.');
    expect(result.redactedText).toBe('Call me at [PHONE_1].');
    expect(result.redactions[0].type).toBe('phone');
  });

  it('redacts SSN', () => {
    const result = redactPII('My SSN is 123-45-6789.');
    expect(result.redactedText).toBe('My SSN is [SSN_1].');
    expect(result.redactions[0].type).toBe('ssn');
  });

  it('redacts credit card numbers (contiguous)', () => {
    const result = redactPII('Card number: 4111111111111111');
    expect(result.redactedText).toBe('Card number: [CARD_1]');
    expect(result.redactions[0].type).toBe('credit_card');
  });

  it('redacts credit card numbers (hyphenated)', () => {
    const result = redactPII('My card is 4532-8721-0039-4456');
    expect(result.redactedText).toBe('My card is [CARD_1]');
    expect(result.redactions[0].original).toBe('4532-8721-0039-4456');
  });

  it('redacts AWS keys', () => {
    const result = redactPII('Key: AKIAIOSFODNN7EXAMPLE');
    expect(result.redactedText).toBe('Key: [AWSKEY_1]');
    expect(result.redactions[0].type).toBe('aws_key');
  });

  it('redacts IP addresses', () => {
    const result = redactPII('Server at 192.168.1.100');
    expect(result.redactedText).toBe('Server at [IP_1]');
    expect(result.redactions[0].type).toBe('ip_address');
  });

  it('redacts multiple PII types in one text', () => {
    const result = redactPII('Send to john@acme.com at 555-123-4567. SSN: 123-45-6789');
    expect(result.redactionCount).toBe(3);
    const types = result.redactions.map(r => r.type);
    expect(types).toContain('email');
    expect(types).toContain('phone');
    expect(types).toContain('ssn');
  });

  it('handles private key markers', () => {
    const result = redactPII('-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAK...');
    expect(result.redactions[0].type).toBe('private_key');
  });

  it('redacts DOB patterns', () => {
    const result = redactPII('DOB: 01/15/1990');
    expect(result.redactions[0].type).toBe('dob');
  });

  it('redacts street addresses', () => {
    const result = redactPII('Lives at 123 Main Street');
    expect(result.redactions[0].type).toBe('address');
  });
});

describe('rehydratePII', () => {
  it('replaces tokens with original values', () => {
    const redactions = [
      { token: '[EMAIL_1]', original: 'john@acme.com', type: 'email', position: 8 },
    ];
    const result = rehydratePII('Contact [EMAIL_1] for details.', redactions);
    expect(result).toBe('Contact john@acme.com for details.');
  });

  it('handles multiple tokens', () => {
    const redactions = [
      { token: '[EMAIL_1]', original: 'john@acme.com', type: 'email', position: 0 },
      { token: '[EMAIL_2]', original: 'jane@acme.com', type: 'email', position: 20 },
    ];
    const result = rehydratePII(
      'Email [EMAIL_1] and [EMAIL_2] about the meeting.',
      redactions
    );
    expect(result).toBe('Email john@acme.com and jane@acme.com about the meeting.');
  });

  it('handles repeated tokens from LLM output', () => {
    const redactions = [
      { token: '[EMAIL_1]', original: 'john@acme.com', type: 'email', position: 0 },
    ];
    const result = rehydratePII(
      'I sent to [EMAIL_1]. Confirming [EMAIL_1] received it.',
      redactions
    );
    expect(result).toBe('I sent to john@acme.com. Confirming john@acme.com received it.');
  });

  it('returns text unchanged if no redactions', () => {
    expect(rehydratePII('No PII here.', [])).toBe('No PII here.');
  });

  it('roundtrips: redact then rehydrate', () => {
    const original = 'Email john@acme.com and call 555-123-4567.';
    const redacted = redactPII(original);
    const restored = rehydratePII(redacted.redactedText, redacted.redactions);
    expect(restored).toBe(original);
  });
});

describe('getRedactionSummary', () => {
  it('counts PII types', () => {
    const redactions = [
      { token: '[EMAIL_1]', original: 'a@b.com', type: 'email', position: 0 },
      { token: '[EMAIL_2]', original: 'c@d.com', type: 'email', position: 10 },
      { token: '[PHONE_1]', original: '555-1234', type: 'phone', position: 20 },
    ];
    expect(getRedactionSummary(redactions)).toEqual({ email: 2, phone: 1 });
  });

  it('returns empty object for no redactions', () => {
    expect(getRedactionSummary([])).toEqual({});
  });
});

describe('updatePIIPatterns', () => {
  it('reports initial pattern count', () => {
    expect(getPIIPatternCount()).toBeGreaterThan(0);
  });

  it('replaces patterns with custom set', () => {
    const custom = [
      {
        name: 'test_iban',
        regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}[A-Z0-9]{0,16}\b/g,
        prefix: 'IBAN',
      },
    ];
    updatePIIPatterns(custom);
    expect(getPIIPatternCount()).toBe(1);

    const result = redactPII('Transfer to GB29NWBK60161331926819');
    expect(result.redactedText).toBe('Transfer to [IBAN_1]');
    expect(result.redactions[0].type).toBe('test_iban');
  });

  it('no longer detects old patterns after replacement', () => {
    updatePIIPatterns([]);
    const result = redactPII('Email john@acme.com');
    expect(result.piiDetected).toBe(false);
  });
});
