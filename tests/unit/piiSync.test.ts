/**
 * Tests for syncPIIPatterns — mocks fetch and verifies the redactor is
 * updated atomically on success and untouched on any failure.
 */

import {
  getPIIPatternCount,
  updatePIIPatterns,
  redactPII,
  type PIIPattern,
} from '../../src/piiRedactor';
import { syncPIIPatterns } from '../../src/piiSync';

// Snapshot the default patterns before the suite runs so each test starts
// from a known state regardless of order.
let defaultPatterns: PIIPattern[];
beforeAll(() => {
  defaultPatterns = [
    { name: 'aws_key', regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, prefix: 'AWSKEY' },
    { name: 'email', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, prefix: 'EMAIL' },
  ];
});

beforeEach(() => {
  updatePIIPatterns(defaultPatterns);
});

const goodBackendPayload = {
  patterns: [
    {
      pattern: '\\b\\d{3}-\\d{2}-\\d{4}\\b',
      threat_type: 'pii_ssn',
      confidence: 0.95,
      description: 'US SSN',
    },
    {
      pattern: '\\b[A-Z]{2}\\d{2}[A-Z0-9]{4}\\d{7}[A-Z0-9]{0,16}\\b',
      threat_type: 'pii_iban',
      confidence: 0.9,
      description: 'IBAN',
    },
  ],
  total: 2,
  version: '2026-06-30',
};

function mockFetchResponse(payload: unknown, status = 200): jest.Mock {
  return jest.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
  });
}

describe('syncPIIPatterns — success path', () => {
  it('replaces bootstrap patterns with backend set', async () => {
    global.fetch = mockFetchResponse(goodBackendPayload) as unknown as typeof fetch;

    const ok = await syncPIIPatterns({ endpoint: 'https://api.shrikesecurity.com' });

    expect(ok).toBe(true);
    expect(getPIIPatternCount()).toBe(2);

    // Backend's wider coverage now redacts IBANs the bootstrap didn't know.
    const result = redactPII('Transfer to GB29NWBK60161331926819 please');
    expect(result.piiDetected).toBe(true);
    expect(result.redactions[0].type).toBe('iban');
    expect(result.redactedText).toContain('[IBAN_1]');
  });

  it('sends Authorization header when apiKey is provided', async () => {
    const fetchMock = mockFetchResponse(goodBackendPayload);
    global.fetch = fetchMock as unknown as typeof fetch;

    await syncPIIPatterns({
      endpoint: 'https://api.shrikesecurity.com/',
      apiKey: 'shrike_test_key',
    });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://api.shrikesecurity.com/api/pii/patterns');
    expect((init as RequestInit).headers).toMatchObject({
      Authorization: 'Bearer shrike_test_key',
    });
  });

  it('omits Authorization header when apiKey is absent', async () => {
    const fetchMock = mockFetchResponse(goodBackendPayload);
    global.fetch = fetchMock as unknown as typeof fetch;

    await syncPIIPatterns({ endpoint: 'https://api.shrikesecurity.com' });

    const [, init] = fetchMock.mock.calls[0];
    expect((init as RequestInit).headers).not.toHaveProperty('Authorization');
  });

  it('strips trailing slashes from the endpoint', async () => {
    const fetchMock = mockFetchResponse(goodBackendPayload);
    global.fetch = fetchMock as unknown as typeof fetch;

    await syncPIIPatterns({ endpoint: 'https://api.shrikesecurity.com///' });

    expect(fetchMock.mock.calls[0][0]).toBe('https://api.shrikesecurity.com/api/pii/patterns');
  });
});

describe('syncPIIPatterns — failure preserves fallback', () => {
  it('network error keeps bootstrap patterns', async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error('connection refused')) as unknown as typeof fetch;
    const before = getPIIPatternCount();

    const ok = await syncPIIPatterns({ endpoint: 'https://api.shrikesecurity.com' });

    expect(ok).toBe(false);
    expect(getPIIPatternCount()).toBe(before);
  });

  it('non-2xx response keeps bootstrap patterns', async () => {
    global.fetch = mockFetchResponse({}, 500) as unknown as typeof fetch;
    const before = getPIIPatternCount();

    const ok = await syncPIIPatterns({ endpoint: 'https://api.shrikesecurity.com' });

    expect(ok).toBe(false);
    expect(getPIIPatternCount()).toBe(before);
  });

  it('empty backend patterns array keeps bootstrap patterns', async () => {
    global.fetch = mockFetchResponse({ patterns: [], total: 0, version: 'v' }) as unknown as typeof fetch;
    const before = getPIIPatternCount();

    const ok = await syncPIIPatterns({ endpoint: 'https://api.shrikesecurity.com' });

    expect(ok).toBe(false);
    expect(getPIIPatternCount()).toBe(before);
  });

  it('unparseable regexes across ALL entries keep bootstrap patterns', async () => {
    // Post-2026-07-02 contract: unknown threat_types no longer silently
    // drop — they derive a fallback prefix (see backend-owned prefix
    // regression test below). So the "everything unknown → keep fallback"
    // behavior only fires when the backend gives us nothing PARSEABLE.
    global.fetch = mockFetchResponse({
      patterns: [
        { pattern: '[invalid', threat_type: 'pii_ssn', confidence: 0.9, description: 'bad' },
      ],
      total: 1,
      version: 'v',
    }) as unknown as typeof fetch;
    const before = getPIIPatternCount();

    const ok = await syncPIIPatterns({ endpoint: 'https://api.shrikesecurity.com' });

    expect(ok).toBe(false);
    expect(getPIIPatternCount()).toBe(before);
  });

  it('unparseable regex among others does not kill the sync', async () => {
    global.fetch = mockFetchResponse({
      patterns: [
        { pattern: '[invalid', threat_type: 'pii_ssn', confidence: 0.9, description: 'bad' },
        { pattern: '\\bok@example\\.com\\b', threat_type: 'pii_email', confidence: 0.9, description: 'ok' },
      ],
      total: 2,
      version: 'v',
    }) as unknown as typeof fetch;

    const ok = await syncPIIPatterns({ endpoint: 'https://api.shrikesecurity.com' });

    expect(ok).toBe(true);
    expect(getPIIPatternCount()).toBe(1);
  });
});

// 2026-07-02 U1 regression: the SDK's PREFIX_MAP allowlist silently dropped
// any backend PII pattern whose threat_type wasn't in the hardcoded list.
// A newly-added `pii_ip_address` recognizer never redacted client-side even
// though the backend was actively detecting it. Same bug MCP had; retired
// the allowlist and switched to backend-shipped prefix + fallback derivation.
// These tests lock in that contract.
describe('syncPIIPatterns — backend-owned prefix contract', () => {
  it('uses backend-shipped prefix verbatim when present (modern backend)', async () => {
    global.fetch = mockFetchResponse({
      patterns: [
        { pattern: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', threat_type: 'pii_ip_address', prefix: 'IP', confidence: 0.75, description: 'IPv4' },
      ],
      total: 1,
      version: '2026-07-02',
    }) as unknown as typeof fetch;

    const ok = await syncPIIPatterns({ endpoint: 'https://api.shrikesecurity.com' });

    expect(ok).toBe(true);
    const { redactedText } = redactPII('server at 192.168.1.100');
    expect(redactedText).not.toContain('192.168.1.100');
    expect(redactedText).toMatch(/\[IP_\d+\]/);
  });

  it('falls back to threat_type-derived prefix when backend omits it (old backend)', async () => {
    // Simulate a pre-2026-07-02 backend that doesn't ship the prefix field.
    // The client must NOT drop the pattern — instead derives IP_ADDRESS
    // from the threat_type. Different tag than a modern backend's `IP`,
    // but redaction still fires. That's the whole point: no silent drop.
    global.fetch = mockFetchResponse({
      patterns: [
        { pattern: '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b', threat_type: 'pii_ip_address', confidence: 0.75, description: 'IPv4' },
      ],
      total: 1,
      version: '2026-06-01',
    }) as unknown as typeof fetch;

    const ok = await syncPIIPatterns({ endpoint: 'https://api.shrikesecurity.com' });

    expect(ok).toBe(true);
    const { redactedText } = redactPII('server at 192.168.1.100');
    expect(redactedText).not.toContain('192.168.1.100');
    expect(redactedText).toMatch(/\[IP_ADDRESS_\d+\]/);
  });

  it('never silently drops unknown threat_types', async () => {
    // A backend adds a hypothetical new pattern the SDK has never seen.
    // Under the old PREFIX_MAP behavior this was silently dropped. Now the
    // sync derives the prefix and applies it.
    global.fetch = mockFetchResponse({
      patterns: [
        { pattern: '0x[a-fA-F0-9]{40}', threat_type: 'pii_wallet_eth', confidence: 0.9, description: 'ETH wallet' },
      ],
      total: 1,
      version: '2026-08-01',
    }) as unknown as typeof fetch;

    const ok = await syncPIIPatterns({ endpoint: 'https://api.shrikesecurity.com' });

    expect(ok).toBe(true);
    const { redactedText } = redactPII('send funds to 0x742d35Cc6634C0532925a3b844Bc9e7595f89999');
    expect(redactedText).not.toContain('0x742d35Cc6634C0532925a3b844Bc9e7595f89999');
    expect(redactedText).toMatch(/\[WALLET_ETH_\d+\]/);
  });
});
