/**
 * Tests pinning the /api/scan/enforce wire migration.
 *
 * Contract-symmetry test — mirrors Python test_enforce_migration.py.
 * If either SDK diverges on these invariants, that is a bug in one of the two.
 */

import { isBlocked, ScanClient } from '../../src/scanner';
import { DEFAULT_ENDPOINT } from '../../src/config';
import { ShrikeOpenAI } from '../../src/openai/client';
import { ShrikeBlockedError } from '../../src/errors';

const mockFetch = jest.fn();
global.fetch = mockFetch;

// -----------------------------------------------------------------------------
// isBlocked — action-authoritative block decision
// -----------------------------------------------------------------------------

describe('isBlocked', () => {
  it('returns true when action is "block"', () => {
    expect(isBlocked({ safe: false, action: 'block' } as any)).toBe(true);
  });

  it('returns true when action is "require_approval"', () => {
    // Held actions are refused at the tool-call boundary. Caller can
    // re-issue after approval lands.
    expect(isBlocked({ safe: false, action: 'require_approval' } as any)).toBe(true);
  });

  it('returns false when action is "allow"', () => {
    expect(isBlocked({ safe: true, action: 'allow' } as any)).toBe(false);
  });

  it('returns false when action is "warn"', () => {
    // warn is advisory — surface via block-feedback but do not refuse.
    expect(isBlocked({ safe: true, action: 'warn' } as any)).toBe(false);
  });

  it('action overrides safe when present', () => {
    expect(isBlocked({ safe: true, action: 'block' } as any)).toBe(true);
    expect(isBlocked({ safe: false, action: 'allow' } as any)).toBe(false);
  });

  it('falls back to !safe when action absent (safe: false)', () => {
    // Older backends / circuit-breaker synthetic verdicts.
    expect(isBlocked({ safe: false, reason: '...' } as any)).toBe(true);
  });

  it('falls back to !safe when action absent (safe: true)', () => {
    expect(isBlocked({ safe: true } as any)).toBe(false);
  });

  it('returns false when both action and safe are absent', () => {
    // Fail-open on empty verdict — matches historical SDK behavior.
    expect(isBlocked({} as any)).toBe(false);
  });

  it('treats empty action string as absent (falls back to safe)', () => {
    expect(isBlocked({ safe: false, action: '' } as any)).toBe(true);
    expect(isBlocked({ safe: true, action: '' } as any)).toBe(false);
  });
});

// -----------------------------------------------------------------------------
// URL migration — every wrapper POSTs to /api/scan/enforce
// -----------------------------------------------------------------------------

function stubOk(body: any) {
  return {
    ok: true,
    json: () => Promise.resolve(body),
  } as any;
}

describe('URL migration — /api/scan/enforce', () => {
  beforeEach(() => {
    mockFetch.mockClear();
  });

  it('ScanClient.scan POSTs to /api/scan/enforce', async () => {
    mockFetch.mockResolvedValueOnce(stubOk({ safe: true, action: 'allow' }));
    const client = new ScanClient({ apiKey: 'test-key' });
    await client.scan('hello');
    expect(mockFetch).toHaveBeenCalledWith(
      `${DEFAULT_ENDPOINT}/api/scan/enforce`,
      expect.objectContaining({ method: 'POST' })
    );
  });

  it('ScanClient.scanSql POSTs to /api/scan/enforce/specialized', async () => {
    mockFetch.mockResolvedValueOnce(stubOk({ safe: true, action: 'allow' }));
    const client = new ScanClient({ apiKey: 'test-key' });
    await client.scanSql('SELECT 1');
    expect(mockFetch).toHaveBeenCalledWith(
      `${DEFAULT_ENDPOINT}/api/scan/enforce/specialized`,
      expect.objectContaining({ method: 'POST' })
    );
  });

  it('ScanClient.scanFile POSTs to /api/scan/enforce/specialized', async () => {
    mockFetch.mockResolvedValueOnce(stubOk({ safe: true, action: 'allow' }));
    const client = new ScanClient({ apiKey: 'test-key' });
    await client.scanFile('/tmp/x');
    expect(mockFetch).toHaveBeenCalledWith(
      `${DEFAULT_ENDPOINT}/api/scan/enforce/specialized`,
      expect.objectContaining({ method: 'POST' })
    );
  });

  it('ScanClient.scanA2AMessage POSTs to /api/scan/enforce/specialized', async () => {
    mockFetch.mockResolvedValueOnce(stubOk({ safe: true, action: 'allow' }));
    const client = new ScanClient({ apiKey: 'test-key' });
    await client.scanA2AMessage('ping');
    expect(mockFetch).toHaveBeenCalledWith(
      `${DEFAULT_ENDPOINT}/api/scan/enforce/specialized`,
      expect.objectContaining({ method: 'POST' })
    );
  });

  it('ScanClient.scanAgentCard POSTs to /api/scan/enforce/specialized', async () => {
    mockFetch.mockResolvedValueOnce(stubOk({ safe: true, action: 'allow' }));
    const client = new ScanClient({ apiKey: 'test-key' });
    await client.scanAgentCard('{"name":"test"}');
    expect(mockFetch).toHaveBeenCalledWith(
      `${DEFAULT_ENDPOINT}/api/scan/enforce/specialized`,
      expect.objectContaining({ method: 'POST' })
    );
  });

  it('ShrikeOpenAI wrapper POSTs to /api/scan/enforce', async () => {
    mockFetch.mockResolvedValueOnce(stubOk({ safe: true, action: 'allow' }));
    const client = new ShrikeOpenAI({
      apiKey: 'sk-test',
      shrikeApiKey: 'shrike-test',
    });
    // Access internal method via cast — validates URL wiring without
    // needing to spin up a full openai chat completion.
    await (client as any)._remoteScan('hello');
    expect(mockFetch).toHaveBeenCalledWith(
      `${DEFAULT_ENDPOINT}/api/scan/enforce`,
      expect.objectContaining({ method: 'POST' })
    );
  });
});

// -----------------------------------------------------------------------------
// ShrikeOpenAI end-to-end: enforce-shape verdict routes through isBlocked
// -----------------------------------------------------------------------------

describe('ShrikeOpenAI enforce integration', () => {
  beforeEach(() => {
    mockFetch.mockClear();
  });

  function makeClient() {
    return new ShrikeOpenAI({
      apiKey: 'sk-test',
      shrikeApiKey: 'shrike-test',
    });
  }

  it('action="block" raises ShrikeBlockedError', async () => {
    mockFetch.mockResolvedValueOnce(
      stubOk({
        action: 'block',
        safe: false,
        reason: 'prompt injection detected',
        threat_type: 'prompt_injection',
        violations: [{ threat_type: 'prompt_injection' }],
      })
    );
    const client = makeClient();
    await expect(
      client.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'malicious' }],
      } as any)
    ).rejects.toThrow(ShrikeBlockedError);
  });

  it('action="allow" proceeds to OpenAI', async () => {
    mockFetch.mockResolvedValueOnce(stubOk({ action: 'allow', safe: true }));
    const client = makeClient();
    const openaiSpy = jest
      .spyOn((client as any)._openai.chat.completions, 'create')
      .mockResolvedValue({} as any);
    await client.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'hello' }],
    } as any);
    expect(openaiSpy).toHaveBeenCalled();
  });

  it('missing action falls back to !safe (downgrade path)', async () => {
    // Legacy /api/scan shape — no `action` field.
    mockFetch.mockResolvedValueOnce(
      stubOk({
        safe: false,
        reason: 'prompt injection',
        threat_type: 'prompt_injection',
        violations: [],
      })
    );
    const client = makeClient();
    await expect(
      client.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'malicious' }],
      } as any)
    ).rejects.toThrow(ShrikeBlockedError);
  });

  it('action="warn" does not block (advisory)', async () => {
    mockFetch.mockResolvedValueOnce(
      stubOk({ action: 'warn', safe: true, refuse_tier: 'warn' })
    );
    const client = makeClient();
    const openaiSpy = jest
      .spyOn((client as any)._openai.chat.completions, 'create')
      .mockResolvedValue({} as any);
    await client.chat.completions.create({
      model: 'gpt-4',
      messages: [{ role: 'user', content: 'borderline' }],
    } as any);
    expect(openaiSpy).toHaveBeenCalled();
  });
});
