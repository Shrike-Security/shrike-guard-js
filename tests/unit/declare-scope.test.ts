/**
 * Tests for ScanClient.declareScope — Scope Tier 1 helper on the TS SDK.
 *
 * Contract-symmetric with tests/test_declare_scope.py on the Python SDK and
 * scanDeclareScope.test.ts on shrike-mcp. If either SDK diverges on the
 * wire shape assertions below, that is a bug in one of the two.
 */

import { ScanClient } from '../../src/scanner';

const mockFetch = jest.fn();
global.fetch = mockFetch;

function newClient(): ScanClient {
  return new ScanClient({
    apiKey: 'shrike-test',
    endpoint: 'https://mock.test',
    timeout: 100,
  });
}

function okResponse(body: object) {
  return {
    ok: true,
    status: 200,
    json: async () => body,
    text: async () => '',
  };
}

describe('ScanClient.declareScope', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  it('posts a valid body with only required fields', async () => {
    mockFetch.mockResolvedValueOnce(okResponse({ scope_id: 'sc_1', agent_id: 'a1' }));

    const result = await newClient().declareScope({
      agentId: 'recon_agent',
      allowedTools: ['read_invoice'],
    });

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const [url, init] = mockFetch.mock.calls[0];
    expect(url).toBe('https://mock.test/api/v1/agent/scope/declare');
    expect(init.method).toBe('POST');
    const body = JSON.parse(init.body as string);
    expect(body).toEqual({
      agent_id: 'recon_agent',
      allowed_tools: ['read_invoice'],
    });
    expect(result.scope_id).toBe('sc_1');
  });

  it('serializes all optional fields when set', async () => {
    mockFetch.mockResolvedValueOnce(okResponse({ scope_id: 'sc_2' }));

    await newClient().declareScope({
      agentId: 'triage_bot',
      allowedTools: ['read_invoice', 'match_ledger_entry'],
      purpose: 'invoice reconciliation',
      forbiddenTools: ['exec_shell'],
      maxDurationSeconds: 28800,
      expiresAt: '2026-07-14T23:59:59Z',
    });

    const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
    expect(body).toEqual({
      agent_id: 'triage_bot',
      allowed_tools: ['read_invoice', 'match_ledger_entry'],
      purpose: 'invoice reconciliation',
      forbidden_tools: ['exec_shell'],
      max_duration_seconds: 28800,
      expires_at: '2026-07-14T23:59:59Z',
    });
  });

  it('omits optional fields when not set (no null keys)', async () => {
    // Contract: backend distinguishes an absent field from a null value.
    // Sending {purpose: null} would override the persisted value; sending
    // no key preserves it. The helper must not add nulls.
    mockFetch.mockResolvedValueOnce(okResponse({ scope_id: 'sc_3' }));

    await newClient().declareScope({
      agentId: 'scoped_agent',
      allowedTools: ['*'],
    });

    const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
    for (const absent of ['purpose', 'forbidden_tools', 'max_duration_seconds', 'expires_at']) {
      expect(body).not.toHaveProperty(absent);
    }
  });

  it('wildcard allowedTools passes through verbatim', async () => {
    mockFetch.mockResolvedValueOnce(okResponse({ scope_id: 'sc_4' }));

    await newClient().declareScope({
      agentId: 'wide_scope',
      allowedTools: ['*'],
    });

    const body = JSON.parse(mockFetch.mock.calls[0][1].body as string);
    expect(body.allowed_tools).toEqual(['*']);
  });

  it('surfaces backend error body in the thrown message', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: async () => ({}),
      text: async () => 'expires_at is in the past',
    });

    await expect(
      newClient().declareScope({
        agentId: 'stale',
        allowedTools: ['*'],
        expiresAt: '2020-01-01T00:00:00Z',
      })
    ).rejects.toThrow('declareScope failed: 400 — expires_at is in the past');
  });

  it('falls back to status alone when backend body is empty', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: false,
      status: 500,
      json: async () => ({}),
      text: async () => '',
    });

    await expect(
      newClient().declareScope({ agentId: 'ag', allowedTools: ['*'] })
    ).rejects.toThrow('declareScope failed: 500');
  });
});
