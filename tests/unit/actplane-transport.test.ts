/**
 * Wire-shape tests for the act-plane scan methods.
 *
 * The parity test asserts that each channel has a method. That is a structural
 * check: it cannot see a wrong endpoint, a misspelled content_type, or an
 * optional argument that never reaches the payload. These tests assert the
 * request each method actually sends, that the response fields the SDK
 * documents survive sanitization, and that the helpers the SDK documents are
 * exported from the package entry point.
 *
 * Contract-symmetric with tests/test_actplane_transport.py on the Python SDK.
 * If the two disagree on a body shape below, one of them is a bug.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ScanClient } from '../../src/scanner';

// The shared request-shape declaration. One file, three consumers (this suite,
// the Python suite, the Go suite), so a divergence is a CI failure rather than
// something someone notices by eye. Sibling of canonical-backend-responses.json,
// which does the same job for the response.
const FIXTURE = JSON.parse(
  readFileSync(
    join(__dirname, '..', 'fixtures', 'contract-symmetry', 'canonical-request-shapes.json'),
    'utf8'
  )
);

const mockFetch = jest.fn();
global.fetch = mockFetch;

const SPECIALIZED_URL = `https://mock.test${FIXTURE.specialized_endpoint}`;
const MCP_SCHEMA_URL = `https://mock.test${FIXTURE.non_specialized.mcp_schema.endpoint}`;
const REQUIRED_IDENTITY: string[] = FIXTURE.session_identity.required_context_keys;
const SOURCE_APP: string = FIXTURE.session_identity.source_application_by_sdk.typescript;

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

/** The minimum a backend reply carries on the act plane. */
function safeVerdict(extra: object = {}) {
  return {
    safe: true,
    action: 'allow',
    refuse_tier: 'allow',
    content_origin: 'agent_action',
    ...extra,
  };
}

function lastCall(): { url: string; body: Record<string, unknown> } {
  const [url, init] = mockFetch.mock.calls[mockFetch.mock.calls.length - 1];
  return { url: url as string, body: JSON.parse(init.body as string) };
}

describe('act-plane transport', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  // --- endpoint + content_type, per channel ------------------------------

  // The whole point of the shared scanSpecialized transport is that adding a
  // channel is one line. The risk that creates is that the one line is wrong,
  // and every channel looks identical from the outside.
  const channels: Array<{
    name: string;
    contentType: string;
    call: (c: ScanClient) => Promise<unknown>;
  }> = [
    { name: 'scanCommand', contentType: 'command', call: (c) => c.scanCommand('ls -la') },
    { name: 'scanSql', contentType: 'sql', call: (c) => c.scanSql('SELECT 1') },
    { name: 'scanWebSearch', contentType: 'web_search', call: (c) => c.scanWebSearch('owasp') },
    { name: 'scanRagContext', contentType: 'rag_context', call: (c) => c.scanRagContext('chunk') },
    { name: 'scanA2AMessage', contentType: 'a2a_message', call: (c) => c.scanA2AMessage('hello') },
    { name: 'scanAgentCard', contentType: 'agent_card', call: (c) => c.scanAgentCard('{}') },
  ];

  it('exercises every channel the fixture declares', () => {
    // The fixture is the channel list. A channel added there without a test
    // here is a channel nobody checks the wire shape of.
    const exercised = new Set([...channels.map((c) => c.contentType), 'file_path', 'file_content']);
    const missing = Object.keys(FIXTURE.channels).filter((ct) => !exercised.has(ct));
    expect(missing).toEqual([]);
  });

  it.each(channels)('$name posts content_type $contentType to the specialized endpoint', async ({
    contentType,
    call,
  }) => {
    mockFetch.mockResolvedValueOnce(okResponse(safeVerdict()));
    await call(newClient());

    expect(mockFetch).toHaveBeenCalledTimes(1);
    const { url, body } = lastCall();
    expect(url).toBe(SPECIALIZED_URL);
    expect(body.content_type).toBe(FIXTURE.channels[contentType].content_type);
    expect(typeof body.content).toBe('string');

    // Identity rides on every act-plane request.
    const ctx = body.context as Record<string, unknown>;
    for (const key of REQUIRED_IDENTITY) {
      expect(ctx[key]).toBeTruthy();
    }
    expect(ctx.source_application).toBe(SOURCE_APP);
  });

  it('scanFile posts file_path when no content is supplied', async () => {
    mockFetch.mockResolvedValueOnce(okResponse(safeVerdict()));
    await newClient().scanFile('/etc/passwd');
    expect(lastCall().body.content_type).toBe('file_path');
  });

  it('scanFile posts file_content when content is supplied', async () => {
    // One method, two channels, decided by an argument. Getting this
    // backwards would scan a file body against path-traversal rules.
    mockFetch.mockResolvedValueOnce(okResponse(safeVerdict()));
    await newClient().scanFile('/tmp/config.py', 'api_key = "sk-x"');
    expect(lastCall().body.content_type).toBe('file_content');
  });

  // --- optional arguments must actually reach the payload ---------------

  it('scanCommand carries cwd into the context', async () => {
    mockFetch.mockResolvedValueOnce(okResponse(safeVerdict()));
    await newClient().scanCommand('git status', '/srv/app');
    const ctx = lastCall().body.context as Record<string, unknown>;
    expect(ctx.cwd).toBe('/srv/app');
  });

  it('scanCommand omits cwd but keeps the session identity', async () => {
    mockFetch.mockResolvedValueOnce(okResponse(safeVerdict()));
    await newClient().scanCommand('git status');
    const ctx = lastCall().body.context as Record<string, unknown>;
    expect(ctx.cwd).toBeUndefined();
    for (const key of REQUIRED_IDENTITY) {
      expect(ctx[key]).toBeTruthy();
    }
  });

  it('scanRagContext carries the query into the context', async () => {
    mockFetch.mockResolvedValueOnce(okResponse(safeVerdict()));
    await newClient().scanRagContext(['a', 'b'], 'what is the refund policy');
    const ctx = lastCall().body.context as Record<string, unknown>;
    expect(ctx.query).toBe('what is the refund policy');
  });

  it('scanRagContext serializes an array of chunks as JSON', async () => {
    // The backend splits chunks back apart. Sending "a,b" (a naive join)
    // would merge two documents into one and lose the boundary an injection
    // usually sits on.
    mockFetch.mockResolvedValueOnce(okResponse(safeVerdict()));
    await newClient().scanRagContext(['first chunk', 'second chunk']);
    expect(lastCall().body.content).toBe(JSON.stringify(['first chunk', 'second chunk']));
  });

  it('scanRagContext passes a single string through unchanged', async () => {
    mockFetch.mockResolvedValueOnce(okResponse(safeVerdict()));
    await newClient().scanRagContext('just one chunk');
    expect(lastCall().body.content).toBe('just one chunk');
  });

  // --- mcp_schema is the odd one out ------------------------------------

  it('scanMcpSchema posts to its own endpoint with a name/description body', async () => {
    // Not a specialized content type: its own route, its own detector, and a
    // body that is not {content, content_type}. Routing it through the
    // specialized endpoint would scan the description as opaque text.
    mockFetch.mockResolvedValueOnce(okResponse(safeVerdict()));
    await newClient().scanMcpSchema('read_file', 'Reads a file from disk.');

    const { url, body } = lastCall();
    expect(url).toBe(MCP_SCHEMA_URL);
    expect(body.name).toBe('read_file');
    expect(body.description).toBe('Reads a file from disk.');
    expect(body).not.toHaveProperty('content_type');
  });

  it('scanMcpSchema includes input_schema when supplied and omits it otherwise', async () => {
    mockFetch.mockResolvedValueOnce(okResponse(safeVerdict()));
    await newClient().scanMcpSchema('t', 'd', { type: 'object' });
    expect(lastCall().body.input_schema).toEqual({ type: 'object' });

    mockFetch.mockResolvedValueOnce(okResponse(safeVerdict()));
    await newClient().scanMcpSchema('t', 'd');
    expect(lastCall().body).not.toHaveProperty('input_schema');
  });

  // --- the response side -------------------------------------------------

  it('content_origin survives the response sanitizer', async () => {
    // The sanitizer is an allow-list: a field the backend sends is dropped
    // unless it is named in PRESERVED_GOVERNANCE_FIELDS.
    mockFetch.mockResolvedValueOnce(
      okResponse(safeVerdict({ content_origin: 'third_party' }))
    );
    const result = await newClient().scanRagContext('retrieved text');
    expect(result.content_origin).toBe('third_party');
  });

  it('the four-state governance surface survives on a refusal', async () => {
    mockFetch.mockResolvedValueOnce(
      okResponse({
        safe: false,
        action: 'block',
        refuse_tier: 'block',
        threat_type: 'sql_injection',
        content_origin: 'agent_action',
        recovery: { instruction: 'rewrite the query with bound parameters' },
        session_state: { session_risk_score: 0.4 },
      })
    );
    const result = await newClient().scanCommand('psql -c "SELECT 1 OR 1=1--"');

    expect(result.safe).toBe(false);
    expect(result.refuse_tier).toBe('block');
    expect(result.recovery).toBeDefined();
    expect(result.session_state).toBeDefined();
    expect(result.content_origin).toBe('agent_action');
  });

  // --- the general prompt path ------------------------------------------

  it('the general scan sends identity in context and history separately', async () => {
    // A string `context` is not the identity object: the backend treats it
    // as a source label and leaves session and agent identity empty. All
    // three SDKs send the object, with the history in its own field.
    mockFetch.mockResolvedValueOnce(okResponse(safeVerdict()));
    await newClient().scan('hello', 'earlier turn');

    const { url, body } = lastCall();
    expect(url).toBe(`https://mock.test${FIXTURE.general_endpoint}`);
    for (const key of FIXTURE.general_scan.required_body_keys as string[]) {
      expect(body).toHaveProperty(key);
    }
    expect(body.scan_type).toBe(FIXTURE.general_scan.scan_type);

    const ctx = body.context as Record<string, unknown>;
    expect(typeof ctx).toBe('object');
    for (const key of REQUIRED_IDENTITY) {
      expect(ctx[key]).toBeTruthy();
    }
    expect(ctx.source_application).toBe(SOURCE_APP);
    expect(body[FIXTURE.general_scan.conversation_history_key as string]).toBe('earlier turn');
  });

  it('a non-200 raises rather than resolving to a safe verdict', async () => {
    // Fail-closed: an enforcement gate that returns "safe" when it could not
    // evaluate is a fail-open in disguise.
    mockFetch.mockResolvedValue({ ok: false, status: 500, json: async () => ({}), text: async () => '' });
    await expect(newClient().scanCommand('ls')).rejects.toThrow(/500/);
  });

  it('sends the scan auth header, never X-API-Key', async () => {
    // OptionalAuth reads Authorization: Bearer or X-Shrike-API-Key only. An
    // X-API-Key request carries no recognized credential, silently resolves
    // to the anonymous tier, and every scan looks like a fast L1-L5 pass.
    mockFetch.mockResolvedValueOnce(okResponse(safeVerdict()));
    await newClient().scanCommand('ls');

    const [, init] = mockFetch.mock.calls[0];
    const headers = init.headers as Record<string, string>;
    const names = Object.keys(headers).map((h) => h.toLowerCase());
    for (const forbidden of FIXTURE.auth.forbidden_headers as string[]) {
      expect(names).not.toContain(forbidden);
    }
    expect(names.some((n) => (FIXTURE.auth.accepted_headers as string[]).includes(n))).toBe(true);
  });
});
