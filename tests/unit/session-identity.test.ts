/**
 * Session identity is configured per client, not per process.
 *
 * Session identity is the key the backend accumulates multi-turn risk against.
 * Every caller sharing one id shares one risk score, so a server that scans on
 * behalf of many end users must give each user its own session; otherwise one
 * user's refusal counts against the next user's action.
 *
 * Contract-symmetric with tests/test_session_identity.py and
 * scanner/session_identity_test.go: if the three disagree about what lands in
 * the request context, one of them is a bug.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ScanClient } from '../../src/scanner';
import {
  getSessionId,
  getAgentId,
  resetProcessSessionWarningForTests,
} from '../../src/config';

const FIXTURE = JSON.parse(
  readFileSync(
    join(__dirname, '..', 'fixtures', 'contract-symmetry', 'canonical-request-shapes.json'),
    'utf8'
  )
);

const REQUIRED_IDENTITY: string[] = FIXTURE.session_identity.required_context_keys;
const SOURCE_APP: string = FIXTURE.session_identity.source_application_by_sdk.typescript;

const mockFetch = jest.fn();
global.fetch = mockFetch;

function okResponse() {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      safe: true,
      action: 'allow',
      refuse_tier: 'allow',
      recovery: {},
      session_state: {},
    }),
    text: async () => '',
  };
}

function newClient(extra: Record<string, unknown> = {}): ScanClient {
  return new ScanClient({
    apiKey: 'shrike-test',
    endpoint: 'https://mock.test',
    timeout: 100,
    ...extra,
  } as never);
}

/** The context object of the most recent scan request. */
function sentContext(): Record<string, unknown> {
  const body = JSON.parse(mockFetch.mock.calls[mockFetch.mock.calls.length - 1][1].body);
  return body.context;
}

beforeEach(() => {
  mockFetch.mockReset();
  mockFetch.mockResolvedValue(okResponse());
  resetProcessSessionWarningForTests();
});

// --- the override reaches the wire ---------------------------------------

describe('explicit identity', () => {
  it('sends the session id given to the constructor', async () => {
    const client = newClient({ sessionId: 'sess-explicit' });
    await client.scanCommand('ls -la');

    const ctx = sentContext();
    expect(ctx.session_id).toBe('sess-explicit');
    // The identity block stays complete — an override replaces one value, it
    // does not drop the others.
    for (const key of REQUIRED_IDENTITY) {
      expect(ctx).toHaveProperty(key);
    }
    expect(ctx.source_application).toBe(SOURCE_APP);
  });

  it('sends the agent id given to the constructor', async () => {
    const client = newClient({ agentId: 'agent-billing' });
    await client.scanCommand('ls -la');
    expect(sentContext().agent_id).toBe('agent-billing');
  });

  it('still sends the process identity when nothing is supplied', async () => {
    // No regression for the single-agent caller. Removing the default would
    // silently delete multi-turn correlation for every CLI and worker that
    // never sets a session id. The default stays; the warning is what changed.
    const client = newClient();
    await client.scanCommand('ls -la');

    const ctx = sentContext();
    expect(ctx.session_id).toBe(getSessionId());
    expect(ctx.agent_id).toBe(getAgentId());
  });
});

describe('agent id env override', () => {
  // The variable named by the fixture (agent_id_env_override) names the
  // process's agent. All three SDKs pin this against the same declaration so
  // they cannot drift on the variable name.
  const envVar: string = FIXTURE.session_identity.agent_id_env_override;

  afterEach(() => {
    delete process.env[envVar];
  });

  it('is honoured, and an explicit agentId outranks it', async () => {
    expect(envVar).toBeTruthy();
    process.env[envVar] = 'agent-from-env';

    // The env override beats the generated process id.
    await newClient().scanCommand('ls -la');
    expect(sentContext().agent_id).toBe('agent-from-env');

    // An explicit client option beats the env override.
    await newClient({ agentId: 'agent-explicit' }).scanCommand('ls -la');
    expect(sentContext().agent_id).toBe('agent-explicit');
  });
});

// --- forSession ------------------------------------------------------------

describe('forSession', () => {
  it('sends the derived session id', async () => {
    const guard = newClient();
    await guard.forSession('sess-request-42').scanCommand('ls -la');
    expect(sentContext().session_id).toBe('sess-request-42');
  });

  it('keeps two derived clients in separate sessions', async () => {
    // The whole point: two end users must not accumulate into one risk score.
    const guard = newClient();
    const alice = guard.forSession('sess-alice');
    const bob = guard.forSession('sess-bob');

    await alice.scanCommand('ls -la');
    const aliceCtx = sentContext();
    await bob.scanCommand('ls -la');
    const bobCtx = sentContext();

    expect(aliceCtx.session_id).toBe('sess-alice');
    expect(bobCtx.session_id).toBe('sess-bob');
    expect(aliceCtx.session_id).not.toBe(bobCtx.session_id);
  });

  it('shares the parent rate limiter', () => {
    // A per-request client with its own limiter would give every request a
    // full rate budget and defeat the limit entirely.
    const guard = newClient();
    const scoped = guard.forSession('sess-1');
    expect((scoped as never as Record<string, unknown>).rateLimiter).toBe(
      (guard as never as Record<string, unknown>).rateLimiter
    );
  });

  it('inherits the agent id but can override it', async () => {
    const guard = newClient({ agentId: 'agent-parent' });

    await guard.forSession('sess-1').scanCommand('ls -la');
    expect(sentContext().agent_id).toBe('agent-parent');

    await guard.forSession('sess-2', 'agent-child').scanCommand('ls -la');
    expect(sentContext().agent_id).toBe('agent-child');
  });

  it('carries the derived session on every channel', async () => {
    // One method wired to the client identity is not enough — all of them.
    // This is the shape of bug the act-plane work kept finding: the value
    // exists, one path uses it, another path was never connected.
    //
    // scanMcpSchema is deliberately absent — see the known-gap test below.
    const guard = newClient();
    const scoped = guard.forSession('sess-everywhere');

    const calls: Array<[string, () => Promise<unknown>]> = [
      ['scan', () => scoped.scan('summarize this')],
      ['scanCommand', () => scoped.scanCommand('ls -la')],
      ['scanSql', () => scoped.scanSql('SELECT 1')],
      ['scanFile', () => scoped.scanFile('/tmp/a.txt')],
      ['scanWebSearch', () => scoped.scanWebSearch('owasp')],
      ['scanRagContext', () => scoped.scanRagContext(['chunk'])],
      ['scanA2AMessage', () => scoped.scanA2AMessage('done')],
      ['scanAgentCard', () => scoped.scanAgentCard('{"name":"a"}')],
    ];

    for (const [name, call] of calls) {
      await call();
      if (sentContext().session_id !== 'sess-everywhere') {
        throw new Error(
          `${name} did not carry the client's session id — it is reading the ` +
            `process default instead of the client`
        );
      }
    }
  });

  it('does not yet send session identity on mcp_schema', async () => {
    // Records current behaviour rather than asserting the target behaviour.
    // /api/scan/mcp_schema is not yet part of the session contract: its
    // request accepts no context object, and its response carries no
    // refuse_tier, recovery or session_state. When the endpoint adopts the
    // contract, this test fails and mcp_schema moves into the loop above.
    const guard = newClient();
    await guard.forSession('sess-everywhere').scanMcpSchema('t', 'desc', {});

    const body = JSON.parse(mockFetch.mock.calls[mockFetch.mock.calls.length - 1][1].body);
    expect(body).not.toHaveProperty('context');
  });
});

// --- the warning -----------------------------------------------------------

describe('the process-session warning', () => {
  let warn: jest.SpyInstance;

  beforeEach(() => {
    warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    delete process.env.SHRIKE_SUPPRESS_SESSION_WARNING;
  });

  afterEach(() => {
    warn.mockRestore();
    delete process.env.SHRIKE_SUPPRESS_SESSION_WARNING;
  });

  const sessionWarnings = () =>
    warn.mock.calls.filter((c) => String(c[0]).includes('process-wide session id'));

  it('fires once, not once per scan', async () => {
    // A silent default is how this shipped in the first place.
    const client = newClient();
    await client.scanCommand('ls -la');
    await client.scanCommand('ls -la');
    await client.scanCommand('ls -la');

    expect(sessionWarnings()).toHaveLength(1);
  });

  it('does not fire when a session id was supplied', async () => {
    const client = newClient({ sessionId: 'sess-explicit' });
    await client.scanCommand('ls -la');
    expect(sessionWarnings()).toHaveLength(0);
  });

  it('can be suppressed', async () => {
    process.env.SHRIKE_SUPPRESS_SESSION_WARNING = '1';
    const client = newClient();
    await client.scanCommand('ls -la');
    expect(sessionWarnings()).toHaveLength(0);
  });
});
