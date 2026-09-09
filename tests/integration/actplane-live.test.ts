/**
 * Live integration tests: real backend, real HTTP, no mocks.
 *
 * The unit suites assert what the SDK sends. Only the backend can confirm that
 * it accepts the request and returns the fields the SDK documents: an
 * unrecognized content_type, a renamed endpoint, a rejected auth header, or a
 * response field that is present on one route and absent on another all look
 * identical to a passing mock.
 *
 * Skipped unless both are set:
 *
 *     SHRIKE_LIVE_ENDPOINT   e.g. https://api.shrikesecurity.com/agent
 *     SHRIKE_LIVE_API_KEY
 *
 * Run:  SHRIKE_LIVE_ENDPOINT=... SHRIKE_LIVE_API_KEY=... npx jest actplane-live
 *
 * These probes write real scan rows, including refused scans, to the account
 * the key belongs to. Use a dedicated test account.
 *
 * Assertions are deliberately coarse. Which layer catches a probe may change
 * freely; that the call round-trips and returns a well-formed governance
 * verdict may not. No exact prose, no confidences, no severities: those are
 * attribution and are allowed to change.
 *
 * Contract-symmetric with tests/test_actplane_live.py (Python) and
 * scanner/actplane_live_test.go (Go). If the three disagree about what the
 * backend returns, one of them is a bug.
 */

import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { ScanClient } from '../../src/scanner';
import type { ScanResult } from '../../src/scanner';

const ENDPOINT = process.env.SHRIKE_LIVE_ENDPOINT;
const API_KEY = process.env.SHRIKE_LIVE_API_KEY;
const live = ENDPOINT && API_KEY ? describe : describe.skip;

const FIXTURE = JSON.parse(
  readFileSync(
    join(__dirname, '..', 'fixtures', 'contract-symmetry', 'canonical-request-shapes.json'),
    'utf8'
  )
);

const TIERS = ['allow', 'warn', 'require_approval', 'block'];
const ORIGINS = ['human_prompt', 'agent_output', 'agent_action', 'third_party'];

// The suite identifies itself: one agent id per SDK suite and one session id
// per run, so its rows are recognisable on the Agents screen and in incidents.
// The session id is fresh each run because backend session state persists
// between runs; a reused id would carry the previous run's history into this
// one.
const LIVE_AGENT_ID = 'sdk-live-test-typescript';
const LIVE_RUN_SESSION_ID = `${LIVE_AGENT_ID}-run-${randomUUID().slice(0, 12)}`;

function newClient(): ScanClient {
  return new ScanClient({
    apiKey: API_KEY as string,
    endpoint: ENDPOINT as string,
    timeout: 30000,
    sessionId: LIVE_RUN_SESSION_ID,
    agentId: LIVE_AGENT_ID,
  });
}

/**
 * The four-state governance surface must be present on every verdict.
 *
 * Contract symmetry is a shipped promise: safe / refuse_tier / recovery /
 * session_state on every response, refused or not. A live check is the only
 * place that promise is tested against the thing that actually makes it.
 */
function assertWellFormed(result: ScanResult, label: string): string {
  if (!result) throw new Error(`${label}: no result`);
  if (!('safe' in result)) throw new Error(`${label}: verdict has no \`safe\``);
  const tier = result.refuse_tier || result.action;
  if (!tier) throw new Error(`${label}: no refuse_tier — contract symmetry broken`);
  if (!TIERS.includes(tier)) throw new Error(`${label}: unknown refuse_tier ${tier}`);
  return tier;
}

live('live backend — act plane', () => {
  // One client for the whole describe, deliberately: it is one session, and
  // session accumulation is part of what is under test below.
  let client: ScanClient;

  beforeAll(() => {
    client = newClient();
  });

  // --- every channel round-trips ------------------------------------------

  // Benign content per channel. The point is that the REQUEST is accepted and a
  // verdict comes back, not that anything is caught.
  const CHANNELS: Array<[string, (c: ScanClient) => Promise<ScanResult>]> = [
    ['command', (c) => c.scanCommand('git status', '/tmp')],
    ['sql', (c) => c.scanSql('SELECT id FROM users WHERE id = 1', 'postgres')],
    ['file_path', (c) => c.scanFile('/tmp/report.csv')],
    ['file_content', (c) => c.scanFile('/tmp/notes.txt', 'meeting notes for thursday')],
    ['web_search', (c) => c.scanWebSearch('sql injection prevention owasp cheat sheet')],
    ['rag_context', (c) => c.scanRagContext(['the refund window is 30 days'], 'refunds')],
    ['a2a_message', (c) => c.scanA2AMessage('task complete, 3 records updated')],
    ['agent_card', (c) => c.scanAgentCard('{"name":"reporter","version":"1.0"}')],
  ];

  test.each(CHANNELS)(
    'channel %s round-trips against the real backend',
    async (channel, call) => {
      // A mock cannot fail this. Only the backend can.
      expect(Object.keys(FIXTURE.channels)).toContain(channel);
      const result = await call(client);
      assertWellFormed(result, channel);
    },
    45000
  );

  // /api/scan/mcp_schema does not yet return refuse_tier, recovery or
  // session_state, and does not accept a session context. `test.failing`
  // passes while the assertion throws; once the endpoint adopts the response
  // contract it stops throwing, the run fails, and the marker is removed.
  test.failing(
    'mcp_schema round-trips (not yet in the response contract)',
    async () => {
      const result = await client.scanMcpSchema(
        'read_report',
        'Reads a report file from the reports directory and returns its contents.',
        { type: 'object', properties: { path: { type: 'string' } } }
      );
      assertWellFormed(result, 'mcp_schema');
    },
    45000
  );

  test(
    'general scan round-trips',
    async () => {
      const result = await client.scan(
        'summarize the quarterly report',
        'user asked about Q3 earlier'
      );
      assertWellFormed(result, 'general scan');
    },
    45000
  );

  // --- the verdict carries what we tell customers it carries ---------------

  test(
    'content_origin arrives on an act-plane verdict',
    async () => {
      // content_origin is the field 4.1.0 exists to deliver, and the README
      // documents it. It was computed by the backend and dropped by every
      // SDK's sanitizer for months; then, once all three preserved it, it
      // turned out the enforce route never sent it at all. This asserts the
      // half nobody had checked: that the backend is actually sending it.
      const result = await client.scanCommand('ls -la', '/tmp');
      const origin = result.content_origin;
      expect(origin).toBeTruthy();
      expect(ORIGINS).toContain(origin);
      // An act-plane scan must never be attributed to the operator — unknown
      // content types resolve to agent_action by design.
      expect(origin).not.toBe('human_prompt');
    },
    45000
  );

  test(
    'benign technical prose is not refused',
    async () => {
      // The other half of the gate. A detector that refuses ordinary work is a
      // detector nobody keeps switched on.
      //
      // Ordering matters: this runs before the attack probes below, and jest
      // executes tests in declaration order. The shared `client` scans under
      // one session id for the whole run, so every scan it makes lands in one
      // session. Run these after that session has accumulated enough risk and
      // they come back held, correctly, and read as false positives that are
      // not there.
      //
      // A client derived with forSession() is a different session and is not
      // subject to this; see 'sessions are isolated end to end'. A
      // false-positive probe on the shared client added below the attack
      // probes will fail for a reason unrelated to false positives.
      const cases: Array<[string, () => Promise<ScanResult>]> = [
        ['git pathspec separator', () => client.scanCommand('git log --oneline -5 --')],
        ['defensive research', () => client.scanWebSearch('owasp top 10 for llm applications')],
        [
          'legitimate union',
          () => client.scanSql('SELECT name FROM staff UNION SELECT name FROM contractors'),
        ],
      ];
      for (const [label, call] of cases) {
        const result = await call();
        assertWellFormed(result, label);
        expect(result.refuse_tier || result.action).toBe('allow');
      }
    },
    90000
  );

  test(
    'a real attack is refused',
    async () => {
      // One end-to-end proof that enforcement actually enforces. Coarse on
      // purpose: refuse_tier must escalate past allow. Which layer caught it,
      // at what confidence, is attribution and may change freely.
      const result = await client.scanCommand(
        'psql -c "SELECT * FROM users WHERE id = 1 OR 1=1--"'
      );
      assertWellFormed(result, 'sqli in a command');
      expect(result.refuse_tier || result.action).not.toBe('allow');
    },
    45000
  );

  test(
    'session quarantine holds later actions',
    async () => {
      // Once a session's accumulated risk crosses the quarantine threshold,
      // later actions in that session are held. Quarantine is a function of
      // accumulated session risk, not of a single refusal: by this point the
      // shared client carries a dozen turns of history plus a refused
      // injection, which is what takes it over the threshold. A fresh
      // session's first refusal does not; see 'sessions are isolated end to
      // end'. Ordering matters: it runs after the SQL-injection probe on the
      // shared client, deliberately.
      const result = await client.scanCommand('git log --oneline -5 --');
      assertWellFormed(result, 'post-refusal benign command');
      expect(result.refuse_tier || result.action).not.toBe('allow');
    },
    45000
  );

  test(
    'sessions are isolated end to end',
    async () => {
      // Two views derived with forSession are two sessions to the backend.
      //
      // Session correlation keys on (customer, session, agent), so two views
      // with different session ids are separate sessions even though they
      // share the agent id and the rate limiter. The proof is what the backend
      // reports on every response: session_state.session_turn_number and
      // session_state.session_risk_score. Session A's turns must count up and
      // carry risk after its refusal; session B, scanning right after, must be
      // on its first turn with no risk and allowed.
      //
      // Not asserted: that A's next action is held. Quarantine is a function
      // of accumulated session risk, and a fresh session's single refusal
      // stays below the threshold.
      //
      // Fresh ids per run, on purpose: backend session state persists across
      // runs, so a fixed id would carry a previous run's history into this one
      // and the test would fail for a reason unrelated to isolation.
      const a = client.forSession(`${LIVE_AGENT_ID}-iso-a-${randomUUID().slice(0, 12)}`);
      const b = client.forSession(`${LIVE_AGENT_ID}-iso-b-${randomUUID().slice(0, 12)}`);

      const refused = await a.scanCommand('psql -c "SELECT * FROM users WHERE id = 1 OR 1=1--"');
      expect(assertWellFormed(refused, 'session A: sqli in a command')).not.toBe('allow');

      const after = await a.scanCommand('git log --oneline -5 --');
      assertWellFormed(after, 'session A: benign command after its own refusal');

      const clean = await b.scanCommand('git log --oneline -5 --');
      const cleanTier = assertWellFormed(clean, 'session B: same benign command, different session');

      const aState = after.session_state ?? {};
      const bState = clean.session_state ?? {};

      // Session A correlates its own turns: the id from forSession reached the
      // backend and the backend kept state under it.
      if (aState.session_turn_number !== 2) {
        throw new Error(
          `session A's second scan was turn ${aState.session_turn_number}, expected 2 — ` +
            'the session id from forSession() is not being correlated'
        );
      }
      if (!((aState.session_risk_score ?? 0) > 0)) {
        throw new Error('session A carries no risk after its own refusal — nothing accumulated');
      }

      // Session B is a different session to the backend: first turn, no risk,
      // allowed. A's refusal did not touch it.
      if (cleanTier !== 'allow') {
        throw new Error(
          `session B was ${cleanTier} because of session A's refusal — sessions are ` +
            'not isolated, which is the cross-user hold forSession() exists to prevent'
        );
      }
      if (bState.session_turn_number !== 1) {
        throw new Error(
          `session B's first scan was turn ${bState.session_turn_number}, expected 1 — ` +
            'B is being correlated into another session'
        );
      }
      if ((bState.session_risk_score ?? 0) !== 0) {
        throw new Error(`session B carries risk ${bState.session_risk_score} it never earned`);
      }
    },
    120000
  );

  // Ordering: no probe below the attack probes may assert 'allow' on the
  // shared client. It scans under the run's session id, so once that session
  // has accumulated enough risk, every later scan in it is legitimately held.
  // See the benign test above. Probes on explicit fresh sessions (forSession)
  // are not subject to this; see the isolation test.
  //
  // Not yet exposed by any SDK: a session reset. The backend and the MCP
  // server provide one.
});
