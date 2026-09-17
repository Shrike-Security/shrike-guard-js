/**
 * Conformance: every framework adapter answers the same table the same way.
 * Contract-symmetric with tests/test_frameworks.py on the Python SDK.
 *
 * Each driver translates one scenario into its framework's hook shape,
 * drives the adapter, and reports ('allowed' | 'refused', message).
 */

import { ALLOW, BLOCK, FakeGuard, HOLD, WARN, refused } from './govern.fixtures';
import type { ScanResult } from '../../src/scanner';

type Driver = (gov: any, name: string, args: Record<string, unknown>) => Promise<[string, string]>;

const down = () => {
  const e = new Error('connect');
  e.name = 'ConnectError';
  return e;
};

const SCENARIOS: Array<[string, ScanResult | undefined, Error | undefined, string, string]> = [
  ['allow', ALLOW, undefined, 'allowed', ''],
  ['warn is allowed', WARN, undefined, 'allowed', ''],
  ['block', BLOCK, undefined, 'refused', 'Shrike blocked this sql: exfil pattern'],
  ['hold names the recovery', HOLD, undefined, 'refused', 'Shrike held this sql'],
  ['backend down fails closed', undefined, down(), 'refused', 'Shrike could not check this sql'],
];

function build(mod: { govern: (g: any, o: any) => any }, verdict?: ScanResult, rejectWith?: Error, extra: Record<string, unknown> = {}) {
  const guard = new FakeGuard(verdict ?? ALLOW, rejectWith);
  const gov = mod.govern(guard, { agentId: 'conformance', ...extra });
  gov.mapTool('run_query', { surface: 'sql', arg: 'query' });
  return gov;
}

async function checkRow(mod: any, drive: Driver, verdict: ScanResult | undefined, rejectWith: Error | undefined, expected: string, prefix: string) {
  const gov = build(mod, verdict, rejectWith);
  const [result, message] = await drive(gov, 'run_query', { query: 'select 1' });
  expect(result).toBe(expected);
  expect(message.startsWith(prefix)).toBe(true);
}

async function checkUnmapped(mod: any, drive: Driver) {
  const gov = build(mod, ALLOW, undefined, { onUnmapped: 'deny' });
  const [result, message] = await drive(gov, 'send_mail', { to: 'x' });
  expect(result).toBe('refused');
  expect(message).toContain("mapTool('send_mail'");
}

async function checkScope(mod: any) {
  const gov = build(mod, ALLOW);
  (gov.guard as FakeGuard).declareRejects = refused('widening');
  const res = await gov.requestScope(['command']);
  expect(res.ok).toBe(false);
  expect(res.message.startsWith('Refused (widening)')).toBe(true);
}

// --- Claude Agent SDK ----------------------------------------------------------
//
// The Claude Agent SDK package is ESM-only, which ts-jest's CommonJS transform
// cannot load. The adapter calls exactly two of its constructors, `tool` and
// `createSdkMcpServer`, so those are stood in for here with the shapes the
// real ones return; the hook and MCP behaviour under test is the adapter's.

jest.mock('@anthropic-ai/claude-agent-sdk', () => ({
  tool: (name: string, description: string, inputSchema: unknown, handler: unknown) => ({ name, description, inputSchema, handler }),
  createSdkMcpServer: (options: { name: string; version?: string; tools?: unknown[] }) => ({ type: 'sdk', name: options.name, instance: { tools: options.tools ?? [] } }),
}));

const claude = require('../../src/claude-agent');

const claudeDrive: Driver = async (gov, name, args) => {
  const out = await gov.preToolUse({ hook_event_name: 'PreToolUse', tool_name: name, tool_input: args, tool_use_id: 't1', session_id: 's', transcript_path: '', cwd: '' }, 't1', { signal: new AbortController().signal });
  const hso = out.hookSpecificOutput ?? {};
  if (hso.permissionDecision === 'deny' || hso.permissionDecision === 'ask') return ['refused', hso.permissionDecisionReason ?? ''];
  return ['allowed', hso.additionalContext ?? ''];
};

describe('claude-agent', () => {
  it.each(SCENARIOS)('%s', (_label, verdict, rejectWith, expected, prefix) => checkRow(claude, claudeDrive, verdict, rejectWith, expected, prefix));
  it('unmapped, scope, and wiring', async () => {
    await checkUnmapped(claude, claudeDrive);
    await checkScope(claude);
    const gov = build(claude, ALLOW);
    // No matcher string: the gate sees every tool the agent can call, not
    // only the ones this SDK knows how to read. Naming tools narrows it.
    expect(gov.hooks.PreToolUse[0].matcher).toBeUndefined();
    expect(gov.hooksFor(['Bash', 'Write']).PreToolUse[0].matcher).toBe('Bash|Write');
    expect(gov.hooks.UserPromptSubmit).toHaveLength(1);
    expect(gov.mcpServer.name).toBe('shrike');
    expect(gov.toolNames).toEqual(['mcp__shrike__request_scope']);
    const hold = build(claude, HOLD, undefined, { onHold: 'ask' });
    const [, msg] = await claudeDrive(hold, 'run_query', { query: 'select 1' });
    expect(msg).toContain('Shrike held this sql');
    const res = await gov.requestScopeTool({ tools: ['command'] });
    expect(res.content[0].text.startsWith('Scope now:')).toBe(true);
  });
  it('the built-in tools are mapped and observe adds context', async () => {
    const guard = new FakeGuard(BLOCK);
    const gov = claude.govern(guard, { agentId: 'a' });
    const out = await gov.preToolUse({ hook_event_name: 'PreToolUse', tool_name: 'MultiEdit', tool_input: { file_path: '/w/a', edits: [{ new_string: 'x' }, { new_string: 'y' }] }, tool_use_id: 't', session_id: 's', transcript_path: '', cwd: '' }, 't', { signal: new AbortController().signal });
    expect(out.hookSpecificOutput.permissionDecision).toBe('deny');
    expect(guard.calls[0]).toEqual(['file_path', '/w/a', undefined]);
    const note = await gov.userPromptSubmit({ hook_event_name: 'UserPromptSubmit', prompt: 'hi', session_id: 's', transcript_path: '', cwd: '' }, undefined, { signal: new AbortController().signal });
    expect(note.hookSpecificOutput.additionalContext).toMatch(/^Shrike observe-plane note/);
  });
});

// --- OpenAI Agents SDK ---------------------------------------------------------

const openai = require('../../src/openai-agents');

const openaiDrive: Driver = async (gov, name, args) => {
  const out = await gov.toolInputGuardrail({ toolCall: { type: 'function_call', name, arguments: JSON.stringify(args), callId: 'c1' }, agent: {}, context: {} });
  if (out.behavior.type === 'rejectContent') return ['refused', out.behavior.message];
  return ['allowed', ''];
};

describe('openai-agents', () => {
  it.each(SCENARIOS)('%s', (_label, verdict, rejectWith, expected, prefix) => checkRow(openai, openaiDrive, verdict, rejectWith, expected, prefix));
  it('unmapped, scope, and wiring', async () => {
    await checkUnmapped(openai, openaiDrive);
    await checkScope(openai);
    const { Agent, tool } = require('@openai/agents');
    const { z } = require('zod');
    const runQuery = tool({ name: 'run_query', description: 'Run a query.', parameters: z.object({ query: z.string() }), execute: async ({ query }: { query: string }) => query });
    const gov = build(openai, ALLOW);
    const agent = gov.governAgent(new Agent({ name: 't', tools: [runQuery] }));
    expect(runQuery.inputGuardrails).toContain(gov.guardrail);
    expect(agent.tools[agent.tools.length - 1].name).toBe('request_scope');
    expect(agent.inputGuardrails).toContain(gov.inputGuardrail);
    expect(openai.parseArguments('not json')).toEqual({ input: 'not json' });
    expect(openai.inputText([{ role: 'user', content: 'hi' }])).toBe('hi');
    const observed = await gov.inputGuardrail.execute({ input: 'hi', agent, context: {} });
    expect(observed.tripwireTriggered).toBe(false);
  });
});

// --- Vercel AI SDK -------------------------------------------------------------
//
// `ai` is ESM-only too. The adapter uses its `tool()` helper, which returns
// the definition it is given; everything else under test is the adapter's.

jest.mock('ai', () => ({ tool: (t: unknown) => t }));

const ai = require('../../src/ai');

const aiDrive: Driver = async (gov, name, args) => {
  const ran: unknown[] = [];
  const tools = gov.governTools({ [name]: { description: 'd', inputSchema: {}, execute: async (input: unknown) => { ran.push(input); return 'ran'; } } });
  const result = await tools[name].execute(args, { toolCallId: 'c1', messages: [] });
  if (!ran.length) return ['refused', String(result)];
  return ['allowed', ''];
};

describe('ai', () => {
  it.each(SCENARIOS)('%s', (_label, verdict, rejectWith, expected, prefix) => checkRow(ai, aiDrive, verdict, rejectWith, expected, prefix));
  it('unmapped, scope, tool, and the observe middleware', async () => {
    await checkUnmapped(ai, aiDrive);
    await checkScope(ai);
    const gov = build(ai, ALLOW);
    expect(typeof gov.tool.execute).toBe('function');
    expect((await gov.tool.execute({ tools: ['command'] }, { toolCallId: 'c', messages: [] })).startsWith('Scope now:')).toBe(true);
    const flagged = build(ai, BLOCK);
    const params = { prompt: [{ role: 'user', content: [{ type: 'text', text: 'do the thing' }] }] };
    const once = await flagged.middleware.transformParams({ type: 'generate', params, model: {} });
    expect(once.prompt[0].role).toBe('system');
    expect(once.prompt[0].content).toMatch(/^Shrike observe-plane note/);
    const twice = await flagged.middleware.transformParams({ type: 'generate', params, model: {} });
    expect(twice).toBe(params);
    expect(ai.lastUserText(params.prompt)).toBe('do the thing');
  });
});

// --- LangChain / LangGraph -------------------------------------------------------

const langchain = require('../../src/langchain');

const langchainDrive: Driver = async (gov, name, args) => {
  const { ToolMessage } = require('@langchain/core/messages');
  const ran: unknown[] = [];
  const out = await gov.wrapToolCall({ toolCall: { name, args, id: 'c1' } }, (r: unknown) => { ran.push(r); return new ToolMessage({ content: 'ran', tool_call_id: 'c1' }); });
  if (!ran.length) {
    expect(out).toBeInstanceOf(ToolMessage);
    expect(out.status).toBe('error');
    return ['refused', String(out.content)];
  }
  return ['allowed', ''];
};

describe('langchain', () => {
  it.each(SCENARIOS)('%s', (_label, verdict, rejectWith, expected, prefix) => checkRow(langchain, langchainDrive, verdict, rejectWith, expected, prefix));
  it('unmapped, scope, wrapped tools, and the middleware', async () => {
    await checkUnmapped(langchain, langchainDrive);
    await checkScope(langchain);
    const { tool } = require('@langchain/core/tools');
    const { z } = require('zod');
    const runQuery = tool(async ({ query }: { query: string }) => `ran:${query}`, { name: 'run_query', description: 'Run a query.', schema: z.object({ query: z.string() }) });
    const held = build(langchain, HOLD);
    const governed = held.governTools([runQuery])[0];
    expect(governed.name).toBe('run_query');
    expect(String(await governed.invoke({ query: 'select 1' }))).toMatch(/^Shrike held this sql/);
    const ok = build(langchain, ALLOW);
    expect(await ok.governTools([runQuery])[0].invoke({ query: 'select 1' })).toBe('ran:select 1');
    expect(String(await ok.tool.invoke({ tools: ['command'] })).startsWith('Scope now:')).toBe(true);
    const mw = ok.middleware;
    expect(mw.name).toBe('shrike');
    expect(mw.tools.map((t: { name: string }) => t.name)).toEqual(['request_scope']);
    const { HumanMessage } = require('@langchain/core/messages');
    const flagged = build(langchain, BLOCK);
    await flagged.observeState({ messages: [new HumanMessage('do the thing')] });
    await flagged.observeState({ messages: [new HumanMessage('do the thing')] });
    expect(flagged.decisions.filter((d: { event: string }) => d.event === 'beforeAgent')).toHaveLength(1);
  });
});
