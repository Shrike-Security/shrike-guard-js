/**
 * Outcome reports: once a governed action ran or failed, the adapter says so,
 * naming the scan the backend kept a record of. The report never reads the
 * tool's result and never blocks the call.
 */

import { Governance as CoreGovernance } from '../../src/govern';
import { FakeGuard, ALLOW, ALLOW_WITH_ID, BLOCK } from './govern.fixtures';

// The Claude Agent SDK package is ESM-only, which ts-jest's CommonJS
// transform cannot load; the adapter uses two of its constructors, stood in
// for here the same way the framework suite does.
jest.mock('@anthropic-ai/claude-agent-sdk', () => ({
  tool: (name: string, description: string, inputSchema: unknown, handler: unknown) => ({ name, description, inputSchema, handler }),
  createSdkMcpServer: (options: { name: string; version?: string; tools?: unknown[] }) => ({ type: 'sdk', name: options.name, instance: { tools: options.tools ?? [] } }),
}));
// The Vercel AI SDK is ESM-only as well; its `tool` returns the definition it is given.
jest.mock('ai', () => ({ tool: (t: unknown) => t }));

/* eslint-disable @typescript-eslint/no-var-requires */
const { Governance: LangChainGovernance } = require('../../src/langchain');
const { Governance: AIGovernance } = require('../../src/ai');
const { Governance: ClaudeAgentGovernance } = require('../../src/claude-agent');

const RUN = { run: { surface: 'command' as const, arg: 'cmd' } };
const flush = () => new Promise((r) => setTimeout(r, 0));

describe('outcome reports', () => {
  test('the core reports each decision the backend kept a record of, with the event as source', async () => {
    const guard = new FakeGuard(ALLOW_WITH_ID);
    const gov = new CoreGovernance(guard, { agentId: 'a', tools: RUN });
    const out = await gov.evaluate('run', { cmd: 'ls' }, 'unit');
    await gov.reportOutcome(out, 'executed', { exitStatus: 0 });
    expect(guard.outcomes).toEqual([{ scanId: 'scan_allow_1', outcome: 'executed', source: 'unit', exitStatus: 0 }]);
  });

  test('no scan id means nothing to name, and a guard without the method is silently fine', async () => {
    const guard = new FakeGuard(ALLOW);
    const gov = new CoreGovernance(guard, { agentId: 'a', tools: RUN });
    await gov.reportOutcome(await gov.evaluate('run', { cmd: 'ls' }), 'executed');
    expect(guard.outcomes).toEqual([]);
    const bare = new FakeGuard(ALLOW_WITH_ID) as unknown as { reportOutcome?: unknown };
    delete bare.reportOutcome;
    const gov2 = new CoreGovernance(bare as unknown as FakeGuard, { agentId: 'a', tools: RUN });
    await expect(gov2.reportOutcome(await gov2.evaluate('run', { cmd: 'ls' }), 'failed')).resolves.toBeUndefined();
  });

  test('langchain wrapToolCall reports executed on return and failed on throw, never on a refusal', async () => {
    const guard = new FakeGuard(ALLOW_WITH_ID);
    const gov = new LangChainGovernance(guard, { agentId: 'a', tools: RUN });
    const request = { toolCall: { name: 'run', args: { cmd: 'ls' }, id: 't1' } };
    expect(await gov.wrapToolCall(request, async () => 'ok')).toBe('ok');
    await expect(gov.wrapToolCall(request, async () => { throw new Error('boom'); })).rejects.toThrow('boom');
    await flush();
    expect(guard.outcomes.map((o) => o.outcome)).toEqual(['executed', 'failed']);
    expect(guard.outcomes.every((o) => o.source === 'wrapToolCall')).toBe(true);

    const blocked = new FakeGuard({ ...(BLOCK as object), scan_id: 'scan_block_1' } as typeof BLOCK);
    const gov2 = new LangChainGovernance(blocked, { agentId: 'a', tools: RUN });
    await gov2.wrapToolCall(request, async () => 'never');
    await flush();
    expect(blocked.outcomes).toEqual([]);
  });

  test('vercel execute reports likewise', async () => {
    const guard = new FakeGuard(ALLOW_WITH_ID);
    const gov = new AIGovernance(guard, { agentId: 'a', tools: { ...RUN, broken: { surface: 'command' as const, arg: 'cmd' } } });
    const tools = gov.governTools({
      run: { description: 'run', execute: async () => 'ok' },
      broken: { description: 'broken', execute: async () => { throw new Error('boom'); } },
    } as never) as unknown as Record<string, { execute: (i: unknown, o: unknown) => Promise<unknown> }>;
    expect(await tools.run.execute({ cmd: 'ls' }, {})).toBe('ok');
    await expect(tools.broken.execute({ cmd: 'ls' }, {})).rejects.toThrow('boom');
    await flush();
    expect(guard.outcomes.map((o) => o.outcome)).toEqual(['executed', 'failed']);
  });

  test('claude agent hooks pair the outcome with the call by tool_use_id', async () => {
    const guard = new FakeGuard(ALLOW_WITH_ID);
    const gov = new ClaudeAgentGovernance(guard, { agentId: 'a' });
    const pre = { hook_event_name: 'PreToolUse', tool_name: 'Bash', tool_input: { command: 'ls' }, session_id: 's', transcript_path: '', cwd: '' } as never;
    await gov.preToolUse(pre, 'tu1', { signal: new AbortController().signal });
    await gov.preToolUse(pre, 'tu2', { signal: new AbortController().signal });
    await gov.postToolUse({ hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: {}, tool_response: {} } as never, 'tu1', { signal: new AbortController().signal });
    await gov.postToolUse({ hook_event_name: 'PostToolUseFailure', tool_name: 'Bash', tool_input: {} } as never, 'tu2', { signal: new AbortController().signal });
    await gov.postToolUse({ hook_event_name: 'PostToolUse', tool_name: 'Bash', tool_input: {} } as never, 'unknown', { signal: new AbortController().signal });
    expect(guard.outcomes.map((o) => [o.outcome, o.source])).toEqual([['executed', 'PreToolUse'], ['failed', 'PreToolUse']]);
    const hooks = gov.hooksFor(['Bash']);
    expect(Object.keys(hooks).sort()).toEqual(['PostToolUse', 'PostToolUseFailure', 'PreToolUse', 'UserPromptSubmit']);
    expect(hooks.PostToolUse?.[0].matcher).toBe('Bash');
  });
});
