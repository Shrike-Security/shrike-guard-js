/**
 * Govern an agent built on the Claude Agent SDK.
 *
 * Three lines in the caller, and every action the agent takes is judged by
 * Shrike before it executes:
 *
 * ```ts
 * import { query } from '@anthropic-ai/claude-agent-sdk';
 * import { ScanClient } from 'shrike-guard';
 * import { govern } from 'shrike-guard/claude-agent';
 *
 * const guard = new ScanClient({ apiKey: KEY });
 * const gov = govern(guard, { agentId: 'invoice-agent' });
 * for await (const m of query({ prompt, options: { hooks: gov.hooks, mcpServers: { shrike: gov.mcpServer } } })) { ... }
 * ```
 *
 * A thin adapter over `shrike-guard`'s framework-free core (`govern.ts`).
 *
 * The act plane is a `PreToolUse` hook: every built-in tool call goes to
 * Shrike first. `Bash` goes to the command scan; `Write`, `Edit`,
 * `MultiEdit` and `NotebookEdit` to the file scan for the path and again for
 * the content; `Read` to the file scan; `WebSearch` and `WebFetch` to the
 * web-search scan. The verdict becomes the SDK's permission decision. A held
 * action (outside the declared scope) is denied by default, or answered
 * `ask` with `onHold: 'ask'`, which routes it to your `canUseTool` callback
 * with Shrike's reason. An unmapped tool that reaches the hook is allowed and
 * AUTHORIZED (`onUnmapped: 'authorize'`, this adapter's default): its
 * arguments stay put, and its name goes to the backend so the operator's
 * declared scope can answer. A tool outside the allowlist is refused by name
 * even though nothing read what it was carrying. Pass `onUnmapped: 'deny'` to
 * refuse anything you have not mapped, or `'allow'` to record it and move on
 * without asking.
 *
 * The observe plane is a `UserPromptSubmit` hook: the person's prompt is
 * scanned on the way in and never blocked; a finding becomes context.
 *
 * One MCP tool, `request_scope`, is the agent's channel for asking for more
 * than it holds. The backend decides.
 *
 * Requires `@anthropic-ai/claude-agent-sdk` and `zod`.
 */

import { createSdkMcpServer, tool } from '@anthropic-ai/claude-agent-sdk';
import type {
  HookCallback,
  HookCallbackMatcher,
  HookEvent,
  HookInput,
  HookJSONOutput,
  McpSdkServerConfigWithInstance,
} from '@anthropic-ai/claude-agent-sdk';
import { z } from 'zod';

import {
  Governance as CoreGovernance,
  REQUEST_SCOPE_DESCRIPTION,
  REQUEST_SCOPE_NAME,
  type GovernanceOptions,
  type Guard,
  type ToolMapping,
} from '../govern';
import type { ScanClient } from '../scanner';

export type { Decision, Outcome, ToolMapping, GovernanceOptions } from '../govern';

/** Name of the in-process MCP server the adapter builds. */
export const MCP_SERVER_NAME = 'shrike';
/** The tool name the model sees for the scope request. */
export const REQUEST_SCOPE_TOOL = `mcp__${MCP_SERVER_NAME}__${REQUEST_SCOPE_NAME}`;

function editContent(input: Record<string, unknown>): string {
  for (const key of ['content', 'new_string', 'new_source']) {
    const v = input[key];
    if (v) return String(v);
  }
  const edits = input.edits;
  if (Array.isArray(edits)) {
    return edits
      .map((e) => (e && typeof e === 'object' ? String((e as Record<string, unknown>).new_string ?? '') : ''))
      .filter(Boolean)
      .join('\n');
  }
  return '';
}

/** The SDK's built-in tools and the Shrike surface each one is. */
export const DEFAULT_TOOLS: Record<string, ToolMapping> = {
  Bash: { surface: 'command', arg: 'command', cwdArg: 'cwd' },
  Write: { surface: 'file', pathArg: 'file_path', contentArg: editContent },
  Edit: { surface: 'file', pathArg: 'file_path', contentArg: editContent },
  MultiEdit: { surface: 'file', pathArg: 'file_path', contentArg: editContent },
  NotebookEdit: { surface: 'file', pathArg: 'notebook_path', contentArg: editContent },
  Read: { surface: 'file_path', arg: 'file_path' },
  WebSearch: { surface: 'web_search', arg: 'query' },
  WebFetch: { surface: 'web_search', arg: 'url' },
};

/** Tools the act-plane hook matches by default. */
export const ACT_PLANE_TOOLS = Object.keys(DEFAULT_TOOLS);

function preToolOutput(decision: 'allow' | 'deny' | 'ask', reason: string): HookJSONOutput {
  return { hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: decision, permissionDecisionReason: reason } };
}

export class Governance extends CoreGovernance {
  /** Tool names to add to `allowedTools` so the model may call `request_scope`. */
  readonly toolNames: string[] = [REQUEST_SCOPE_TOOL];
  private hooksCache?: Partial<Record<HookEvent, HookCallbackMatcher[]>>;
  private serverCache?: McpSdkServerConfigWithInstance;

  constructor(guard: Guard | ScanClient, options: GovernanceOptions) {
    super(guard, { ...options, tools: { ...DEFAULT_TOOLS, ...(options.tools ?? {}) }, onUnmapped: options.onUnmapped ?? 'authorize' });
  }

  /** The act-plane hook. Returns the SDK's hook output. */
  readonly preToolUse: HookCallback = async (input: HookInput): Promise<HookJSONOutput> => {
    if (input.hook_event_name !== 'PreToolUse') return {};
    const args = (input.tool_input && typeof input.tool_input === 'object' ? input.tool_input : {}) as Record<string, unknown>;
    const out = await this.evaluate(input.tool_name, args, 'PreToolUse');
    if (out.decision === 'hold') return preToolOutput(this.onHold === 'ask' ? 'ask' : 'deny', out.message);
    if (out.decision === 'deny') return preToolOutput('deny', out.message);
    if (out.advisories.length) return { hookSpecificOutput: { hookEventName: 'PreToolUse', additionalContext: out.advisories.join(' ') } };
    return {};
  };

  /** The observe-plane hook. Never blocks; a finding becomes context. */
  readonly userPromptSubmit: HookCallback = async (input: HookInput): Promise<HookJSONOutput> => {
    if (input.hook_event_name !== 'UserPromptSubmit') return {};
    const d = await this.observePrompt(String(input.prompt ?? ''), 'UserPromptSubmit');
    const note = CoreGovernance.observeNote(d);
    if (!note) return {};
    return { hookSpecificOutput: { hookEventName: 'UserPromptSubmit', additionalContext: note } };
  };

  /** The `request_scope` MCP tool body. A refusal is an error result. */
  async requestScopeTool(args: { tools: string[]; reason?: string }): Promise<{ content: Array<{ type: 'text'; text: string }>; isError?: boolean }> {
    const res = await this.requestScope(args.tools ?? [], args.reason);
    return res.ok ? { content: [{ type: 'text', text: res.message }] } : { content: [{ type: 'text', text: res.message }], isError: true };
  }

  /**
   * `hooks` for the SDK options, matching the given tools. Defaults to every
   * mapped tool. Pass a wider list to route unmapped tools through the gate,
   * where `onUnmapped` decides. Defaults to EVERY tool.
   */
  hooksFor(toolNames?: string[]): Partial<Record<HookEvent, HookCallbackMatcher[]>> {
    // No names given means every tool the agent can call, not only the ones
    // this SDK knows how to read. A tool with no reader is exactly the tool
    // whose authorization nobody has checked, so the gate has to see it;
    // `onUnmapped` then decides what happens. Naming tools narrows the
    // matcher, at the cost of everything left outside it going unseen.
    const matchers: Partial<Record<HookEvent, HookCallbackMatcher[]>> = {
      PreToolUse: toolNames?.length
        ? [{ matcher: toolNames.join('|'), hooks: [this.preToolUse] }]
        : [{ hooks: [this.preToolUse] }],
    };
    if (this.observe) matchers.UserPromptSubmit = [{ hooks: [this.userPromptSubmit] }];
    return matchers;
  }

  /** `hooks` for the SDK options. */
  get hooks(): Partial<Record<HookEvent, HookCallbackMatcher[]>> {
    if (!this.hooksCache) this.hooksCache = this.hooksFor();
    return this.hooksCache;
  }

  /** The in-process MCP server carrying `request_scope`; pass it as `mcpServers: { shrike: gov.mcpServer }`. */
  get mcpServer(): McpSdkServerConfigWithInstance {
    if (!this.serverCache) {
      const requestScope = tool(
        REQUEST_SCOPE_NAME,
        REQUEST_SCOPE_DESCRIPTION,
        { tools: z.array(z.string()), reason: z.string().optional() },
        async (args) => this.requestScopeTool(args as { tools: string[]; reason?: string })
      );
      this.serverCache = createSdkMcpServer({ name: MCP_SERVER_NAME, version: '1.0.0', tools: [requestScope] });
    }
    return this.serverCache;
  }
}

/** Build the governance for one agent. */
export function govern(guard: Guard | ScanClient, options: GovernanceOptions): Governance {
  return new Governance(guard, options);
}
