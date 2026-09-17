/**
 * Govern an agent built with LangChain `createAgent` or a LangGraph tool node.
 *
 * ```ts
 * import { createAgent } from 'langchain';
 * import { ScanClient } from 'shrike-guard';
 * import { govern } from 'shrike-guard/langchain';
 *
 * const guard = new ScanClient({ apiKey: KEY });
 * const gov = govern(guard, { agentId: 'invoice-agent' }).mapTool('run_query', { surface: 'sql', arg: 'query' });
 * const agent = createAgent({ model, tools: [runQuery, saveReport], middleware: [gov.middleware] });
 * ```
 *
 * For a hand-built graph with a `ToolNode`, wrap the tools instead:
 * `new ToolNode(gov.governTools([runQuery, saveReport]))`.
 *
 * A thin adapter over `shrike-guard`'s framework-free core (`govern.ts`).
 *
 * The act plane, two ways. `gov.middleware` is an agent middleware whose
 * `wrapToolCall` evaluates every tool call through the tool's mapping before
 * handing it to the tool; a refused or held call never runs, and the
 * middleware returns a `ToolMessage` carrying Shrike's reason and the
 * recovery, so the model reads it as the tool's result. `gov.governTools`
 * does the same by wrapping each tool. Tools with no mapping are refused by
 * default (`onUnmapped: 'deny'`).
 *
 * The observe plane: the middleware's `beforeAgent` scans the latest human
 * message on the way in and records the finding. It never blocks and does
 * not alter the conversation.
 *
 * `request_scope` is registered by the middleware. A held action is answered
 * like a refusal whatever `onHold` says; use LangGraph interrupts if the run
 * itself should pause.
 *
 * Requires `langchain`, `@langchain/core` and `zod`.
 */

import { createMiddleware } from 'langchain';
import { HumanMessage, ToolMessage } from '@langchain/core/messages';
import { tool, type StructuredToolInterface } from '@langchain/core/tools';
import { z } from 'zod';

import {
  Governance as CoreGovernance,
  REQUEST_SCOPE_DESCRIPTION,
  REQUEST_SCOPE_NAME,
  isAllowed,
  type GovernanceOptions,
  type Guard,
  type Outcome,
} from '../govern';
import type { ScanClient } from '../scanner';

export type { Decision, Outcome, ToolMapping, GovernanceOptions } from '../govern';

type ToolCallLike = { name?: string; args?: Record<string, unknown>; id?: string };
type RequestLike = { toolCall: ToolCallLike };

/** The latest human message's text in a LangChain message list. */
export function lastHumanText(messages: unknown): string {
  if (!Array.isArray(messages)) return '';
  for (let i = messages.length - 1; i >= 0; i--) {
    const m = messages[i];
    if (!(m instanceof HumanMessage)) continue;
    const content = (m as { content: unknown }).content;
    if (typeof content === 'string') return content;
    if (Array.isArray(content)) return content.map((p) => String((p as { text?: string })?.text ?? '')).join(' ');
  }
  return '';
}

/** The ToolMessage the model reads when a call is refused or held. */
export function refusalMessage(out: Outcome, toolCallId: string, name: string): ToolMessage {
  return new ToolMessage({ content: out.message, tool_call_id: toolCallId, name, status: 'error' });
}

export class Governance extends CoreGovernance {
  private toolCache?: StructuredToolInterface;
  private middlewareCache?: unknown;
  private lastObserved?: string;

  /** The middleware's hook. Public so it can be driven without a graph. */
  async wrapToolCall(request: RequestLike, handler: (request: RequestLike) => unknown): Promise<unknown> {
    const call = request.toolCall ?? {};
    const name = String(call.name ?? '');
    const out = await this.evaluate(name, call.args ?? {}, 'wrapToolCall');
    if (!isAllowed(out)) return refusalMessage(out, String(call.id ?? ''), name);
    return handler(request);
  }

  /** Scan the latest human message in an agent state, once. */
  async observeState(state: unknown): Promise<void> {
    const messages = (state as { messages?: unknown })?.messages;
    const text = lastHumanText(messages);
    if (!text || text === this.lastObserved) return;
    this.lastObserved = text;
    await this.observePrompt(text, 'beforeAgent');
  }

  /** Wrap each tool so Shrike judges its calls. Returns the wrapped tools. */
  governTools(tools: StructuredToolInterface[]): StructuredToolInterface[] {
    return tools.map((inner) => {
      const name = inner.name;
      const governed = tool(
        async (input: unknown) => {
          const out = await this.evaluate(name, (input && typeof input === 'object' ? input : { input }) as Record<string, unknown>, 'governedTool');
          if (!isAllowed(out)) return out.message;
          return (inner as { invoke: (i: unknown) => Promise<unknown> }).invoke(input);
        },
        { name, description: inner.description, schema: (inner as { schema?: unknown }).schema as any }
      );
      return governed as unknown as StructuredToolInterface;
    });
  }

  /** `request_scope` as a LangChain tool. */
  get tool(): StructuredToolInterface {
    if (!this.toolCache) {
      this.toolCache = tool(
        async ({ tools, reason }: { tools: string[]; reason?: string }) => (await this.requestScope(tools, reason)).message,
        {
          name: REQUEST_SCOPE_NAME,
          description: REQUEST_SCOPE_DESCRIPTION,
          schema: z.object({ tools: z.array(z.string()), reason: z.string().optional() }),
        }
      ) as unknown as StructuredToolInterface;
    }
    return this.toolCache;
  }

  /** An agent middleware for `createAgent({ middleware: [gov.middleware] })`. */
  get middleware(): ReturnType<typeof createMiddleware> {
    if (!this.middlewareCache) {
      this.middlewareCache = createMiddleware({
        name: 'shrike',
        tools: [this.tool as any],
        beforeAgent: async (state: unknown) => {
          if (this.observe) await this.observeState(state);
          return undefined;
        },
        wrapToolCall: (request: any, handler: any) => this.wrapToolCall(request, handler) as any,
      } as any);
    }
    return this.middlewareCache as ReturnType<typeof createMiddleware>;
  }
}

/** Build the governance for one agent. */
export function govern(guard: Guard | ScanClient, options: GovernanceOptions): Governance {
  return new Governance(guard, options);
}
