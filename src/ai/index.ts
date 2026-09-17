/**
 * Govern an agent built with the Vercel AI SDK (`ai`).
 *
 * ```ts
 * import { generateText, wrapLanguageModel } from 'ai';
 * import { ScanClient } from 'shrike-guard';
 * import { govern } from 'shrike-guard/ai';
 *
 * const guard = new ScanClient({ apiKey: KEY });
 * const gov = govern(guard, { agentId: 'invoice-agent' }).mapTool('runQuery', { surface: 'sql', arg: 'query' });
 * const result = await generateText({
 *   model: wrapLanguageModel({ model, middleware: gov.middleware }),
 *   tools: gov.governTools({ runQuery, saveReport, request_scope: gov.tool }),
 *   prompt,
 * });
 * ```
 *
 * A thin adapter over `shrike-guard`'s framework-free core (`govern.ts`).
 *
 * The act plane wraps each tool's `execute`: Shrike judges the call through
 * the tool's mapping before the inner `execute` runs. A refused or held call
 * never runs; the wrapper returns Shrike's reason and the recovery as the
 * tool's result, so the model reads why and what to do next. Tools with no
 * mapping are refused by default (`onUnmapped: 'deny'`).
 *
 * The observe plane is a language-model middleware whose `transformParams`
 * scans the latest user message on the way in, once per message, and never
 * blocks. A finding is prepended to the prompt as a system message.
 *
 * `request_scope` is available as `gov.tool`; add it to the tool set. A held
 * action is answered like a refusal whatever `onHold` says; use the SDK's
 * `needsApproval` if the run itself should pause.
 *
 * Requires `ai` and `zod`.
 */

import { tool, type LanguageModelMiddleware, type Tool, type ToolSet } from 'ai';
import { z } from 'zod';

import {
  Governance as CoreGovernance,
  REQUEST_SCOPE_DESCRIPTION,
  isAllowed,
  type GovernanceOptions,
  type Guard,
} from '../govern';
import type { ScanClient } from '../scanner';

export type { Decision, Outcome, ToolMapping, GovernanceOptions } from '../govern';

type PromptMessage = { role: string; content: unknown };

/** The latest user message's text in a language-model prompt. */
export function lastUserText(prompt: unknown): string {
  if (!Array.isArray(prompt)) return '';
  for (let i = prompt.length - 1; i >= 0; i--) {
    const m = prompt[i] as PromptMessage;
    if (m?.role !== 'user') continue;
    if (typeof m.content === 'string') return m.content;
    if (Array.isArray(m.content)) {
      const text = m.content
        .map((p) => ((p as { type?: string; text?: string })?.type === 'text' ? String((p as { text?: string }).text ?? '') : ''))
        .join(' ')
        .trim();
      if (text) return text;
    }
  }
  return '';
}

function asRecord(v: unknown): Record<string, unknown> {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : { input: v };
}

export class Governance extends CoreGovernance {
  private toolCache?: Tool;
  private middlewareCache?: LanguageModelMiddleware;
  private lastObserved?: string;

  /** Wrap each tool's `execute` so Shrike judges its calls. Returns a new tool set. */
  governTools<T extends ToolSet>(tools: T): T {
    const out: Record<string, Tool> = {};
    for (const [name, t] of Object.entries(tools)) {
      const inner = t as Tool & { execute?: (input: unknown, options: unknown) => unknown };
      if (typeof inner.execute !== 'function') {
        out[name] = inner;
        continue;
      }
      const execute = inner.execute.bind(inner);
      out[name] = {
        ...inner,
        execute: async (input: unknown, options: unknown) => {
          const verdict = await this.evaluate(name, asRecord(input), 'execute');
          if (!isAllowed(verdict)) return verdict.message;
          return execute(input, options);
        },
      } as Tool;
    }
    return out as T;
  }

  /** `request_scope` as an AI SDK tool; add it to your tool set under that name. */
  get tool(): Tool {
    if (!this.toolCache) {
      this.toolCache = tool({
        description: REQUEST_SCOPE_DESCRIPTION,
        inputSchema: z.object({ tools: z.array(z.string()), reason: z.string().optional() }),
        execute: async ({ tools, reason }: { tools: string[]; reason?: string }) => (await this.requestScope(tools, reason)).message,
      }) as Tool;
    }
    return this.toolCache;
  }

  /** Scan a new user message in a prompt, once. Returns the note to prepend, or empty. */
  async observePromptMessages(prompt: unknown): Promise<string> {
    if (!this.observe) return '';
    const text = lastUserText(prompt);
    if (!text || text === this.lastObserved) return '';
    this.lastObserved = text;
    return CoreGovernance.observeNote(await this.observePrompt(text, 'transformParams'));
  }

  /** The observe-plane middleware for `wrapLanguageModel({ model, middleware })`. */
  get middleware(): LanguageModelMiddleware {
    if (!this.middlewareCache) {
      this.middlewareCache = {
        transformParams: async ({ params }: { params: any }) => {
          const note = await this.observePromptMessages(params?.prompt);
          if (!note) return params;
          return { ...params, prompt: [{ role: 'system', content: note }, ...(params.prompt ?? [])] };
        },
      } as LanguageModelMiddleware;
    }
    return this.middlewareCache;
  }
}

/** Build the governance for one agent. */
export function govern(guard: Guard | ScanClient, options: GovernanceOptions): Governance {
  return new Governance(guard, options);
}
