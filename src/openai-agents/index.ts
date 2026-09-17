/**
 * Govern an agent built on the OpenAI Agents SDK.
 *
 * ```ts
 * import { Agent, run } from '@openai/agents';
 * import { ScanClient } from 'shrike-guard';
 * import { govern } from 'shrike-guard/openai-agents';
 *
 * const guard = new ScanClient({ apiKey: KEY });
 * const gov = govern(guard, { agentId: 'invoice-agent' }).mapTool('run_query', { surface: 'sql', arg: 'query' });
 * const agent = gov.governAgent(new Agent({ name: 'invoices', tools: [runQuery, saveReport] }));
 * ```
 *
 * A thin adapter over `shrike-guard`'s framework-free core (`govern.ts`).
 *
 * The act plane is a tool input guardrail on every function tool. The SDK
 * runs it before the tool executes; a refused or held call is answered with
 * `rejectContent`, so the tool never runs and the model reads Shrike's
 * reason and the recovery as the tool's output. Tools with no mapping are
 * refused by default (`onUnmapped: 'deny'`) with a message that says how to
 * map them.
 *
 * The observe plane is an input guardrail that never trips: the run's input
 * is scanned and recorded, and the finding is on `decisions` and in the
 * guardrail's `outputInfo`.
 *
 * `request_scope` is added to the agent by `governAgent`. A held action is
 * answered like a refusal whatever `onHold` says, because a tool guardrail
 * cannot pause a run for a person; use the SDK's `needsApproval` for that.
 *
 * Requires `@openai/agents` and `zod`.
 */

import {
  defineToolInputGuardrail,
  tool,
  type Agent,
  type InputGuardrail,
  type ToolGuardrailFunctionOutput,
  type ToolInputGuardrailData,
  type ToolInputGuardrailDefinition,
} from '@openai/agents';
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

export const GUARDRAIL_NAME = 'shrike';

/** The SDK hands tool arguments as a JSON string; make them a record. */
export function parseArguments(raw: unknown): Record<string, unknown> {
  if (raw && typeof raw === 'object' && !Array.isArray(raw)) return raw as Record<string, unknown>;
  if (!raw) return {};
  try {
    const parsed = JSON.parse(String(raw));
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : { input: parsed };
  } catch {
    return { input: String(raw) };
  }
}

/** The person's text in a run input: a string, or the last user item. */
export function inputText(value: unknown): string {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) {
    for (let i = value.length - 1; i >= 0; i--) {
      const item = value[i] as { role?: string; content?: unknown };
      if (item && item.role === 'user') {
        if (typeof item.content === 'string') return item.content;
        if (Array.isArray(item.content)) {
          return item.content.map((p) => String((p as { text?: string })?.text ?? '')).join(' ');
        }
      }
    }
  }
  return '';
}

/** Translate an Outcome into the SDK's guardrail output. */
export function guardrailOutput(out: Outcome): ToolGuardrailFunctionOutput {
  const outputInfo = { decision: out.decision, tool: out.tool, advisories: out.advisories };
  if (!isAllowed(out)) return { behavior: { type: 'rejectContent', message: out.message }, outputInfo };
  return { behavior: { type: 'allow' }, outputInfo };
}

export class Governance extends CoreGovernance {
  private guardrailCache?: ToolInputGuardrailDefinition;
  private inputGuardrailCache?: InputGuardrail;
  private toolCache?: ReturnType<typeof tool>;

  /** The guardrail function. Public so it can be driven without a run. */
  readonly toolInputGuardrail = async (data: ToolInputGuardrailData): Promise<ToolGuardrailFunctionOutput> => {
    const call = data.toolCall as { name?: string; arguments?: unknown };
    const out = await this.evaluate(String(call.name ?? ''), parseArguments(call.arguments), 'toolInputGuardrail');
    return guardrailOutput(out);
  };

  /** The tool input guardrail; attach it to any function tool. */
  get guardrail(): ToolInputGuardrailDefinition {
    if (!this.guardrailCache) this.guardrailCache = defineToolInputGuardrail({ name: GUARDRAIL_NAME, run: this.toolInputGuardrail });
    return this.guardrailCache;
  }

  /** Attach the guardrail to every function tool in `tools`; returns them. */
  governTools<T extends unknown[]>(tools: T): T {
    for (const t of tools) {
      const ft = t as { type?: string; inputGuardrails?: ToolInputGuardrailDefinition[] };
      if (ft.type !== 'function') continue;
      const existing = ft.inputGuardrails ?? [];
      if (!existing.includes(this.guardrail)) ft.inputGuardrails = [this.guardrail, ...existing];
    }
    return tools;
  }

  /** The observe-plane input guardrail. It never trips. */
  get inputGuardrail(): InputGuardrail {
    if (!this.inputGuardrailCache) {
      this.inputGuardrailCache = {
        name: GUARDRAIL_NAME,
        execute: async ({ input }) => {
          const d = await this.observePrompt(inputText(input), 'inputGuardrail');
          return { outputInfo: { note: CoreGovernance.observeNote(d) }, tripwireTriggered: false };
        },
      };
    }
    return this.inputGuardrailCache;
  }

  /** `request_scope` as a function tool. */
  get tool(): ReturnType<typeof tool> {
    if (!this.toolCache) {
      this.toolCache = tool({
        name: REQUEST_SCOPE_NAME,
        description: REQUEST_SCOPE_DESCRIPTION,
        parameters: z.object({ tools: z.array(z.string()), reason: z.string().nullable().optional() }),
        execute: async (args: { tools: string[]; reason?: string | null }) => (await this.requestScope(args.tools, args.reason ?? undefined)).message,
      });
    }
    return this.toolCache;
  }

  /** Guard every function tool on `agent`, add `request_scope`, add the observe guardrail. Returns the agent. */
  governAgent<A extends Agent<any, any>>(agent: A): A {
    this.governTools(agent.tools as unknown[]);
    if (!agent.tools.some((t) => (t as { name?: string }).name === REQUEST_SCOPE_NAME)) {
      (agent.tools as unknown[]).push(this.tool);
    }
    if (this.observe && !agent.inputGuardrails.includes(this.inputGuardrail)) agent.inputGuardrails.push(this.inputGuardrail);
    return agent;
  }
}

/** Build the governance for one agent. */
export function govern(guard: Guard | ScanClient, options: GovernanceOptions): Governance {
  return new Governance(guard, options);
}
