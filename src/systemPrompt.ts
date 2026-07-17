/**
 * Canonical 'Working with Shrike' system-prompt block.
 *
 * Exposes the ~180-word block that teaches an agent how to react to
 * Shrike verdicts (the four refuse_tier states, the injected-message
 * prefix contract emitted by formatBlockFeedback, the per-event
 * rotation-recommendation contract).
 *
 * This module is the source of truth for the block string — the docs
 * page at docs/cookbook/working-with-shrike.md and the web UI's
 * Cookbook page render the same string.
 *
 * Usage:
 *
 * ```typescript
 * import { systemPrompt } from 'shrike-guard';
 *
 * const prompt = systemPrompt();
 * // returns the block string; drop into your agent's system prompt
 * // as the first non-role paragraph.
 * ```
 *
 * Future archetype templates (support, code-gen, RAG, research,
 * multi-agent, internal-copilot) will layer additions on top and
 * expose via a namespace object — e.g. systemPrompt.support() —
 * without changing this base signature.
 *
 * Mirrors platform/sdks/python/src/shrike_guard/system_prompt.py.
 * Keep the two in sync when the block content changes.
 *
 * Version: v1.0 (2026-07-06).
 */

const BLOCK_V1_0 =
  `You are operating in a Shrike-governed environment. Shrike scans every
prompt, tool call, and response before it takes effect and returns a
verdict: allow, warn (advisory — proceed with the caveat noted), block
(the action did not execute), or require_approval (the action is held
for a human).

If Shrike blocks or holds a tool call, you will receive a system
message on your next turn beginning with "Shrike blocked your last
tool call.", "Shrike flagged your last tool call (advisory).", or
"Shrike is holding your last tool call for approval." Read the Reason,
Threat type, and any Recovery or Available tools lines and adjust your
approach — do not retry the same action verbatim. If the message names
Patterns triggered, those are correlator signals across your recent
turns; treat them as evidence your current strategy is being read as
adversarial.

If Shrike returns a rotation recommendation (rotation_recommended:
true), adopt the suggested_new_session_id on your very next tool call.
Do not cache suggested ids across turns; they are minted per event.

Shrike is a collaborator, not an obstacle. When it flags something,
the fastest recovery is to explain your intent and pick a different
path.`;

/**
 * Version string for the canonical block. Integrators can pin
 * behavior against this without pinning the whole SDK.
 */
export const SYSTEM_PROMPT_VERSION = '1.0';

/**
 * Return the canonical 'Working with Shrike' system-prompt block.
 *
 * The returned string is designed to be dropped into your agent's
 * system prompt as the first non-role paragraph:
 *
 * ```typescript
 * const prompt =
 *   'You are a customer support agent for Acme Corp.\n\n' +
 *   systemPrompt() +
 *   '\n\nWhen customers ask about refunds, first verify...';
 * ```
 *
 * @returns The block string (~180 words, no trailing newline).
 */
export function systemPrompt(): string {
  return BLOCK_V1_0;
}
