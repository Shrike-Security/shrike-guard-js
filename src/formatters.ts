/**
 * Canonical formatters for Shrike verdict-to-prompt injection.
 *
 * Implements the block-feedback layer (layer 4) of the four-layer
 * self-consultation stack described in the integration guide:
 *
 *   1. System prompt tells the agent HOW to work with Shrike
 *   2. MCP tools give the agent CHANNELS to consult Shrike
 *   3. SDK guard is the deterministic enforcement floor
 *   4. Block-feedback injection (this module) closes the learning loop
 *
 * When the SDK guard blocks a tool call, the developer's control flow
 * can call `formatBlockFeedback(verdict)` and append the returned
 * string as a system message to the model's next turn. The model reads
 * Shrike's reason + recovery guidance and adjusts, rather than looping
 * on the same blocked action.
 *
 * The rendering is stable across SDK versions so cookbook prompt
 * templates can teach the model to recognize the "Shrike blocked"
 * prefix and act on the structured fields inside.
 *
 * This helper is verdict-shape-tolerant: it accepts partial objects
 * and uses optional-chaining throughout. When the backend ships the
 * `recovery` block (with `instruction`, `available_tools`,
 * `patterns_triggered`), this helper picks up the new fields
 * automatically without a signature change.
 *
 * Mirrors the Python `format_block_feedback` in
 * platform/sdks/python/src/shrike_guard/formatters.py — keep the two
 * in sync when either shape changes.
 */

const BLOCK_PREFIX = 'Shrike blocked your last tool call.';
const WARN_PREFIX = 'Shrike flagged your last tool call (advisory).';
const APPROVAL_PREFIX = 'Shrike is holding your last tool call for approval.';

/**
 * Verdict-shape input to `formatBlockFeedback`. All fields are optional.
 * The helper renders whatever it finds and stays silent on missing
 * fields — empty verdicts render just the block prefix.
 */
export interface BlockFeedbackVerdict {
  action?: 'block' | 'warn' | 'require_approval' | 'allow' | string;
  threat_type?: string;
  reason?: string;
  /**
   * The MCP sanitizer emits `guidance` today; the future
   * `/api/scan/enforce` endpoint will emit `reason`. Helper falls back
   * from `reason` to `guidance` so current MCP-shaped verdicts render.
   */
  guidance?: string;
  session_state?: {
    session_risk_score?: number;
    session_turn_number?: number;
    session_patterns?: string[];
  };
  recovery?: {
    instruction?: string;
    available_tools?: string[];
    patterns_triggered?: string[];
  };
  [key: string]: unknown;
}

/**
 * Render a canonical prompt-shape string from a Shrike verdict.
 *
 * The rendered string is designed to be injected as a system message
 * into the model's next turn, so it uses a stable prefix + a small
 * set of well-named field lines the model can reason over.
 *
 * Recognized verdict keys (all optional):
 *
 * - `action`: `"block"` | `"warn"` | `"require_approval"` | `"allow"`.
 *   Selects the prefix. Defaults to `"block"` when the verdict is
 *   non-empty and no action is set — matches the primary use case
 *   (a developer catching a block verdict and wanting the model to
 *   know why).
 * - `threat_type`: canonical Shrike threat type string.
 * - `reason`: human-readable explanation. Falls back to `guidance`
 *   when `reason` is absent.
 * - `session_state.session_risk_score` + `session_turn_number` +
 *   `session_patterns`: the L9 session outcome block.
 * - `recovery.instruction`: the "what to do next" hint.
 * - `recovery.available_tools`: which tools remain callable under
 *   the current quarantine posture.
 * - `recovery.patterns_triggered`: which correlator patterns fired
 *   on THIS block. Prefers this over
 *   `session_state.session_patterns` when present, because the
 *   recovery block scopes to the triggering event rather than the
 *   whole session.
 *
 * @param verdict - any dict-shaped verdict from a Shrike SDK scan,
 *   the MCP sanitizer, or the future `/api/scan/enforce` endpoint.
 * @returns a single string suitable for use as the `content` of a
 *   system message in a downstream model call.
 *
 * @example
 * ```typescript
 * const verdict = {
 *   action: 'block',
 *   threat_type: 'data_exfiltration',
 *   reason: 'Command routes IMDS credentials to external endpoint',
 *   session_state: {
 *     session_risk_score: 0.85,
 *     session_turn_number: 4,
 *     session_patterns: ['multi_turn_reconnaissance'],
 *   },
 * };
 * console.log(formatBlockFeedback(verdict));
 * // Shrike blocked your last tool call.
 * // Reason: Command routes IMDS credentials to external endpoint
 * // Threat type: data_exfiltration
 * // Session risk: 0.85 (turn 4)
 * // Patterns triggered: multi_turn_reconnaissance
 * ```
 */
export function formatBlockFeedback(verdict: BlockFeedbackVerdict): string {
  const action = (verdict.action ?? 'block').toString().toLowerCase();
  const lines: string[] = [];

  if (action === 'warn') {
    lines.push(WARN_PREFIX);
  } else if (action === 'require_approval') {
    lines.push(APPROVAL_PREFIX);
  } else {
    // "block" is the default so callers can pass a raw block verdict
    // without threading action through explicitly.
    lines.push(BLOCK_PREFIX);
  }

  const reason = verdict.reason ?? verdict.guidance;
  if (reason) {
    lines.push(`Reason: ${reason}`);
  }

  if (verdict.threat_type) {
    lines.push(`Threat type: ${verdict.threat_type}`);
  }

  const sessionState = verdict.session_state ?? {};
  const risk = sessionState.session_risk_score;
  const turn = sessionState.session_turn_number;
  if (typeof risk === 'number') {
    if (typeof turn === 'number') {
      lines.push(`Session risk: ${risk} (turn ${turn})`);
    } else {
      lines.push(`Session risk: ${risk}`);
    }
  }

  // Prefer recovery.patterns_triggered (scoped to THIS triggering
  // event) over session_state.session_patterns (whole-session
  // accumulator). Falls through cleanly when neither is present.
  const recovery = verdict.recovery ?? {};
  const patterns =
    (recovery.patterns_triggered && recovery.patterns_triggered.length > 0
      ? recovery.patterns_triggered
      : undefined) ??
    (sessionState.session_patterns && sessionState.session_patterns.length > 0
      ? sessionState.session_patterns
      : undefined);
  if (patterns && patterns.length > 0) {
    lines.push(`Patterns triggered: ${patterns.join(', ')}`);
  }

  if (recovery.instruction) {
    lines.push(`Recovery: ${recovery.instruction}`);
  }

  if (recovery.available_tools && recovery.available_tools.length > 0) {
    lines.push(`Available tools: ${recovery.available_tools.join(', ')}`);
  }

  return lines.join('\n');
}
