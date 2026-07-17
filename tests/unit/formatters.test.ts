/**
 * Tests for src/formatters.ts.
 *
 * Verifies the canonical block-feedback rendering shape used by the
 * self-consultation stack's layer 4. The tests pin the current shape
 * AND verify graceful upgrade when the backend ships the `recovery`
 * block.
 *
 * Mirrors platform/sdks/python/tests/test_formatters.py — keep the two
 * suites aligned when either shape changes.
 */

import { formatBlockFeedback } from '../../src/formatters';

describe('formatBlockFeedback', () => {
  it('renders prefix for a minimal verdict with only threat_type', () => {
    const result = formatBlockFeedback({ threat_type: 'prompt_injection' });
    expect(result.startsWith('Shrike blocked your last tool call.')).toBe(true);
    expect(result).toContain('Threat type: prompt_injection');
  });

  it('renders prefix only for an empty verdict, does not crash', () => {
    const result = formatBlockFeedback({});
    expect(result).toBe('Shrike blocked your last tool call.');
  });

  it('renders full current MCP shape verdict', () => {
    const verdict = {
      action: 'block',
      threat_type: 'data_exfiltration',
      reason: 'Command routes IMDS credentials to external endpoint',
      session_state: {
        session_risk_score: 0.85,
        session_turn_number: 4,
        session_patterns: ['multi_turn_reconnaissance', 'multi_turn_escalation'],
      },
    };
    const result = formatBlockFeedback(verdict);
    expect(result).toContain('Shrike blocked your last tool call.');
    expect(result).toContain('Reason: Command routes IMDS credentials to external endpoint');
    expect(result).toContain('Threat type: data_exfiltration');
    expect(result).toContain('Session risk: 0.85 (turn 4)');
    expect(result).toContain('multi_turn_reconnaissance, multi_turn_escalation');
  });

  it('picks up recovery block shape without signature change (forward compat)', () => {
    const verdict = {
      action: 'block',
      threat_type: 'session_locked',
      session_state: {
        session_risk_score: 0.9,
        session_turn_number: 5,
        session_patterns: ['multi_turn_reconnaissance'],
      },
      recovery: {
        instruction: 'Rotate session_id and re-verify user intent before retry',
        available_tools: ['scan_prompt', 'scan_response', 'session_status'],
        patterns_triggered: ['multi_turn_reconnaissance'],
      },
    };
    const result = formatBlockFeedback(verdict);
    expect(result).toContain('Recovery: Rotate session_id and re-verify user intent');
    expect(result).toContain('Available tools: scan_prompt, scan_response, session_status');
  });

  it('prefers recovery.patterns_triggered over session_state.session_patterns', () => {
    const verdict = {
      session_state: {
        session_patterns: ['multi_turn_old_pattern'],
      },
      recovery: {
        patterns_triggered: ['multi_turn_new_pattern'],
      },
    };
    const result = formatBlockFeedback(verdict);
    expect(result).toContain('multi_turn_new_pattern');
    expect(result).not.toContain('multi_turn_old_pattern');
  });

  it('falls back to guidance when reason is absent (current MCP shape)', () => {
    const result = formatBlockFeedback({
      threat_type: 'sql_injection',
      guidance: 'This query contains dangerous SQL patterns.',
    });
    expect(result).toContain('Reason: This query contains dangerous SQL patterns.');
  });

  it('prefers reason over guidance when both present', () => {
    const result = formatBlockFeedback({
      reason: 'Explicit reason',
      guidance: 'Fallback guidance',
    });
    expect(result).toContain('Reason: Explicit reason');
    expect(result).not.toContain('Fallback guidance');
  });

  it('renders risk without turn qualifier when session_turn_number is missing', () => {
    const result = formatBlockFeedback({
      session_state: { session_risk_score: 0.5, session_patterns: [] },
    });
    expect(result).toContain('Session risk: 0.5');
    expect(result).not.toContain('(turn');
  });

  it('uses advisory prefix for action: warn', () => {
    const result = formatBlockFeedback({
      action: 'warn',
      threat_type: 'prompt_injection',
      reason: 'Elevated risk on this turn — proceed with caveat',
    });
    expect(result.startsWith('Shrike flagged your last tool call (advisory).')).toBe(true);
    expect(result).toContain('Reason: Elevated risk');
  });

  it('uses hold prefix for action: require_approval', () => {
    const result = formatBlockFeedback({
      action: 'require_approval',
      threat_type: 'destructive_operation',
    });
    expect(result.startsWith('Shrike is holding your last tool call for approval.')).toBe(true);
  });

  it('defaults to block prefix when action is unset', () => {
    const result = formatBlockFeedback({ threat_type: 'prompt_injection' });
    expect(result.startsWith('Shrike blocked your last tool call.')).toBe(true);
  });

  it('stays silent on empty session_patterns (no empty Patterns triggered line)', () => {
    const result = formatBlockFeedback({
      threat_type: 'prompt_injection',
      session_state: {
        session_risk_score: 0.3,
        session_turn_number: 2,
        session_patterns: [],
      },
    });
    expect(result).not.toContain('Patterns triggered');
  });

  /**
   * Integration contract test — uses the EXACT JSON shape the backend
   * emits on a session_locked verdict once the backend emits it.
   * Locks in that the SDK helper and the backend agree on field names
   * and values so the loop closes without a shape drift.
   *
   * The canonical instruction here MUST match the string in
   * platform/common/models/recovery.go — if either side changes, this
   * test fails and forces the other side to sync. That is the contract.
   */
  it('renders the session-locked wire shape', () => {
    const canonicalInstruction =
      'Start a new session_id for the next call. This session has ' +
      'accumulated risk from prior turns that cannot be scanned out; ' +
      'a fresh session_id is the self-service recovery path. ' +
      'reset_session is administratively restricted at the block ' +
      'threshold.';

    const verdict = {
      safe: false,
      refuse_tier: 'block',
      threat_type: 'session_locked',
      severity: 'high',
      session_state: {
        session_risk_score: 0.9,
        session_turn_number: 6,
        session_patterns: [
          'multi_turn_reconnaissance',
          'multi_turn_crescendo',
          'multi_turn_escalation',
        ],
      },
      recovery: {
        instruction: canonicalInstruction,
        available_tools: ['scan_prompt', 'scan_response', 'session_status'],
        // Q1 session_locked short-circuit does NOT populate
        // patterns_triggered — the block fires on accumulated state
        // not a per-turn correlator report.
      },
    };

    const result = formatBlockFeedback(verdict);

    expect(result.startsWith('Shrike blocked your last tool call.')).toBe(true);
    expect(result).toContain('Threat type: session_locked');
    expect(result).toContain('Session risk: 0.9 (turn 6)');
    // Falls back to session_state.session_patterns when
    // recovery.patterns_triggered is absent.
    expect(result).toContain(
      'Patterns triggered: multi_turn_reconnaissance, multi_turn_crescendo, multi_turn_escalation',
    );
    expect(result).toContain(`Recovery: ${canonicalInstruction}`);
    expect(result).toContain('Available tools: scan_prompt, scan_response, session_status');
  });

  /**
   * Integration contract test for a generic block verdict (non-locked)
   * on the specialized path. Recovery is populated by the handler after
   * PopulateUserGuidance sets SuggestedAction. Verifies helper renders
   * the shape emitted by handlers/scan_specialized_handler.go.
   */
  it('renders the generic-block wire shape', () => {
    const verdict = {
      safe: false,
      refuse_tier: 'block',
      threat_type: 'data_exfiltration',
      severity: 'high',
      guidance:
        'This request looks like it could move sensitive data outside your environment.',
      suggested_action:
        "If this is a legitimate export, use your platform's authorized data-export workflow. Your security team can grant scoped access if you explain the use case.",
      session_state: {
        session_risk_score: 0.45,
        session_turn_number: 1,
        session_patterns: [],
      },
      recovery: {
        instruction:
          "If this is a legitimate export, use your platform's authorized data-export workflow. Your security team can grant scoped access if you explain the use case.",
        // Non-locked block: available_tools omitted intentionally.
      },
    };

    const result = formatBlockFeedback(verdict);

    expect(result.startsWith('Shrike blocked your last tool call.')).toBe(true);
    expect(result).toContain(
      'Reason: This request looks like it could move sensitive data',
    );
    expect(result).toContain('Threat type: data_exfiltration');
    // Empty session_patterns stays silent.
    expect(result).not.toContain('Patterns triggered');
    expect(result).toContain('Recovery: If this is a legitimate export');
    expect(result).not.toContain('Available tools');
  });
});
