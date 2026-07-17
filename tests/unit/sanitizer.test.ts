/**
 * Tests for sanitizer output shape.
 *
 * Pins the SDK-output contract at the sanitizer boundary. The pre-2026-07-07
 * sanitizer stripped `action`, `refuse_tier`, `recovery`, `session_state`,
 * `content_type`, and `violations[]` from every response — violating the
 * contract-symmetry principle in platform/CLAUDE.md and rendering the
 * the four-state Cooperative Governance wire shape is invisible to
 * direct SDK callers.
 *
 * Contract-symmetry test — mirrors Python test_sanitizer.py.
 * If either SDK diverges, that is a bug in one of the two.
 */

import {
  INTERNAL_FIELDS,
  sanitizeScanResponse,
  sanitizeViolation,
} from '../../src/sanitizer';
import type { ScanResult } from '../../src/scanner';

// ---------------------------------------------------------------------------
// Governance fields survive on BOTH safe and unsafe branches
// ---------------------------------------------------------------------------

describe('sanitizeScanResponse — governance fields preserved', () => {
  it('safe branch preserves action and refuse_tier', () => {
    const result = sanitizeScanResponse({
      safe: true,
      action: 'allow',
      refuse_tier: 'allow',
    } as ScanResult);
    expect(result.action).toBe('allow');
    expect(result.refuse_tier).toBe('allow');
  });

  it('safe branch preserves warn advisory recovery', () => {
    const result = sanitizeScanResponse({
      safe: true,
      action: 'warn',
      refuse_tier: 'warn',
      recovery: { instruction: 'Consider rephrasing to reduce risk.' },
    } as ScanResult);
    expect(result.action).toBe('warn');
    expect(result.refuse_tier).toBe('warn');
    expect(result.recovery?.instruction).toMatch(/^Consider rephrasing/);
  });

  it('unsafe branch preserves action + refuse_tier + recovery', () => {
    const result = sanitizeScanResponse({
      safe: false,
      action: 'block',
      refuse_tier: 'block',
      threat_type: 'prompt_injection',
      recovery: {
        instruction: 'Rephrase without instruction-override phrasing.',
        available_tools: ['scan_prompt', 'session_status'],
        patterns_triggered: ['multi_turn_reconnaissance'],
      },
    } as ScanResult);
    expect(result.action).toBe('block');
    expect(result.refuse_tier).toBe('block');
    expect(result.recovery?.instruction).toMatch(/^Rephrase/);
    expect(result.recovery?.available_tools).toContain('scan_prompt');
    expect(result.recovery?.patterns_triggered).toContain(
      'multi_turn_reconnaissance'
    );
  });

  it('session_state passes through verbatim', () => {
    const result = sanitizeScanResponse({
      safe: false,
      action: 'block',
      threat_type: 'multi_turn_attack',
      session_state: {
        session_risk_score: 0.9,
        session_turn_number: 4,
        session_patterns: ['multi_turn_reconnaissance'],
        session_locked: true,
      },
    } as ScanResult);
    expect(result.session_state?.session_risk_score).toBe(0.9);
    expect(result.session_state?.session_turn_number).toBe(4);
    expect(result.session_state?.session_patterns).toEqual([
      'multi_turn_reconnaissance',
    ]);
    expect(result.session_state?.session_locked).toBe(true);
  });

  it('content_type preserved on specialized endpoint', () => {
    const result = sanitizeScanResponse({
      safe: false,
      action: 'block',
      threat_type: 'sql_injection',
      content_type: 'sql',
    } as ScanResult);
    expect(result.content_type).toBe('sql');
  });

  it('require_approval action preserved', () => {
    const result = sanitizeScanResponse({
      safe: false,
      action: 'require_approval',
      refuse_tier: 'block',
      threat_type: 'pii_exposure',
      approval_info: { reason: 'PII disclosure requires approval' } as any,
    } as ScanResult);
    expect(result.action).toBe('require_approval');
    expect((result.approval_info as any).reason).toMatch(/^PII disclosure/);
  });
});

// ---------------------------------------------------------------------------
// violations[] survives with per-item attribution stripped
// ---------------------------------------------------------------------------

describe('sanitizeScanResponse — violations[] preserved', () => {
  it('preserves violations array from /api/scan/enforce', () => {
    // Exact shape observed from /api/scan/enforce.
    const raw: ScanResult = {
      safe: false,
      action: 'block',
      refuse_tier: 'block',
      threat_type: undefined,
      violations: [
        {
          policy_id: '',
          policy_name: 'Security Policy',
          action: 'block',
          severity: 'critical',
          threat_type: 'data_exfiltration',
          owasp_category: 'LLM02',
          user_message: 'This request looks like data exfiltration.',
          suggested_action: 'Use authorized data-export workflow.',
        },
        {
          policy_id: '',
          policy_name: 'Security Policy',
          action: 'block',
          severity: 'critical',
          threat_type: 'prompt_injection',
          owasp_category: 'LLM01',
          user_message: 'This request contains injection patterns.',
          suggested_action: "Rephrase without 'ignore previous instructions'.",
        },
      ],
    } as ScanResult;
    const result = sanitizeScanResponse(raw);
    expect(result.violations).toBeDefined();
    expect(result.violations).toHaveLength(2);
    const types = new Set(result.violations!.map((v) => v.threat_type));
    expect(types).toEqual(new Set(['data_exfiltration', 'prompt_injection']));
    const owasp = new Set(result.violations!.map((v) => v.owasp_category));
    expect(owasp).toEqual(new Set(['LLM01', 'LLM02']));
  });

  it('strips policy_id and policy_name from each violation', () => {
    const v = sanitizeViolation({
      policy_id: 'internal-policy-42',
      policy_name: 'Security Policy',
      action: 'block',
      severity: 'critical',
      threat_type: 'prompt_injection',
      owasp_category: 'LLM01',
      user_message: 'test',
      suggested_action: 'test',
    });
    expect(v).not.toBeNull();
    expect(v!).not.toHaveProperty('policy_id');
    expect(v!).not.toHaveProperty('policy_name');
    expect(v!.threat_type).toBe('prompt_injection');
    expect(v!.owasp_category).toBe('LLM01');
    expect(v!.severity).toBe('critical');
    expect(v!.user_message).toBe('test');
  });

  it('strips all internal attribution fields from a violation', () => {
    const v = sanitizeViolation({
      threat_type: 'prompt_injection',
      severity: 'high',
      detected_by: 'L1_regex',
      matched_pattern: 'ignore_previous_instructions_v3',
      matched_text: 'ignore all prior instructions',
      ai_reasoning: 'L7 said...',
      llm_analysis: { model: 'gemini-2.5-flash', tokens: 42 },
      performance_metrics: { total_ms: 1234 },
    });
    expect(v).not.toBeNull();
    for (const stripped of Array.from(INTERNAL_FIELDS)) {
      expect(v!).not.toHaveProperty(stripped);
    }
    expect(v!.threat_type).toBe('prompt_injection');
  });

  it('empty violations array is dropped (noise)', () => {
    const result = sanitizeScanResponse({
      safe: false,
      threat_type: 'prompt_injection',
      violations: [],
    } as ScanResult);
    expect(result.violations).toBeUndefined();
  });

  it('non-array violations value is ignored', () => {
    const result = sanitizeScanResponse({
      safe: false,
      threat_type: 'prompt_injection',
      violations: 'malformed' as any,
    } as ScanResult);
    expect(result.violations).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// Legacy threat_type derivation still works
// ---------------------------------------------------------------------------

describe('sanitizeScanResponse — legacy threat_type derivation', () => {
  it('falls back to first violation threat_type when top-level is null', () => {
    // /api/scan/enforce puts classification in violations[] and returns
    // top-level threat_type=null. Legacy callers expect a top-level string.
    const result = sanitizeScanResponse({
      safe: false,
      action: 'block',
      threat_type: undefined,
      violations: [{ threat_type: 'prompt_injection', owasp_category: 'LLM01' }],
    } as ScanResult);
    expect(result.threat_type).toBe('prompt_injection');
  });

  it('unknown threat type falls through to "unknown"', () => {
    const result = sanitizeScanResponse({
      safe: false,
      threat_type: 'some_novel_type',
    } as ScanResult);
    expect(result.threat_type).toBe('unknown');
  });

  it('safe: true minimal response returns minimal shape', () => {
    const result = sanitizeScanResponse({ safe: true } as ScanResult);
    expect(result).toEqual({ safe: true, reason: '' });
  });
});

// ---------------------------------------------------------------------------
// Regression: internal-attribution fields must NEVER appear on output
// ---------------------------------------------------------------------------

describe('sanitizeScanResponse — internal attribution never leaks', () => {
  it('internal attribution fields never appear on top-level', () => {
    const result = sanitizeScanResponse({
      safe: false,
      action: 'block',
      threat_type: 'prompt_injection',
      detected_by: 'L1',
      matched_pattern: 'ignore_previous_v3',
      matched_text: 'ignore all prior',
      ai_reasoning: 'L7 said malicious',
      llm_analysis: { model: 'gemini-2.5-flash' },
      performance_metrics: { total_ms: 42 },
      scan_stage: 'l7_semantic',
    } as ScanResult);
    for (const stripped of Array.from(INTERNAL_FIELDS)) {
      expect(result).not.toHaveProperty(stripped);
    }
  });

  it('action is preserved so isBlocked() can consume it authoritatively', () => {
    // Without this, warn is indistinguishable from allow and the
    // action-authoritative property in isBlocked() is broken.
    const warn = sanitizeScanResponse({
      safe: true,
      action: 'warn',
      refuse_tier: 'warn',
    } as ScanResult);
    expect(warn.action).toBe('warn');

    const requireApproval = sanitizeScanResponse({
      safe: false,
      action: 'require_approval',
      threat_type: 'pii_exposure',
    } as ScanResult);
    expect(requireApproval.action).toBe('require_approval');
  });
});
