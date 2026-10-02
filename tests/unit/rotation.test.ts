/**
 * Tests for src/rotation.ts — three-shape session rotation record.
 *
 * Locks in:
 *   - The discriminated union shape (rotated: true vs rotated: false)
 *   - Ownership detection via effective_session_id vs module_session_id
 *   - Trigger semantics (session_locked, risk >= ROTATION_THRESHOLD)
 *   - Non-trigger cases return null
 *   - Per-event suggestion (each caller-owned recommendation mints a
 *     fresh suggested_new_session_id — none are stable across events)
 */

import {
  evaluateRotation,
  ROTATION_THRESHOLD,
  type ModuleOwnedRotation,
  type CallerOwnedRotationRecommendation,
  type SessionLockedNotice,
} from '../../src/rotation';

const MODULE_SESSION = 'module-fixed-uuid-11111111-1111-1111-1111-111111111111';
const CALLER_SESSION = 'caller-supplied-imds-traj';

describe('evaluateRotation', () => {
  describe('no trigger', () => {
    it('returns null for safe response with no risk score', () => {
      const result = evaluateRotation({
        effective_session_id: MODULE_SESSION,
        module_session_id: MODULE_SESSION,
      });
      expect(result).toBeNull();
    });

    it('returns null when risk_score is below threshold', () => {
      const result = evaluateRotation({
        threat_type: 'prompt_injection',
        session_state: {
          session_risk_score: ROTATION_THRESHOLD - 0.01,
          session_turn_number: 2,
          session_patterns: [],
        },
        effective_session_id: MODULE_SESSION,
        module_session_id: MODULE_SESSION,
      });
      expect(result).toBeNull();
    });

    it('returns null when threat_type is not session_locked and risk is absent', () => {
      const result = evaluateRotation({
        threat_type: 'sql_injection',
        effective_session_id: MODULE_SESSION,
        module_session_id: MODULE_SESSION,
      });
      expect(result).toBeNull();
    });
  });

  describe('module-owned branch (caller did not supply session_id)', () => {
    it('emits rotated: true with sdk_client owner on risk >= threshold', () => {
      const result = evaluateRotation({
        session_state: {
          session_risk_score: 0.85,
          session_turn_number: 3,
          session_patterns: ['multi_turn_crescendo', 'multi_turn_escalation'],
        },
        effective_session_id: MODULE_SESSION,
        module_session_id: MODULE_SESSION,
      }) as ModuleOwnedRotation;

      expect(result).not.toBeNull();
      expect(result.rotated).toBe(true);
      expect(result.owner).toBe('sdk_client');
      expect(result.reason).toBe('risk_threshold_exceeded');
      expect(result.previous_session_id).toBe(MODULE_SESSION);
      expect(result.new_session_id).toMatch(/^[0-9a-f-]{36}$/);
      expect(result.new_session_id).not.toBe(MODULE_SESSION);
      expect(result.triggering_risk_score).toBe(0.85);
      expect(result.configured_threshold).toBe(ROTATION_THRESHOLD);
    });

    it('session_locked does NOT rotate; it emits a notice with no new id', () => {
      // The lock is the control. Rotating past it sidesteps the control
      // rather than clearing it, which is what the backend's own recovery
      // instruction tells the agent not to do. A lock lifts by a
      // self-release under a live declared scope, or by an operator.
      const result = evaluateRotation({
        threat_type: 'session_locked',
        effective_session_id: MODULE_SESSION,
        module_session_id: MODULE_SESSION,
      }) as SessionLockedNotice;

      expect(result.reason).toBe('session_locked');
      expect(result.rotated).toBe(false);
      expect(result.rotation_recommended).toBe(false);
      expect(result.owner).toBe('sdk_client');
      expect(result.current_session_id).toBe(MODULE_SESSION);
      expect((result as unknown as Record<string, unknown>).new_session_id).toBeUndefined();
      expect((result as unknown as Record<string, unknown>).suggested_new_session_id).toBeUndefined();
    });

    it('a locked session is not rotated even when risk is above threshold', () => {
      // This ordering is the whole fix: a locked session is ALREADY above
      // the score threshold, so checking the score first would rotate it.
      const result = evaluateRotation({
        threat_type: 'session_locked',
        session_state: { session_risk_score: 0.95 },
        effective_session_id: MODULE_SESSION,
        module_session_id: MODULE_SESSION,
      }) as SessionLockedNotice;

      expect(result.rotated).toBe(false);
      expect(result.rotation_recommended).toBe(false);
      expect(result.triggering_risk_score).toBe(0.95);
    });

    it('session_locked without risk still emits a valid notice (no triggering_risk_score)', () => {
      const result = evaluateRotation({
        threat_type: 'session_locked',
        effective_session_id: MODULE_SESSION,
        module_session_id: MODULE_SESSION,
      }) as SessionLockedNotice;

      expect(result.triggering_risk_score).toBeUndefined();
      expect(result.configured_threshold).toBe(ROTATION_THRESHOLD);
    });
  });

  describe('caller-owned branch (caller supplied their own session_id)', () => {
    it('emits rotated: false + rotation_recommended: true on risk >= threshold', () => {
      const result = evaluateRotation({
        session_state: {
          session_risk_score: 0.85,
          session_turn_number: 3,
          session_patterns: ['multi_turn_crescendo', 'multi_turn_escalation'],
        },
        effective_session_id: CALLER_SESSION,
        module_session_id: MODULE_SESSION,
      }) as CallerOwnedRotationRecommendation;

      expect(result).not.toBeNull();
      expect(result.rotated).toBe(false);
      expect(result.rotation_recommended).toBe(true);
      expect(result.owner).toBe('caller');
      expect(result.reason).toBe('risk_threshold_exceeded');
      expect(result.current_session_id).toBe(CALLER_SESSION);
      expect(result.suggested_new_session_id).toMatch(/^[0-9a-f-]{36}$/);
      expect(result.suggested_new_session_id).not.toBe(CALLER_SESSION);
      expect(result.triggering_risk_score).toBe(0.85);
      expect(result.configured_threshold).toBe(ROTATION_THRESHOLD);
    });

    it('does not mutate module_session_id (caller-owned means SDK stays hands-off)', () => {
      const originalModuleId = MODULE_SESSION;
      const result = evaluateRotation({
        threat_type: 'session_locked',
        effective_session_id: CALLER_SESSION,
        module_session_id: originalModuleId,
      });

      expect(result?.rotated).toBe(false);
      expect(originalModuleId).toBe(MODULE_SESSION);
    });

    it('session_locked emits a notice, and suggests nothing to the caller either', () => {
      const result = evaluateRotation({
        threat_type: 'session_locked',
        effective_session_id: CALLER_SESSION,
        module_session_id: MODULE_SESSION,
      }) as SessionLockedNotice;

      expect(result.reason).toBe('session_locked');
      expect(result.owner).toBe('caller');
      expect(result.rotation_recommended).toBe(false);
      expect(result.current_session_id).toBe(CALLER_SESSION);
      // A caller who owns the session still must not be told that minting
      // a new id is the way past a lock.
      expect((result as unknown as Record<string, unknown>).suggested_new_session_id).toBeUndefined();
    });
  });

  describe('per-event suggestion contract (docstring invariant)', () => {
    it('mints a distinct suggested_new_session_id for each recommendation', () => {
      const input = {
        session_state: {
          session_risk_score: 0.85,
          session_turn_number: 3,
          session_patterns: [],
        },
        effective_session_id: CALLER_SESSION,
        module_session_id: MODULE_SESSION,
      };

      const suggestions = new Set<string>();
      for (let i = 0; i < 10; i++) {
        const rec = evaluateRotation(input) as CallerOwnedRotationRecommendation;
        suggestions.add(rec.suggested_new_session_id);
      }

      // 10 evaluations, 10 distinct suggested ids — the value is per-event,
      // not a stable "next id" the caller can cache-key on.
      expect(suggestions.size).toBe(10);
    });
  });

  describe('threshold exactly', () => {
    it('risk == ROTATION_THRESHOLD triggers rotation (>= not >)', () => {
      const result = evaluateRotation({
        session_state: {
          session_risk_score: ROTATION_THRESHOLD,
          session_turn_number: 2,
          session_patterns: [],
        },
        effective_session_id: MODULE_SESSION,
        module_session_id: MODULE_SESSION,
      });
      expect(result?.rotated).toBe(true);
    });
  });
});
