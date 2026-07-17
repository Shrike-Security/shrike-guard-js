/**
 * Session rotation contract, ported from the MCP client's two-shape record.
 *
 * When a scan response indicates the session should rotate (either the
 * backend returned an explicit "session_locked" verdict, or the
 * session_state carries an accumulated risk score above the configured
 * threshold), integrators need a stable record they can act on. The
 * shape depends on WHO owns the session_id lifecycle for this call:
 *
 * - **Module-owned**: the SDK's own SESSION_ID was used (developer did
 *   not thread a caller-supplied session_id via extra context). The SDK
 *   rotates its module SESSION_ID in place and reports previous → new.
 * - **Caller-owned**: the developer threaded their own session_id via
 *   extra context on the scan call. The SDK does NOT mutate its module
 *   SESSION_ID and instead returns a recommendation the developer can
 *   act on inside their own control flow.
 *
 * The discriminant is the `rotated` boolean plus the `owner` field.
 * `evaluateRotation` is a pure function — it does not mutate module
 * state on its own. Rotation of the module SESSION_ID is the SDK
 * caller's responsibility once they act on a `ModuleOwnedRotation`.
 */

import { randomUUID } from 'node:crypto';

/**
 * Rotation record when the SDK's fallback SESSION_ID was the id used
 * for this scan. Developer did not supply their own session_id.
 */
export interface ModuleOwnedRotation {
  rotated: true;
  /** Who owns the session lifecycle. `sdk_client` = SDK's module SESSION_ID. */
  owner: 'sdk_client';
  /** Why rotation is being signalled. */
  reason: 'session_locked' | 'risk_threshold_exceeded';
  /** The SDK's fallback session_id that was in force before rotation. */
  previous_session_id: string;
  /** The fresh session_id the SDK caller should adopt for subsequent scans. */
  new_session_id: string;
  /** For "risk_threshold_exceeded", the score that crossed. For "session_locked", the score if the response carried one. */
  triggering_risk_score?: number;
  /** The threshold in force at the time of evaluation (reproducibility). */
  configured_threshold?: number;
}

/**
 * Rotation recommendation when the CALLER supplied their own session_id
 * on the scan call — they own the session lifecycle, so the SDK can
 * only signal. `rotated: false` + `rotation_recommended: true` are the
 * discriminant. The SDK does NOT mutate its module SESSION_ID in this
 * branch. The caller decides whether to adopt `suggested_new_session_id`,
 * mint their own, or ignore the recommendation.
 *
 * Per-event suggestion contract: `suggested_new_session_id` is minted
 * per recommendation and is NOT a stable "next id" the caller should
 * cache across scans. If the caller ignores turn N's suggestion and
 * stays on `current_session_id`, turn N+1 will emit a fresh
 * recommendation with a different `suggested_new_session_id`. Callers
 * that persist and re-use a stale suggestion will find it
 * de-correlated from the event that produced it. Adopt the suggestion
 * at the moment of the recommendation, or ignore it and let the next
 * event mint its own — do not cache-key on the value.
 */
export interface CallerOwnedRotationRecommendation {
  rotated: false;
  rotation_recommended: true;
  /** Who owns the session lifecycle. `caller` = the SDK caller supplied session_id. */
  owner: 'caller';
  /** Why the SDK is recommending rotation. */
  reason: 'session_locked' | 'risk_threshold_exceeded';
  /** The session_id the caller supplied on this scan, echoed back for correlation. */
  current_session_id: string;
  /**
   * A fresh UUID the SDK suggests the caller adopt for subsequent
   * scans. Advisory. Per-event, not a stable next-id — see interface
   * docstring.
   */
  suggested_new_session_id: string;
  triggering_risk_score?: number;
  configured_threshold?: number;
}

/**
 * Discriminated union — the value returned to describe what happened
 * (or should happen). Discriminate on `rotated`.
 */
export type SessionRotation = ModuleOwnedRotation | CallerOwnedRotationRecommendation;

/**
 * Configured risk-score threshold above which `evaluateRotation` emits
 * a `risk_threshold_exceeded` recommendation. Mirrors the MCP client's
 * ROTATION_THRESHOLD (config.ts).
 */
export const ROTATION_THRESHOLD = 0.7;

/**
 * Verdict-shape input to `evaluateRotation`. Kept structurally light so
 * this module has no dependency on the concrete ScanResult type — a
 * caller can pass any object that carries a `threat_type` and/or a
 * `session_state.session_risk_score`.
 */
export interface RotationTriggerInput {
  threat_type?: string;
  session_state?: {
    session_risk_score: number;
    session_turn_number?: number;
    session_patterns?: string[];
  };
  /**
   * The session_id that was actually used for this scan. When it matches
   * the SDK's module session_id (from `getSessionId()`), rotation is
   * treated as module-owned; when it differs, rotation is treated as a
   * caller-owned recommendation.
   */
  effective_session_id: string;
  /**
   * The SDK's current module SESSION_ID. Ownership detection compares
   * `effective_session_id` against this value.
   */
  module_session_id: string;
}

/**
 * Inspects a scan response and returns a `SessionRotation` record when
 * rotation is warranted, or null when no trigger fired.
 *
 * Triggers:
 *   - `threat_type === 'session_locked'` — the backend has explicitly
 *     told the SDK the session is done.
 *   - `session_state.session_risk_score >= ROTATION_THRESHOLD` — the L9
 *     correlator has accumulated risk past the safe-continuation floor.
 *
 * The function is pure: it does not mutate anything. In the
 * module-owned branch it returns the `new_session_id` the caller should
 * assign to the SDK's module SESSION_ID (or generate its own — this is
 * a suggestion). In the caller-owned branch it returns a
 * recommendation record with a fresh `suggested_new_session_id`.
 *
 * @param input - the verdict shape (any object with the fields above)
 * @returns SessionRotation | null
 */
export function evaluateRotation(input: RotationTriggerInput): SessionRotation | null {
  const risk = input.session_state?.session_risk_score;
  const locked = input.threat_type === 'session_locked';
  const overThreshold = typeof risk === 'number' && risk >= ROTATION_THRESHOLD;

  if (!locked && !overThreshold) {
    return null;
  }

  const reason: 'session_locked' | 'risk_threshold_exceeded' = locked
    ? 'session_locked'
    : 'risk_threshold_exceeded';

  const isCallerOwned = input.effective_session_id !== input.module_session_id;

  if (isCallerOwned) {
    const rec: CallerOwnedRotationRecommendation = {
      rotated: false,
      rotation_recommended: true,
      owner: 'caller',
      reason,
      current_session_id: input.effective_session_id,
      suggested_new_session_id: randomUUID(),
    };
    if (typeof risk === 'number') {
      rec.triggering_risk_score = risk;
    }
    rec.configured_threshold = ROTATION_THRESHOLD;
    return rec;
  }

  const rotation: ModuleOwnedRotation = {
    rotated: true,
    owner: 'sdk_client',
    reason,
    previous_session_id: input.module_session_id,
    new_session_id: randomUUID(),
  };
  if (typeof risk === 'number') {
    rotation.triggering_risk_score = risk;
  }
  rotation.configured_threshold = ROTATION_THRESHOLD;
  return rotation;
}
