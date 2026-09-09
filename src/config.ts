/**
 * Configuration constants and types for the Shrike Guard SDK.
 */

import { randomUUID } from 'node:crypto';

/**
 * Defines behavior when scan operations fail.
 */
export enum FailMode {
  /**
   * Allow the request to proceed (fail-open). Use this mode when
   * availability is prioritized over strict security.
   */
  OPEN = 'open',

  /**
   * Block the request and raise an exception (fail-closed). This is the
   * default behavior — matching the MCP server's security posture. Use
   * fail-open only when you've explicitly decided availability matters more.
   */
  CLOSED = 'closed',
}

/** Default timeout for scan requests in milliseconds */
export const DEFAULT_SCAN_TIMEOUT = 10000;

/** Default fail mode - block requests when scan fails (fail-closed) */
export const DEFAULT_FAIL_MODE = FailMode.CLOSED;

/** Default Shrike API endpoint (uses load balancer for scalability) */
export const DEFAULT_ENDPOINT = 'https://api.shrikesecurity.com/agent';

/** Default rate limit (requests per minute) */
export const DEFAULT_RATE_LIMIT_PER_MINUTE = 100;

// Note: Scan depth is set by the backend from the license tier (community = L1-L5 deterministic layers; Pro and above = full L1-L9 including LLM semantic, response intel and session correlation).
// Detection logic is backend-side. The one deliberate exception is PII redaction,
// which runs locally from a bundled pattern set so redaction survives a backend
// outage; see piiRedactor / piiSync.

/** SDK identification */
export const SDK_NAME = 'typescript';
export const SDK_USER_AGENT = 'shrike-guard-typescript';

/**
 * Process-wide session and agent identity. The session id is the backend's
 * multi-turn correlation key; the agent id is what a declared scope is
 * enforced against. Both can be overridden per client (`sessionId` /
 * `agentId` options and `forSession()`).
 */
const SESSION_ID = randomUUID();
const AGENT_ID = `sdk-ts-${randomUUID().slice(0, 8)}`;

/** Returns the stable session ID for this SDK process. */
export function getSessionId(): string {
  return SESSION_ID;
}

/**
 * Returns the agent ID: SHRIKE_AGENT_ID when set, so a deployment can name its
 * agents; otherwise an id generated once per process. The variable is read at
 * call time rather than at import, matching the Go and Python SDKs, so setting
 * it after import still takes effect and the shared contract
 * (`agent_id_env_override` in canonical-request-shapes.json) can be tested
 * in-process.
 */
export function getAgentId(): string {
  return process.env.SHRIKE_AGENT_ID || AGENT_ID;
}

let processSessionWarned = false;

/**
 * Log, once per process, that scans are using the process-wide session id.
 *
 * The process-wide default suits a CLI, a worker or a single agent, and gives
 * those callers multi-turn correlation without configuration.
 *
 * It does not suit a server handling many end users: session identity is the
 * key the backend accumulates risk against, so every user sharing one id shares
 * one risk score, and one user's refusal counts against the next user's action.
 * The SDK cannot tell the two deployments apart, so the default is kept and
 * stated once. Pass `sessionId` to the client, or derive a per-request client
 * with `forSession()`, and the message is not emitted.
 *
 * Silence it with `SHRIKE_SUPPRESS_SESSION_WARNING=1`.
 */
export function warnOnceAboutTheProcessSession(): void {
  if (processSessionWarned) return;
  processSessionWarned = true;

  if (process.env.SHRIKE_SUPPRESS_SESSION_WARNING) return;

  console.warn(
    '[shrike-guard] Using the process-wide session id. This suits a single ' +
      'agent; a server handling many end users should pass sessionId or use ' +
      'client.forSession(<per-request id>) so each user has its own session. ' +
      'Set SHRIKE_SUPPRESS_SESSION_WARNING=1 to silence this message.'
  );
}

/** Test seam: forget that the warning was emitted. */
export function resetProcessSessionWarningForTests(): void {
  processSessionWarned = false;
}

/**
 * Approval information returned when a policy requires human sign-off.
 */
export interface ApprovalInfo {
  requires_approval: boolean;
  approval_id: string;
  approval_level: string;
  action_summary: string;
  policy_name: string;
  expires_in_seconds: number;
  threat_type?: string;
  severity?: string;
  owasp_category?: string;
  risk_factors?: string[];
  original_action?: string;
}

/**
 * Retry configuration for transient failure resilience.
 * Matches MCP server's RETRY_CONFIG for consistent behavior.
 */
export const RETRY_CONFIG = {
  maxRetries: 2,
  initialDelayMs: 200,
  maxDelayMs: 2000,
  backoffMultiplier: 2,
  retryableErrors: ['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'fetch failed'],
};
