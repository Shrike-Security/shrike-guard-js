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

// Note: All scanning is done via backend API (tier-based: community=L1-L4, pro=L1-L8)
// No local patterns needed - backend handles all detection logic

/** SDK identification */
export const SDK_NAME = 'typescript';
export const SDK_USER_AGENT = 'shrike-guard-typescript';

/**
 * Session identity — persists for the lifetime of this SDK process.
 * Maps to L9's SessionCache key for multi-turn attack detection.
 */
const SESSION_ID = randomUUID();
const AGENT_ID = process.env.SHRIKE_AGENT_ID || `sdk-ts-${randomUUID().slice(0, 8)}`;

/** Returns the stable session ID for this SDK process. */
export function getSessionId(): string {
  return SESSION_ID;
}

/** Returns the agent ID (from SHRIKE_AGENT_ID env or auto-generated). */
export function getAgentId(): string {
  return AGENT_ID;
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
