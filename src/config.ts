/**
 * Configuration constants and types for the Shrike Guard SDK.
 */

/**
 * Defines behavior when scan operations fail.
 */
export enum FailMode {
  /**
   * Allow the request to proceed (fail-open). This is the default
   * behavior suitable for most applications where availability is
   * prioritized over strict security.
   */
  OPEN = 'open',

  /**
   * Block the request and raise an exception (fail-closed). Use
   * this mode for security-critical applications where you'd rather
   * block potentially safe requests than allow unsafe ones through.
   */
  CLOSED = 'closed',
}

/** Default timeout for scan requests in milliseconds */
export const DEFAULT_SCAN_TIMEOUT = 10000;

/** Default fail mode - allow requests when scan fails */
export const DEFAULT_FAIL_MODE = FailMode.OPEN;

/** Default Shrike API endpoint (uses load balancer for scalability) */
export const DEFAULT_ENDPOINT = 'https://api.shrikesecurity.com/agent';

// Note: All scanning is done via backend API. All tiers get full 9-layer cascade (L1-L8).
// Enterprise tier includes priority processing, higher rate limits, and custom policies.

/** SDK identification */
export const SDK_NAME = 'typescript';
export const SDK_USER_AGENT = 'shrike-guard-typescript';
