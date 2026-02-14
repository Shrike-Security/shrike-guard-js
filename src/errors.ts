/**
 * Custom exceptions for the Shrike Guard SDK.
 */

/**
 * Base exception for all Shrike SDK errors.
 */
export class ShrikeError extends Error {
  public readonly details: Record<string, unknown>;

  constructor(message: string, details: Record<string, unknown> = {}) {
    super(message);
    this.name = 'ShrikeError';
    this.details = details;
    // Maintain proper prototype chain
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Raised when a scan operation fails and fail_mode is 'closed'.
 *
 * This exception is raised when:
 * - The Shrike API times out
 * - A network error occurs
 * - The API returns an unexpected error
 *
 * When fail_mode is 'open' (default), these errors are silently
 * handled and the request is allowed to proceed.
 */
export class ShrikeScanError extends ShrikeError {
  constructor(message: string, details: Record<string, unknown> = {}) {
    super(message, details);
    this.name = 'ShrikeScanError';
  }
}

/**
 * Raised when a prompt is blocked by Shrike security checks.
 *
 * This exception indicates that the prompt was scanned and determined
 * to be unsafe. The scan result details are available in the `details`
 * attribute.
 */
export class ShrikeBlockedError extends ShrikeError {
  /** The type of threat detected (e.g., 'prompt_injection', 'pii') */
  public readonly threatType?: string;

  /** The confidence level of the detection ('high', 'medium', 'low') or raw score (0.0-1.0) */
  public readonly confidence?: number | string;

  /** List of specific violations detected */
  public readonly violations: unknown[];

  constructor(
    message: string,
    threatType?: string,
    confidence?: number | string,
    violations: unknown[] = []
  ) {
    super(message, {
      threat_type: threatType,
      confidence,
      violations,
    });
    this.name = 'ShrikeBlockedError';
    this.threatType = threatType;
    this.confidence = confidence;
    this.violations = violations;
  }
}

/**
 * Raised when there's a configuration error in the SDK.
 */
export class ShrikeConfigError extends ShrikeError {
  constructor(message: string, details: Record<string, unknown> = {}) {
    super(message, details);
    this.name = 'ShrikeConfigError';
  }
}
