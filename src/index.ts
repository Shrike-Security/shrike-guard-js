/**
 * Shrike Guard SDK - Protect your LLM applications from security threats.
 *
 * @example
 * ```typescript
 * import { ShrikeOpenAI } from 'shrike-guard/openai';
 *
 * const client = new ShrikeOpenAI({
 *   apiKey: 'sk-...',
 *   shrikeApiKey: 'shrike-...',
 * });
 *
 * const response = await client.chat.completions.create({
 *   model: 'gpt-4',
 *   messages: [{ role: 'user', content: 'Hello!' }],
 * });
 * ```
 */

// Configuration
export { FailMode, DEFAULT_ENDPOINT, DEFAULT_SCAN_TIMEOUT, DEFAULT_FAIL_MODE, getSessionId, getAgentId } from './config';
export type { ApprovalInfo } from './config';

// Errors
export {
  ShrikeError,
  ShrikeScanError,
  ShrikeBlockedError,
  ShrikeConfigError,
  ShrikeRateLimitError,
} from './errors';

// Scanner
export { ScanClient, getScanHeaders, isBlocked, maybeAddSignupHint } from './scanner';
export type { ScanResult, ScanClientOptions, CorrelationPattern } from './scanner';

// Session rotation (two-shape record — mirrors MCP client contract)
export { evaluateRotation, ROTATION_THRESHOLD } from './rotation';
export type {
  ModuleOwnedRotation,
  CallerOwnedRotationRecommendation,
  SessionRotation,
  RotationTriggerInput,
} from './rotation';

// Block-feedback formatter (self-consultation stack layer 4)
export { formatBlockFeedback } from './formatters';
export type { BlockFeedbackVerdict } from './formatters';

// 'Working with Shrike' canonical system-prompt block (self-consultation stack layer 1)
export { systemPrompt, SYSTEM_PROMPT_VERSION } from './systemPrompt';

// Rate Limiter
export { RateLimiter } from './rateLimiter';

// Resilience (circuit breaker + retry with backoff — mirrors Python SDK)
export {
  CircuitBreaker,
  CircuitOpenError,
  CircuitState,
  retryWithBackoff,
} from './resilience';
export type { CircuitBreakerOptions, CircuitBreakerStats, RetryOptions } from './resilience';

// Auth client (dashboard login / register / JWT — mirrors Python SDK)
export { AuthClient } from './api/auth';

// Sanitizer (IP protection)
export { sanitizeScanResponse, normalizeThreatType, bucketConfidence, deriveSeverity } from './sanitizer';

// PII redaction (client-side; mirrors MCP server)
export {
  redactPII,
  rehydratePII,
  getRedactionSummary,
  updatePIIPatterns,
  getPIIPatternCount,
} from './piiRedactor';
export type { PIIPattern, RedactionEntry, RedactionResult } from './piiRedactor';

// PII pattern sync (fetches canonical Presidio-derived pattern set from backend)
export { syncPIIPatterns } from './piiSync';
export type { SyncPIIPatternsOptions } from './piiSync';

// Version
export { VERSION } from './version';
