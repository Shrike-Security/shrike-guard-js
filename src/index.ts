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
export { FailMode, DEFAULT_ENDPOINT, DEFAULT_SCAN_TIMEOUT, DEFAULT_FAIL_MODE } from './config';

// Errors
export {
  ShrikeError,
  ShrikeScanError,
  ShrikeBlockedError,
  ShrikeConfigError,
} from './errors';

// Scanner
export { ScanClient, getScanHeaders } from './scanner';
export type { ScanResult, ScanClientOptions } from './scanner';

// Sanitizer (IP protection)
export { sanitizeScanResponse, normalizeThreatType, bucketConfidence, deriveSeverity } from './sanitizer';

// Version
export { VERSION } from './version';
