/**
 * HTTP client for the Shrike scan API.
 * Includes retry with exponential backoff, session correlation,
 * approval workflow, 401 key refresh, and rate limiting.
 */

import {
  DEFAULT_ENDPOINT,
  DEFAULT_SCAN_TIMEOUT,
  DEFAULT_RATE_LIMIT_PER_MINUTE,
  SDK_NAME,
  RETRY_CONFIG,
  getSessionId,
  getAgentId,
} from './config';
import type { ApprovalInfo } from './config';
import { AUTO_CHUNK_THRESHOLD, aggregateChunkResults, chunkContent } from './chunker';
import { ShrikeRateLimitError } from './errors';
import { RateLimiter } from './rateLimiter';
import { sanitizeScanResponse } from './sanitizer';
import { VERSION } from './version';

/**
 * Phase 8b: Client-side size limits to fail fast before network round-trip.
 * These limits match the backend limits for consistency.
 */
const MAX_CONTENT_SIZE = 100 * 1024; // 100KB - matches backend MaxRequestBodySize

/**
 * Result from a scan operation.
 */
/**
 * Correlation pattern from L9 session-aware correlation engine.
 */
export interface CorrelationPattern {
  pattern_id: string;
  pattern_name: string;
  category: string;
  confidence: number;
  description: string;
}

/**
 * Governance action per Cooperative Governance 4-state contract (allow / warn / require_approval / block).
 * The `action` field is the server-authoritative signal for proceed-vs-refuse;
 * `isBlocked()` in this module consumes it directly.
 */
export type ScanAction = 'allow' | 'warn' | 'require_approval' | 'block';

/**
 * Recovery guidance emitted by the backend on refuse verdicts.
 * `available_tools` names the MCP tools the caller can still invoke while
 * under quarantine (typically read-only surfaces like session_status).
 */
export interface ScanRecovery {
  instruction?: string;
  available_tools?: string[];
  patterns_triggered?: string[];
  [key: string]: unknown;
}

/**
 * Session-level state carried on every scan response (contract symmetry).
 * Fields are outcome state per the dashboard IP boundary — customer-visible.
 */
export interface ScanSessionState {
  session_risk_score?: number;
  session_turn_number?: number;
  session_patterns?: string[];
  session_locked?: boolean;
  [key: string]: unknown;
}

/**
 * A single policy violation as emitted by the /api/scan/enforce endpoint.
 * The sanitizer strips policy_id / policy_name / matched_pattern / other
 * attribution before this reaches callers; what remains here is the
 * customer-visible outcome surface.
 */
export interface ScanViolation {
  threat_type?: string;
  owasp_category?: string;
  severity?: string;
  action?: string;
  user_message?: string;
  suggested_action?: string;
  [key: string]: unknown;
}

export interface ScanResult {
  safe: boolean;
  reason?: string;
  threat_type?: string;
  severity?: string;
  confidence?: number | string;
  violations?: ScanViolation[];
  guidance?: string;
  approval_info?: ApprovalInfo;
  /** Cooperative Governance action — server-authoritative proceed/refuse signal */
  action?: ScanAction;
  /** Refuse tier: allow / warn / require_approval / block */
  refuse_tier?: ScanAction;
  /** Recovery guidance, present on refuse verdicts */
  recovery?: ScanRecovery;
  /** L9 session correlation state — outcome, customer-visible */
  session_state?: ScanSessionState;
  /** Specialized scan input type, e.g. 'sql' / 'file_path' / 'a2a_message' */
  content_type?: string;
  /** Client-side session rotation guidance */
  client_session_rotation?: unknown;
  /** L9 session risk score (0.0-1.0), present when session correlation is active */
  session_risk_score?: number;
  /** L9 matched correlation patterns, present when multi-turn patterns are detected */
  correlation_patterns?: CorrelationPattern[];
  /**
   * True when this is a fail-open verdict returned without a completed scan —
   * i.e. `failMode: 'open'` was set and the backend was unreachable, so
   * enforcement was skipped. Lets a caller distinguish "scanned and clean"
   * from "not scanned, allowed anyway."
   */
  degraded?: boolean;
  [key: string]: unknown;
}

/**
 * Build a fail-open ALLOW verdict. Returned only when `failMode === 'open'` is
 * explicitly set and the scan could not complete (timeout, backend error).
 * Marked `degraded: true` — centralize all fail-open returns through this so the
 * marker can never be forgotten on a new wrapper.
 */
export function failOpenResult(reason: string): ScanResult {
  return { safe: true, reason, degraded: true };
}

/**
 * Result of ScanClient.declareScope — the persisted scope row plus derived
 * active_until + expired fields. Mirrors the shape returned by
 * POST /api/v1/agent/scope/declare on the backend.
 */
export interface DeclareScopeResult {
  scope_id?: string;
  agent_id?: string;
  purpose?: string;
  allowed_tools?: string[];
  forbidden_tools?: string[];
  max_duration_seconds?: number;
  expires_at?: string;
  active_until?: string;
  expired?: boolean;
  created_at?: string;
  updated_at?: string;
}

/**
 * Options for the ScanClient.
 */
export interface ScanClientOptions {
  /** Shrike API key for authentication */
  apiKey: string;
  /** Shrike API endpoint URL */
  endpoint?: string;
  /** Request timeout in milliseconds */
  timeout?: number;
  /** Rate limit in requests per minute (default: 100) */
  rateLimitPerMinute?: number;
  /** Optional callback to refresh API key on 401. Return new key or null. */
  onKeyRefresh?: () => Promise<string | null>;
}

/**
 * Generate a UUID v4 string.
 */
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

/**
 * Generate headers for scan API requests.
 */
export function getScanHeaders(
  shrikeApiKey: string,
  requestId?: string
): Record<string, string> {
  return {
    Authorization: `Bearer ${shrikeApiKey}`,
    'Content-Type': 'application/json',
    'X-Shrike-SDK': SDK_NAME,
    'X-Shrike-SDK-Version': VERSION,
    'X-Shrike-Request-ID': requestId || generateUUID(),
  };
}

/** Check if an error is transient and retryable. */
function isRetryableError(error: unknown): boolean {
  if (error instanceof Error) {
    const cause = 'cause' in error ? String((error as { cause?: unknown }).cause) : '';
    const errorStr = `${error.name} ${error.message} ${cause}`;
    return RETRY_CONFIG.retryableErrors.some((e) => errorStr.includes(e));
  }
  return false;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Fetch with retry for cold-start and transient failure resilience.
 * Matches MCP server's fetchWithRetry pattern.
 */
async function fetchWithRetry(
  url: string,
  options: RequestInit,
  timeoutMs: number,
  apiKey: string,
  onKeyRefresh?: () => Promise<string | null>
): Promise<Response> {
  let lastError: Error | null = null;
  let delay = RETRY_CONFIG.initialDelayMs;

  for (let attempt = 0; attempt <= RETRY_CONFIG.maxRetries; attempt++) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      // On 401, try key refresh and retry once
      if (response.status === 401 && onKeyRefresh && attempt === 0) {
        const newKey = await onKeyRefresh();
        if (newKey && newKey !== apiKey) {
          const retryController = new AbortController();
          const retryTimeout = setTimeout(() => retryController.abort(), timeoutMs);
          try {
            const headers = {
              ...(options.headers as Record<string, string>),
              Authorization: `Bearer ${newKey}`,
            };
            const retryResponse = await fetch(url, {
              ...options,
              headers,
              signal: retryController.signal,
            });
            clearTimeout(retryTimeout);
            return retryResponse;
          } catch {
            clearTimeout(retryTimeout);
            // Fall through to return original 401
          }
        }
      }

      return response;
    } catch (error) {
      clearTimeout(timeoutId);
      lastError = error instanceof Error ? error : new Error(String(error));

      // Don't retry on abort (timeout) or non-retryable errors
      if (lastError.name === 'AbortError' || !isRetryableError(error)) {
        throw lastError;
      }

      if (attempt < RETRY_CONFIG.maxRetries) {
        await sleep(delay);
        delay = Math.min(delay * RETRY_CONFIG.backoffMultiplier, RETRY_CONFIG.maxDelayMs);
      }
    }
  }

  throw lastError || new Error('Fetch failed after retries');
}

/**
 * Build the session context object for backend requests.
 */
function buildSessionContext(extraContext?: Record<string, unknown>): Record<string, unknown> {
  return {
    ...extraContext,
    session_id: getSessionId(),
    agent_id: getAgentId(),
    source_application: 'shrike-guard-ts',
  };
}

/**
 * HTTP client for the Shrike scan API.
 */
/**
 * Decide whether a scan verdict should be enforced as a block.
 *
 * Prefers the server-authoritative `action` field emitted by
 * /api/scan/enforce. Falls back to the legacy
 * `safe` boolean for verdicts that predate the enforce endpoint (older
 * backends, circuit-breaker fail-open synthetic verdicts, cached responses).
 *
 * Behavior:
 *   - action = "block"            → true
 *   - action = "require_approval" → true (held actions are refused at the
 *                                    tool-call boundary; caller can re-issue
 *                                    after approval lands)
 *   - action = "allow"            → false
 *   - action = "warn"             → false (advisory; caller should surface
 *                                    via block-feedback but not refuse)
 *   - action absent               → fall back to `!safe`
 *
 * This helper is the ONLY place the SDK converts a verdict into a
 * proceed-vs-refuse decision. Every LLM wrapper (OpenAI, Anthropic, Gemini)
 * routes through it so behavior stays uniform.
 *
 * Contract-symmetry pin: mirrors Python `_is_blocked` in shrike_guard.scanner.
 * If either SDK diverges, that is a bug in one of the two.
 */
export function isBlocked(verdict: ScanResult | Record<string, unknown>): boolean {
  const action = (verdict as Record<string, unknown>).action;
  if (typeof action === 'string' && action.length > 0) {
    // Known non-blocking tiers proceed.
    if (action === 'allow' || action === 'warn') return false;
    // Known blocking tiers refuse.
    if (action === 'block' || action === 'require_approval') return true;
    // Unknown/future tier (e.g. a new "quarantine" the backend adds): do NOT
    // fail open on an unrecognized name — fall through to `safe`. A new
    // blocking tier also sets safe:false, so this fails closed until the
    // client learns the tier explicitly. Forward-compat contract, see
    // tests/unit/contract-forward-compat.test.ts.
  }
  const safe = (verdict as Record<string, unknown>).safe;
  if (typeof safe === 'boolean') {
    return !safe;
  }
  return false;
}

/**
 * When running without an API key, appends a signup hint to scan results
 * so agents/users know they can upgrade from regex-only to full scanning.
 */
export function maybeAddSignupHint(result: ScanResult, apiKey: string): ScanResult {
  if (apiKey) return result;
  // Don't override if backend already provided upgrade_hint
  if ((result as any).upgrade_hint) return result;
  return {
    ...result,
    _note: 'Running without API key (L1-L5 only). Register free for cognitive threat detection: npx shrike-mcp --signup',
  };
}

export class ScanClient {
  private apiKey: string;
  private readonly endpoint: string;
  private readonly timeout: number;
  private readonly rateLimiter: RateLimiter;
  private readonly onKeyRefresh?: () => Promise<string | null>;

  constructor(options: ScanClientOptions) {
    this.apiKey = options.apiKey;
    this.endpoint = (options.endpoint || DEFAULT_ENDPOINT).replace(/\/$/, '');
    this.timeout = options.timeout || DEFAULT_SCAN_TIMEOUT;
    this.rateLimiter = new RateLimiter(options.rateLimitPerMinute || DEFAULT_RATE_LIMIT_PER_MINUTE);
    this.onKeyRefresh = options.onKeyRefresh;

    if (!this.apiKey) {
      console.warn('[shrike-guard] No API key provided — running in free tier (regex-only).');
      console.warn('[shrike-guard] For full scanning (LLM analysis, session correlation): npx shrike-mcp --signup');
    }
  }

  /** Check rate limit before each request. */
  private checkRateLimit(): void {
    const result = this.rateLimiter.consume();
    if (!result.allowed) {
      throw new ShrikeRateLimitError(result.retryAfterMs!);
    }
  }

  /**
   * Scan a prompt for security threats.
   *
   * @param prompt - The user prompt to scan.
   * @param context - Optional conversation context for better analysis.
   * @returns Scan result with 'safe' boolean and additional details.
   * @throws Error if the request fails or times out.
   */
  async scan(prompt: string, context?: string): Promise<ScanResult> {
    // Client-side size validation to fail fast
    const totalSize = prompt.length + (context?.length || 0);
    if (totalSize > MAX_CONTENT_SIZE) {
      return {
        safe: false,
        reason: `Content too large (${Math.round(totalSize / 1024)}KB > ${MAX_CONTENT_SIZE / 1024}KB limit)`,
        threat_type: 'size_limit_exceeded',
        confidence: 1.0,
        violations: [
          {
            type: 'size_limit',
            description: `Content exceeds maximum size of ${MAX_CONTENT_SIZE / 1024}KB`,
          },
        ],
      };
    }

    // Auto-chunk large prompts. Below the threshold we keep the single-shot
    // path unchanged; above it we split on natural boundaries, scan each
    // chunk sequentially, and stop on the first block verdict. The
    // conversation_history context is NOT chunked — it rides on every scan
    // so downstream layers see the same session shape.
    if (prompt.length > AUTO_CHUNK_THRESHOLD) {
      return this.scanChunked(prompt, context);
    }

    this.checkRateLimit();

    const payload: Record<string, unknown> = {
      prompt,
      scan_type: 'full',
      context: buildSessionContext(),
    };
    if (context) {
      payload.conversation_history = context;
    }

    const response = await fetchWithRetry(
      `${this.endpoint}/api/scan/enforce`,
      {
        method: 'POST',
        headers: getScanHeaders(this.apiKey),
        body: JSON.stringify(payload),
      },
      this.timeout,
      this.apiKey,
      this.onKeyRefresh
    );

    if (!response.ok) {
      throw new Error(`Scan API returned error: ${response.status}`);
    }

    return maybeAddSignupHint(sanitizeScanResponse((await response.json()) as ScanResult), this.apiKey);
  }

  /**
   * Chunk-and-scan path for prompts above AUTO_CHUNK_THRESHOLD. Splits on
   * natural boundaries, scans sequentially, aggregates. Stops on the first
   * block verdict (fail-fast) so a compromised chunk doesn't pay for the
   * remaining scans.
   *
   * Known limit: same session ID rides every chunk, so L9 turn count
   * inflates by chunk-count. Fix post-launch via backend chunk_group field.
   */
  private async scanChunked(prompt: string, context?: string): Promise<ScanResult> {
    const chunks = chunkContent(prompt);
    const results: ScanResult[] = [];
    for (const chunk of chunks) {
      const chunkResult = await this.scan(chunk, context);
      results.push(chunkResult);
      const action = chunkResult.action || chunkResult.refuse_tier;
      if (action === 'block') {
        break;
      }
    }
    return maybeAddSignupHint(aggregateChunkResults(results), this.apiKey);
  }

  /**
   * Scan a SQL query for injection attacks.
   *
   * @param query - The SQL query to scan.
   * @param database - Optional database name for context.
   * @param allowDestructive - If true, allows DROP/TRUNCATE operations.
   * @returns Scan result with 'safe' boolean and additional details.
   */
  async scanSql(
    query: string,
    database?: string,
    allowDestructive = false
  ): Promise<ScanResult> {
    if (query.length > MAX_CONTENT_SIZE) {
      return {
        safe: false,
        reason: `SQL query too large (${Math.round(query.length / 1024)}KB > ${MAX_CONTENT_SIZE / 1024}KB limit)`,
        threat_type: 'size_limit_exceeded',
        confidence: 1.0,
        violations: [
          {
            type: 'size_limit',
            description: `Query exceeds maximum size of ${MAX_CONTENT_SIZE / 1024}KB`,
          },
        ],
      };
    }

    this.checkRateLimit();

    const toolContext: Record<string, unknown> = {};
    if (database) {
      toolContext.database = database;
    }
    if (allowDestructive) {
      toolContext.allow_destructive = 'true';
    }

    const payload = {
      content: query,
      content_type: 'sql',
      context: buildSessionContext(toolContext),
    };

    const response = await fetchWithRetry(
      `${this.endpoint}/api/scan/enforce/specialized`,
      {
        method: 'POST',
        headers: getScanHeaders(this.apiKey),
        body: JSON.stringify(payload),
      },
      this.timeout,
      this.apiKey,
      this.onKeyRefresh
    );

    if (!response.ok) {
      throw new Error(`SQL scan API returned error: ${response.status}`);
    }

    return maybeAddSignupHint(sanitizeScanResponse((await response.json()) as ScanResult), this.apiKey);
  }

  /**
   * Scan a file path for security risks.
   *
   * @param path - The file path to validate.
   * @param content - Optional file content to scan for secrets/PII.
   * @returns Scan result with 'safe' boolean and additional details.
   */
  async scanFile(path: string, content?: string): Promise<ScanResult> {
    const totalSize = path.length + (content?.length || 0);
    if (totalSize > MAX_CONTENT_SIZE) {
      return {
        safe: false,
        reason: `File content too large (${Math.round(totalSize / 1024)}KB > ${MAX_CONTENT_SIZE / 1024}KB limit)`,
        threat_type: 'size_limit_exceeded',
        confidence: 1.0,
        violations: [
          {
            type: 'size_limit',
            description: `Content exceeds maximum size of ${MAX_CONTENT_SIZE / 1024}KB`,
          },
        ],
      };
    }

    this.checkRateLimit();

    const contentType = content ? 'file_content' : 'file_path';
    const extraContext: Record<string, unknown> = {};
    if (content) {
      extraContext.file_content = content;
    }

    const payload = {
      content: path,
      content_type: contentType,
      context: buildSessionContext(extraContext),
    };

    const response = await fetchWithRetry(
      `${this.endpoint}/api/scan/enforce/specialized`,
      {
        method: 'POST',
        headers: getScanHeaders(this.apiKey),
        body: JSON.stringify(payload),
      },
      this.timeout,
      this.apiKey,
      this.onKeyRefresh
    );

    if (!response.ok) {
      throw new Error(`File scan API returned error: ${response.status}`);
    }

    return maybeAddSignupHint(sanitizeScanResponse((await response.json()) as ScanResult), this.apiKey);
  }

  /**
   * Scan an A2A (Agent-to-Agent) protocol message for security threats.
   *
   * @param message - The A2A message text content to scan.
   * @param options - Optional context: sender/receiver agent IDs, task ID, role.
   * @returns Scan result with 'safe' boolean and additional details.
   */
  async scanA2AMessage(
    message: string,
    options?: {
      senderAgentId?: string;
      receiverAgentId?: string;
      taskId?: string;
      role?: 'user' | 'agent';
    }
  ): Promise<ScanResult> {
    if (message.length > MAX_CONTENT_SIZE) {
      return {
        safe: false,
        reason: `Message too large (${Math.round(message.length / 1024)}KB > ${MAX_CONTENT_SIZE / 1024}KB limit)`,
        threat_type: 'size_limit_exceeded',
        confidence: 1.0,
        violations: [
          {
            type: 'size_limit',
            description: `Content exceeds maximum size of ${MAX_CONTENT_SIZE / 1024}KB`,
          },
        ],
      };
    }

    this.checkRateLimit();

    const extraContext: Record<string, unknown> = {};
    if (options?.senderAgentId) extraContext.sender_agent_id = options.senderAgentId;
    if (options?.receiverAgentId) extraContext.receiver_agent_id = options.receiverAgentId;
    if (options?.taskId) extraContext.task_id = options.taskId;
    if (options?.role) extraContext.role = options.role;

    const payload = {
      content: message,
      content_type: 'a2a_message',
      context: buildSessionContext(extraContext),
    };

    const response = await fetchWithRetry(
      `${this.endpoint}/api/scan/enforce/specialized`,
      {
        method: 'POST',
        headers: getScanHeaders(this.apiKey),
        body: JSON.stringify(payload),
      },
      this.timeout,
      this.apiKey,
      this.onKeyRefresh
    );

    if (!response.ok) {
      throw new Error(`A2A message scan API returned error: ${response.status}`);
    }

    return maybeAddSignupHint(sanitizeScanResponse((await response.json()) as ScanResult), this.apiKey);
  }

  /**
   * Scan an A2A AgentCard JSON for security threats.
   *
   * @param agentCard - The raw JSON string of the A2A AgentCard to scan.
   * @param verifySignature - Reserved for future JWS signature verification.
   * @returns Scan result with 'safe' boolean and additional details.
   */
  async scanAgentCard(
    agentCard: string,
    verifySignature = false
  ): Promise<ScanResult> {
    if (agentCard.length > MAX_CONTENT_SIZE) {
      return {
        safe: false,
        reason: `Agent card too large (${Math.round(agentCard.length / 1024)}KB > ${MAX_CONTENT_SIZE / 1024}KB limit)`,
        threat_type: 'size_limit_exceeded',
        confidence: 1.0,
        violations: [
          {
            type: 'size_limit',
            description: `Content exceeds maximum size of ${MAX_CONTENT_SIZE / 1024}KB`,
          },
        ],
      };
    }

    this.checkRateLimit();

    const extraContext: Record<string, unknown> = {};
    if (verifySignature) extraContext.verify_signature = 'true';

    const payload = {
      content: agentCard,
      content_type: 'agent_card',
      context: buildSessionContext(extraContext),
    };

    const response = await fetchWithRetry(
      `${this.endpoint}/api/scan/enforce/specialized`,
      {
        method: 'POST',
        headers: getScanHeaders(this.apiKey),
        body: JSON.stringify(payload),
      },
      this.timeout,
      this.apiKey,
      this.onKeyRefresh
    );

    if (!response.ok) {
      throw new Error(`Agent card scan API returned error: ${response.status}`);
    }

    return maybeAddSignupHint(sanitizeScanResponse((await response.json()) as ScanResult), this.apiKey);
  }

  /**
   * Declare (or refresh) the operating scope for a task-scoped agent.
   *
   * Once declared, every subsequent scan for the same agent_id is enforced
   * against the scope on the backend. Tool calls outside allowed_tools —
   * or explicitly on forbidden_tools — route to refuse_tier:
   * "require_approval" with threat_type: "scope_violation". Expired scopes
   * emit threat_type: "scope_expired". Absent a declaration, no scope
   * check runs; every existing SDK integration is unaffected until it
   * opts in.
   *
   * Wire contract mirrors ScanClient.declare_scope on the Python SDK and
   * scan_declare_scope on the shrike-mcp package — do not diverge without
   * updating those siblings.
   *
   * @param options.agentId - Agent identity this scope applies to.
   * @param options.allowedTools - Exact tool names permitted; ["*"] = any.
   * @param options.forbiddenTools - Optional. Wins over allowedTools.
   * @param options.purpose - Optional audit + dashboard label.
   * @param options.maxDurationSeconds - Optional TTL from created_at.
   * @param options.expiresAt - Optional ISO-8601 absolute expiry.
   * @returns The persisted scope row, including scope_id + active_until.
   */
  async declareScope(options: {
    agentId: string;
    allowedTools: string[];
    forbiddenTools?: string[];
    purpose?: string;
    maxDurationSeconds?: number;
    expiresAt?: string;
  }): Promise<DeclareScopeResult> {
    this.checkRateLimit();

    const payload: Record<string, unknown> = {
      agent_id: options.agentId,
      allowed_tools: options.allowedTools,
    };
    if (options.purpose !== undefined) payload.purpose = options.purpose;
    if (options.forbiddenTools !== undefined) payload.forbidden_tools = options.forbiddenTools;
    if (options.maxDurationSeconds !== undefined) {
      payload.max_duration_seconds = options.maxDurationSeconds;
    }
    if (options.expiresAt !== undefined) payload.expires_at = options.expiresAt;

    const response = await fetchWithRetry(
      `${this.endpoint}/api/v1/agent/scope/declare`,
      {
        method: 'POST',
        headers: getScanHeaders(this.apiKey),
        body: JSON.stringify(payload),
      },
      this.timeout,
      this.apiKey,
      this.onKeyRefresh
    );

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(
        `declareScope failed: ${response.status}${text ? ` — ${text.trim()}` : ''}`
      );
    }

    return (await response.json()) as DeclareScopeResult;
  }
}
