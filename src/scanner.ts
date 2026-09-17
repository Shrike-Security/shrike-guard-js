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
  warnOnceAboutTheProcessSession,
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

/**
 * Provenance of scanned content. See {@link ScanResult.content_origin}.
 */
export type ContentOrigin =
  | 'human_prompt'
  | 'agent_output'
  | 'agent_action'
  | 'third_party';

/**
 * True when the operator is answerable for this content — i.e. a person
 * typed it. Everything else was produced by the agent or arrived from
 * outside, and a refusal on it is not something the operator did.
 *
 * Use it to decide who a refusal message is addressed to: telling a user
 * "your request was blocked" when the agent poisoned its own context is
 * both wrong and unhelpful.
 */
export function attributableToOperator(origin?: ContentOrigin): boolean {
  return origin === 'human_prompt';
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
  /**
   * Where the scanned content came from — who is answerable for it.
   *
   * - `human_prompt`   the operator typed it
   * - `agent_output`   the model generated it
   * - `agent_action`   the agent is about to do it (every act-plane surface)
   * - `third_party`    it arrived from outside: a tool result, a retrieved
   *                    document, a peer agent
   *
   * This is the field that answers "was that my prompt, or the agent acting
   * on its own?" — the question you cannot reconstruct after the fact from a
   * verdict alone. Unknown content types resolve to `agent_action`, never to
   * `human_prompt`: attributing an unattributable action to the operator is
   * the one error that is never safe to make.
   */
  content_origin?: ContentOrigin;
  /**
   * True when the agent's declared scope held this action (expired, tool
   * outside the scope, or action ceiling reached). The hold never skips the
   * content scan: a content block wins and stands as the verdict; otherwise
   * the verdict is require_approval and content_verdict carries what the
   * content scan said.
   */
  held_by_scope?: boolean;
  /** The content scan's own answer on a held action; absent when the content was blocked */
  content_verdict?: {
    safe: boolean;
    refuse_tier: ScanAction;
    threat_type?: string;
    severity?: string;
  };
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
  /** Renewal window: until when this key may refresh the scope itself.
      Absent means no ceiling; ceiling_reached means only an operator can now. */
  renewable_seconds?: number;
  renewable_until?: string;
  ceiling_reached?: boolean;
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
  /**
   * The session this client scans under. Session identity is the key the
   * backend accumulates multi-turn risk against, so it should mean one unit
   * of work: one agent run, one conversation, one user's request. Defaults to
   * a process-wide id, which suits a CLI or a worker but not a server serving
   * many end users, where each user needs its own session. Prefer
   * `client.forSession(id)` per request.
   */
  sessionId?: string;
  /**
   * The agent this client scans as. Defaults to the process-wide id
   * (`SHRIKE_AGENT_ID` when set). Set it when one process drives several
   * distinct agents, so scope enforcement and agent attribution land on the
   * right one.
   */
  agentId?: string;
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
 *
 * `sessionId` / `agentId` override the process-wide defaults. When no session
 * id is supplied we warn once — see warnOnceAboutTheProcessSession for why the
 * default stays rather than being removed.
 */
function buildSessionContext(
  extraContext?: Record<string, unknown>,
  sessionId?: string,
  agentId?: string
): Record<string, unknown> {
  if (!sessionId) warnOnceAboutTheProcessSession();

  return {
    ...extraContext,
    session_id: sessionId || getSessionId(),
    agent_id: agentId || getAgentId(),
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
  private readonly sessionId?: string;
  private readonly agentId?: string;

  constructor(options: ScanClientOptions) {
    this.apiKey = options.apiKey;
    this.endpoint = (options.endpoint || DEFAULT_ENDPOINT).replace(/\/$/, '');
    this.timeout = options.timeout || DEFAULT_SCAN_TIMEOUT;
    this.rateLimiter = new RateLimiter(options.rateLimitPerMinute || DEFAULT_RATE_LIMIT_PER_MINUTE);
    this.onKeyRefresh = options.onKeyRefresh;
    this.sessionId = options.sessionId;
    this.agentId = options.agentId;

    if (!this.apiKey) {
      console.warn('[shrike-guard] No API key provided — running in free tier (regex-only).');
      console.warn('[shrike-guard] For full scanning (LLM analysis, session correlation): npx shrike-mcp --signup');
    }
  }

  /**
   * Return a view of this client that scans under `sessionId`.
   *
   * The returned client SHARES this one's rate limiter, so deriving one per
   * request is cheap and cannot multiply your rate budget. Build one ScanClient
   * at startup and derive a per-request view from it:
   *
   * ```ts
   * const guard = new ScanClient({ apiKey: KEY });   // once, at startup
   *
   * app.post('/act', async (req, res) => {           // per request
   *   const scoped = guard.forSession(req.session.id);
   *   const verdict = await scoped.scanCommand(req.body.command);
   * });
   * ```
   *
   * Without this, every end user shares one session id and therefore one risk
   * score, and one user's refusal counts against the next user's action.
   */
  forSession(sessionId: string, agentId?: string): ScanClient {
    const view: ScanClient = Object.create(ScanClient.prototype);
    // Written through a mutable alias because the fields are readonly on the
    // class: this is a copy constructor, not a mutation of an existing client.
    const w = view as unknown as Record<string, unknown>;
    w.apiKey = this.apiKey;
    w.endpoint = this.endpoint;
    w.timeout = this.timeout;
    // Shared deliberately — a per-request client with its own limiter would
    // give every request a full rate budget and defeat the limit entirely.
    w.rateLimiter = this.rateLimiter;
    w.onKeyRefresh = this.onKeyRefresh;
    w.sessionId = sessionId;
    w.agentId = agentId !== undefined ? agentId : this.agentId;
    return view;
  }

  /** Session identity for this client, with any per-call extras merged. */
  private sessionContext(extraContext?: Record<string, unknown>): Record<string, unknown> {
    return buildSessionContext(extraContext, this.sessionId, this.agentId);
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
  async scan(
    prompt: string,
    context?: string,
    options?: { plane?: string }
  ): Promise<ScanResult> {
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
      return this.scanChunked(prompt, context, options);
    }

    this.checkRateLimit();

    const payload: Record<string, unknown> = {
      prompt,
      scan_type: 'full',
      context: this.sessionContext(options?.plane ? { plane: options.plane } : undefined),
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
   * Known limit: the same session id rides every chunk, so the session turn
   * count grows by the number of chunks.
   */
  private async scanChunked(
    prompt: string,
    context?: string,
    options?: { plane?: string }
  ): Promise<ScanResult> {
    const chunks = chunkContent(prompt);
    const results: ScanResult[] = [];
    for (const chunk of chunks) {
      const chunkResult = await this.scan(chunk, context, options);
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
      context: this.sessionContext(toolContext),
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
      context: this.sessionContext(extraContext),
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
      context: this.sessionContext(extraContext),
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
      context: this.sessionContext(extraContext),
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
   * Scan a shell command before executing it.
   *
   * The highest-volume act-plane surface, and the one the SDK could not
   * reach until 4.1.0: `shrike.scanCommand(cmd)` before you shell out is the
   * enforcement point. Catches destructive operations, fetch-and-execute
   * chains, reverse shells, credential reads, anti-forensics, and SQL
   * injection carried inside a database CLI argument (`psql -c "..."`),
   * which the command's own grammar cannot see.
   *
   * @param command - The command line about to be executed.
   * @param cwd - Optional working directory, for context.
   * @returns Scan result; check `safe` and `refuse_tier` before executing.
   */
  /**
   * Ask whether this agent may call a tool, without sending its arguments.
   *
   * For a tool this SDK has no reader for. The operator's declared scope
   * judges a tool by NAME, so a tool nobody can parse is still refused when
   * it is not on the allowlist, and still held when the scope has expired or
   * run out of actions.
   *
   * This answers one question. A permit says the agent was allowed to make
   * the call; it never says the arguments were inspected, because none were
   * sent. Where a tool maps to one of the scanned surfaces, scan that surface
   * instead and get both answers.
   *
   * @param toolName - The tool about to run.
   * @returns Scan result; check `safe` and `refuse_tier` before running.
   */
  async authorizeTool(toolName: string): Promise<ScanResult> {
    this.checkRateLimit();
    const response = await fetchWithRetry(
      `${this.endpoint}/api/scan/authorize`,
      {
        method: 'POST',
        headers: getScanHeaders(this.apiKey),
        body: JSON.stringify({ tool_name: toolName, context: this.sessionContext() }),
      },
      this.timeout,
      this.apiKey,
      this.onKeyRefresh
    );
    if (!response.ok) {
      throw new Error(`Tool authorization API returned error: ${response.status}`);
    }
    return maybeAddSignupHint(sanitizeScanResponse((await response.json()) as ScanResult), this.apiKey);
  }

  async scanCommand(command: string, cwd?: string): Promise<ScanResult> {
    const toolContext: Record<string, unknown> = {};
    if (cwd) toolContext.cwd = cwd;
    return this.scanSpecialized(command, 'command', 'Command', toolContext);
  }

  /**
   * Scan a web search query before it reaches an external search engine.
   *
   * Catches PII and credentials leaving through a search box, credential
   * dorking, evasion tradecraft, illicit acquisition, and attack-tool
   * acquisition — while leaving ordinary defensive research alone.
   *
   * @param query - The search query about to be issued.
   * @returns Scan result; check `safe` before searching.
   */
  async scanWebSearch(query: string): Promise<ScanResult> {
    return this.scanSpecialized(query, 'web_search', 'Web search');
  }

  /**
   * Scan a single MCP tool definition before trusting or registering it.
   *
   * Detects tool poisoning: instructions hidden in a tool's own
   * `description`, which an agent reads as guidance and acts on without the
   * tool ever executing. Call this on every entry of a `tools/list` response
   * from a server you do not control.
   *
   * @param name - The tool name as advertised.
   * @param description - The tool description to screen.
   * @param inputSchema - Optional JSON schema; also screened.
   * @returns Scan result; do not register the tool when `safe` is false.
   */
  async scanMcpSchema(
    name: string,
    description: string,
    inputSchema?: Record<string, unknown>
  ): Promise<ScanResult> {
    this.checkRateLimit();

    const payload = {
      name,
      description,
      ...(inputSchema ? { input_schema: inputSchema } : {}),
    };

    const response = await fetchWithRetry(
      `${this.endpoint}/api/scan/mcp_schema`,
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
      throw new Error(`MCP schema scan API returned error: ${response.status}`);
    }

    return maybeAddSignupHint(sanitizeScanResponse((await response.json()) as ScanResult), this.apiKey);
  }

  /**
   * Scan retrieved context before feeding it to the model.
   *
   * RAG chunks are untrusted text from documents someone else wrote — the
   * standard carrier for indirect prompt injection. Scan them on the way in,
   * not after the model has already acted on them.
   *
   * @param chunks - The retrieved chunks, as text or an array of texts.
   * @param query - Optional user query the chunks were retrieved for.
   * @returns Scan result; check `safe` before including the context.
   */
  async scanRagContext(chunks: string | string[], query?: string): Promise<ScanResult> {
    const content = Array.isArray(chunks) ? JSON.stringify(chunks) : chunks;
    const toolContext: Record<string, unknown> = {};
    if (query) toolContext.query = query;
    return this.scanSpecialized(content, 'rag_context', 'RAG context', toolContext);
  }

  /**
   * Shared transport for the specialized (act-plane) surfaces.
   *
   * Every act-plane method above differs only in content type, the label used
   * in the error message, and any extra context. Before 4.1.0 each surface
   * hand-rolled this block, which is how the SDK ended up with five of the
   * eight channels missing: adding one meant copying forty lines. Now it
   * means one method.
   */
  private async scanSpecialized(
    content: string,
    contentType: string,
    label: string,
    toolContext: Record<string, unknown> = {}
  ): Promise<ScanResult> {
    if (content.length > MAX_CONTENT_SIZE) {
      return {
        safe: false,
        reason: `${label} content too large (${Math.round(content.length / 1024)}KB > ${MAX_CONTENT_SIZE / 1024}KB limit)`,
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

    const payload = {
      content,
      content_type: contentType,
      context: this.sessionContext(toolContext),
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
      throw new Error(`${label} scan API returned error: ${response.status}`);
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
   * @param options.maxDurationSeconds - Optional TTL from the latest declaration.
   * @param options.expiresAt - Optional ISO-8601 absolute expiry.
   * @param options.renewableSeconds - Optional renewal window: how long, from
   *   the operator's grant, this key may keep refreshing the scope. Honoured
   *   on a first declaration; on a refresh the stored value always wins.
   * @returns The persisted scope row, including scope_id, active_until and
   *   renewable_until.
   *
   * Refreshing: once the scope exists, calling again from the agent's own key
   * is a refresh. Any option left out is inherited from the scope on file, so
   * `{ agentId, maxDurationSeconds: 7200 }` is a complete refresh. A refresh
   * may narrow but never widen (403, reason "widening"), and stops working
   * once the operator's renewal window closes (403, reason "ceiling_reached").
   */
  async declareScope(options: {
    agentId: string;
    /** Required on a first declaration; omit on a refresh to inherit. */
    allowedTools?: string[];
    forbiddenTools?: string[];
    purpose?: string;
    maxDurationSeconds?: number;
    expiresAt?: string;
    renewableSeconds?: number;
  }): Promise<DeclareScopeResult> {
    this.checkRateLimit();

    const payload: Record<string, unknown> = {
      agent_id: options.agentId,
    };
    if (options.allowedTools !== undefined) payload.allowed_tools = options.allowedTools;
    if (options.purpose !== undefined) payload.purpose = options.purpose;
    if (options.forbiddenTools !== undefined) payload.forbidden_tools = options.forbiddenTools;
    if (options.maxDurationSeconds !== undefined) {
      payload.max_duration_seconds = options.maxDurationSeconds;
    }
    if (options.expiresAt !== undefined) payload.expires_at = options.expiresAt;
    if (options.renewableSeconds !== undefined) payload.renewable_seconds = options.renewableSeconds;

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
