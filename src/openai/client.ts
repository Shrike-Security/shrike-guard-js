/**
 * ShrikeOpenAI - Drop-in replacement for OpenAI client with security scanning.
 */

import type OpenAI from 'openai';
import type {
  ChatCompletionCreateParams,
  ChatCompletionCreateParamsNonStreaming,
  ChatCompletionCreateParamsStreaming,
  ChatCompletion,
  ChatCompletionChunk,
} from 'openai/resources/chat/completions';
import type { Stream } from 'openai/streaming';

import {
  FailMode,
  DEFAULT_ENDPOINT,
  DEFAULT_FAIL_MODE,
  DEFAULT_SCAN_TIMEOUT,
} from '../config';
import { ShrikeBlockedError, ShrikeScanError } from '../errors';
import { sanitizeScanResponse } from '../sanitizer';
import { getScanHeaders, ScanResult } from '../scanner';

/**
 * Simple logger for warnings.
 */
function logWarning(message: string): void {
  console.warn(`⚠️  ${message}`);
}

/**
 * Message content part type for multimodal messages.
 */
interface ContentPart {
  type: string;
  text?: string;
  [key: string]: unknown;
}

/**
 * Chat message type.
 */
interface ChatMessage {
  role: string;
  content?: string | ContentPart[] | null;
  [key: string]: unknown;
}

/**
 * Options for creating a ShrikeOpenAI client.
 */
export interface ShrikeOpenAIOptions {
  /** OpenAI API key. If not provided, uses OPENAI_API_KEY env var. */
  apiKey?: string;
  /** Shrike API key for authentication with the scan service. */
  shrikeApiKey?: string;
  /** Shrike API endpoint URL. */
  shrikeEndpoint?: string;
  /** Behavior on scan failure - 'open' (allow) or 'closed' (block). */
  failMode?: FailMode | 'open' | 'closed';
  /** Timeout for scan requests in milliseconds. */
  scanTimeout?: number;
  /** Additional options passed to the OpenAI client. */
  openaiOptions?: Record<string, unknown>;
}

/**
 * Drop-in replacement for openai.OpenAI with Shrike security protection.
 *
 * This class wraps the official OpenAI client and automatically scans
 * all prompts before they are sent to the LLM. If a prompt is detected
 * as unsafe, the request is blocked and a ShrikeBlockedError is raised.
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
export class ShrikeOpenAI {
  private _openai: OpenAI;
  private _shrikeEndpoint: string;
  private _shrikeApiKey: string;
  private _failMode: FailMode;
  private _scanTimeout: number;

  /** Namespace for chat-related operations */
  public readonly chat: ChatNamespace;

  constructor(options: ShrikeOpenAIOptions = {}) {
    // Dynamically import OpenAI to make it a peer dependency
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const OpenAIClient = require('openai').default;

    this._openai = new OpenAIClient({
      apiKey: options.apiKey,
      ...options.openaiOptions,
    });
    this._shrikeEndpoint = (options.shrikeEndpoint || DEFAULT_ENDPOINT).replace(/\/$/, '');
    this._shrikeApiKey = options.shrikeApiKey || '';
    this._failMode =
      typeof options.failMode === 'string'
        ? (options.failMode as FailMode)
        : options.failMode || DEFAULT_FAIL_MODE;
    this._scanTimeout = options.scanTimeout || DEFAULT_SCAN_TIMEOUT;

    // Note: All scanning is done via backend API (tier-based: free=L1-L4, paid=L1-L8)
    // No local scanning - backend has full regex patterns (~50+) and normalizers

    // Expose chat interface
    this.chat = new ChatNamespace(this);
  }

  /**
   * Extract all user message content from a messages list.
   */
  _extractUserContent(messages: ChatMessage[]): string {
    const userContents: string[] = [];

    for (const msg of messages) {
      if (msg.role === 'user' && msg.content) {
        if (typeof msg.content === 'string') {
          userContents.push(msg.content);
        } else if (Array.isArray(msg.content)) {
          // Handle multimodal content (list of content parts)
          for (const part of msg.content) {
            if (part.type === 'text' && part.text) {
              userContents.push(part.text);
            }
          }
        }
      }
    }

    return userContents.join('\n');
  }

  /**
   * Scan user messages for security threats via backend API.
   *
   * Always calls backend - backend handles tier-based scanning:
   * - Free tier (no API key): L1-L4 (regex, unicode, encoding, token normalization)
   * - Paid tier: L1-L8 (full scan including LLM)
   */
  async _scanMessages(messages: ChatMessage[]): Promise<ScanResult> {
    const userContent = this._extractUserContent(messages);

    if (!userContent.trim()) {
      return { safe: true, reason: 'No user content to scan' };
    }

    // Always call backend API - tier detection happens server-side
    return this._remoteScan(userContent);
  }

  /**
   * Full scan via Shrike backend API.
   * Backend handles tier-based scanning automatically based on API key presence.
   */
  private async _remoteScan(prompt: string): Promise<ScanResult> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this._scanTimeout);

    try {
      const response = await fetch(`${this._shrikeEndpoint}/scan`, {
        method: 'POST',
        headers: getScanHeaders(this._shrikeApiKey),
        body: JSON.stringify({ prompt }),
        signal: controller.signal,
      });

      if (!response.ok) {
        if (this._failMode === FailMode.OPEN) {
          return { safe: true, reason: `Scan API error: ${response.status}` };
        }
        throw new ShrikeScanError(`Scan API returned error: ${response.status}`);
      }

      return sanitizeScanResponse((await response.json()) as ScanResult);
    } catch (error) {
      if (error instanceof ShrikeScanError) {
        throw error;
      }

      const errorMessage = error instanceof Error ? error.message : String(error);

      if (errorMessage.includes('abort')) {
        if (this._failMode === FailMode.OPEN) {
          // No local fallback - just fail open
          logWarning('Scan request timed out, failing open (allowing request)');
          return { safe: true, reason: 'Scan timeout, failing open' };
        }
        throw new ShrikeScanError("Scan request timed out and fail_mode is 'closed'");
      }

      if (this._failMode === FailMode.OPEN) {
        return { safe: true, reason: `Scan error: ${errorMessage}` };
      }
      throw new ShrikeScanError(`Scan failed: ${errorMessage}`);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Scan a SQL query for injection attacks and dangerous operations.
   *
   * @param query - The SQL query to scan.
   * @param database - Optional database name for context.
   * @param allowDestructive - If true, allows DROP/TRUNCATE operations.
   * @returns Scan result with 'safe' boolean, 'threat_level', 'issues', etc.
   */
  async scanSql(
    query: string,
    database?: string,
    allowDestructive = false
  ): Promise<ScanResult> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this._scanTimeout);

    try {
      const response = await fetch(`${this._shrikeEndpoint}/api/scan/specialized`, {
        method: 'POST',
        headers: getScanHeaders(this._shrikeApiKey),
        body: JSON.stringify({
          content: query,
          content_type: 'sql',
          context: {
            database: database || '',
            allow_destructive: String(allowDestructive),
          },
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        if (this._failMode === FailMode.OPEN) {
          return { safe: true, reason: `Scan API error: ${response.status}` };
        }
        throw new ShrikeScanError(`SQL scan API returned error: ${response.status}`);
      }

      return sanitizeScanResponse((await response.json()) as ScanResult);
    } catch (error) {
      if (error instanceof ShrikeScanError) {
        throw error;
      }

      if (this._failMode === FailMode.OPEN) {
        return { safe: true, reason: `Scan error: ${error}` };
      }
      throw new ShrikeScanError(`SQL scan failed: ${error}`);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Scan a file path for security risks.
   *
   * @param path - The file path to validate.
   * @param content - Optional file content to scan for secrets/PII.
   * @returns Scan result with 'safe' boolean, 'threat_type', 'reason', etc.
   */
  async scanFile(path: string, content?: string): Promise<ScanResult> {
    const contentType = content ? 'file_content' : 'file_path';
    const payload: Record<string, unknown> = {
      content: path,
      content_type: contentType,
    };
    if (content) {
      payload.context = { file_content: content };
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this._scanTimeout);

    try {
      const response = await fetch(`${this._shrikeEndpoint}/api/scan/specialized`, {
        method: 'POST',
        headers: getScanHeaders(this._shrikeApiKey),
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!response.ok) {
        if (this._failMode === FailMode.OPEN) {
          return { safe: true, reason: `Scan API error: ${response.status}` };
        }
        throw new ShrikeScanError(`File scan API returned error: ${response.status}`);
      }

      return sanitizeScanResponse((await response.json()) as ScanResult);
    } catch (error) {
      if (error instanceof ShrikeScanError) {
        throw error;
      }

      if (this._failMode === FailMode.OPEN) {
        return { safe: true, reason: `Scan error: ${error}` };
      }
      throw new ShrikeScanError(`File scan failed: ${error}`);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /** Access the underlying OpenAI client */
  get openai(): OpenAI {
    return this._openai;
  }
}

/**
 * Namespace for chat-related operations.
 */
class ChatNamespace {
  public readonly completions: CompletionsNamespace;

  constructor(client: ShrikeOpenAI) {
    this.completions = new CompletionsNamespace(client);
  }
}

/**
 * Namespace for chat.completions operations.
 */
class CompletionsNamespace {
  private _client: ShrikeOpenAI;

  constructor(client: ShrikeOpenAI) {
    this._client = client;
  }

  /**
   * Create a chat completion with security scanning.
   *
   * This method scans the user messages before sending them to OpenAI.
   * If the scan detects a security threat, a ShrikeBlockedError is raised.
   */
  async create(params: ChatCompletionCreateParamsNonStreaming): Promise<ChatCompletion>;
  async create(
    params: ChatCompletionCreateParamsStreaming
  ): Promise<Stream<ChatCompletionChunk>>;
  async create(
    params: ChatCompletionCreateParams
  ): Promise<ChatCompletion | Stream<ChatCompletionChunk>>;
  async create(
    params: ChatCompletionCreateParams
  ): Promise<ChatCompletion | Stream<ChatCompletionChunk>> {
    // 1. Scan messages for security threats
    const scanResult = await this._client._scanMessages(
      params.messages as unknown as ChatMessage[]
    );

    // 2. Block if unsafe
    if (!scanResult.safe) {
      throw new ShrikeBlockedError(
        `Request blocked: ${scanResult.reason || 'Security threat detected'}`,
        scanResult.threat_type,
        scanResult.confidence,
        scanResult.violations || []
      );
    }

    // 3. Proxy to OpenAI
    return this._client.openai.chat.completions.create(params);
  }
}
