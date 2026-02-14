/**
 * ShrikeAnthropic - Drop-in replacement for Anthropic client with security scanning.
 */

import type Anthropic from '@anthropic-ai/sdk';
import type { MessageCreateParams, Message } from '@anthropic-ai/sdk/resources/messages';

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
 * Content block type for Anthropic messages.
 */
interface ContentBlock {
  type: string;
  text?: string;
  [key: string]: unknown;
}

/**
 * Anthropic message type.
 */
interface AnthropicMessage {
  role: string;
  content: string | ContentBlock[];
}

/**
 * Options for creating a ShrikeAnthropic client.
 */
export interface ShrikeAnthropicOptions {
  /** Anthropic API key. If not provided, uses ANTHROPIC_API_KEY env var. */
  apiKey?: string;
  /** Shrike API key for authentication with the scan service. */
  shrikeApiKey?: string;
  /** Shrike API endpoint URL. */
  shrikeEndpoint?: string;
  /** Behavior on scan failure - 'open' (allow) or 'closed' (block). */
  failMode?: FailMode | 'open' | 'closed';
  /** Timeout for scan requests in milliseconds. */
  scanTimeout?: number;
  /** Additional options passed to the Anthropic client. */
  anthropicOptions?: Record<string, unknown>;
}

/**
 * Drop-in replacement for Anthropic with Shrike security protection.
 *
 * This class wraps the official Anthropic client and automatically scans
 * all prompts before they are sent to Claude. If a prompt is detected
 * as unsafe, the request is blocked and a ShrikeBlockedError is raised.
 *
 * @example
 * ```typescript
 * import { ShrikeAnthropic } from 'shrike-guard/anthropic';
 *
 * const client = new ShrikeAnthropic({
 *   apiKey: 'sk-ant-...',
 *   shrikeApiKey: 'shrike-...',
 * });
 *
 * const message = await client.messages.create({
 *   model: 'claude-3-opus-20240229',
 *   max_tokens: 1024,
 *   messages: [{ role: 'user', content: 'Hello!' }],
 * });
 * ```
 */
export class ShrikeAnthropic {
  private _anthropic: Anthropic;
  private _shrikeEndpoint: string;
  private _shrikeApiKey: string;
  private _failMode: FailMode;
  private _scanTimeout: number;

  /** Namespace for messages operations */
  public readonly messages: MessagesNamespace;

  constructor(options: ShrikeAnthropicOptions = {}) {
    // Dynamically import Anthropic to make it a peer dependency
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const AnthropicClient = require('@anthropic-ai/sdk').default;

    this._anthropic = new AnthropicClient({
      apiKey: options.apiKey,
      ...options.anthropicOptions,
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

    // Expose messages interface
    this.messages = new MessagesNamespace(this);
  }

  /**
   * Extract all user message content from a messages list.
   */
  _extractUserContent(messages: AnthropicMessage[]): string {
    const userContents: string[] = [];

    for (const msg of messages) {
      if (msg.role === 'user') {
        if (typeof msg.content === 'string') {
          userContents.push(msg.content);
        } else if (Array.isArray(msg.content)) {
          for (const block of msg.content) {
            if (block.type === 'text' && block.text) {
              userContents.push(block.text);
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
  async _scanMessages(messages: AnthropicMessage[]): Promise<ScanResult> {
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

  /** Access the underlying Anthropic client */
  get anthropic(): Anthropic {
    return this._anthropic;
  }
}

/**
 * Namespace for messages operations.
 */
class MessagesNamespace {
  private _client: ShrikeAnthropic;

  constructor(client: ShrikeAnthropic) {
    this._client = client;
  }

  /**
   * Create a message with security scanning.
   *
   * This method scans the user messages before sending them to Anthropic.
   * If the scan detects a security threat, a ShrikeBlockedError is raised.
   */
  async create(params: MessageCreateParams): Promise<Message> {
    // 1. Scan messages for security threats
    const scanResult = await this._client._scanMessages(
      params.messages as unknown as AnthropicMessage[]
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

    // 3. Proxy to Anthropic (non-streaming)
    return this._client.anthropic.messages.create({
      ...params,
      stream: false,
    }) as unknown as Promise<Message>;
  }
}
