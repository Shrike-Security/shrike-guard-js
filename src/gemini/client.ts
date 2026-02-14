/**
 * ShrikeGemini - Drop-in replacement for Google Gemini client with security scanning.
 */

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
 * Content part type for Gemini messages.
 */
interface ContentPart {
  text?: string;
  [key: string]: unknown;
}

/**
 * Content type for Gemini - can be string, array of parts, or object with parts.
 */
type GeminiContent = string | ContentPart[] | { parts?: ContentPart[]; text?: string };

/**
 * Minimal interface for the underlying Google GenerativeAI client.
 * Defined here to avoid requiring @google/generative-ai at compile time.
 */
interface GoogleGenAIClient {
  getGenerativeModel(params: { model: string; [key: string]: unknown }): GoogleGenModel;
}

/**
 * Minimal interface for Google's GenerativeModel.
 */
interface GoogleGenModel {
  generateContent(contents: GeminiContent): Promise<unknown>;
  generateContentStream(contents: GeminiContent): Promise<unknown>;
  startChat(options?: Record<string, unknown>): GoogleChatSession;
}

/**
 * Minimal interface for Google's ChatSession.
 */
interface GoogleChatSession {
  sendMessage(content: GeminiContent): Promise<unknown>;
  sendMessageStream(content: GeminiContent): Promise<unknown>;
  history: unknown[];
}

/**
 * Options for creating a ShrikeGemini client.
 */
export interface ShrikeGeminiOptions {
  /** Google AI API key. */
  apiKey?: string;
  /** Shrike API key for authentication with the scan service. */
  shrikeApiKey?: string;
  /** Shrike API endpoint URL. */
  shrikeEndpoint?: string;
  /** Behavior on scan failure - 'open' (allow) or 'closed' (block). */
  failMode?: FailMode | 'open' | 'closed';
  /** Timeout for scan requests in milliseconds. */
  scanTimeout?: number;
}

/**
 * Shrike-protected wrapper for Google's Generative AI (Gemini).
 *
 * Intercepts all generate_content() calls to scan prompts before
 * they reach Gemini.
 *
 * @example
 * ```typescript
 * import { ShrikeGemini } from 'shrike-guard/gemini';
 *
 * const client = new ShrikeGemini({
 *   apiKey: 'AIza...',
 *   shrikeApiKey: 'shrike-...',
 * });
 *
 * const model = client.getGenerativeModel({ model: 'gemini-1.5-flash' });
 * const response = await model.generateContent('Hello!');
 * ```
 */
export class ShrikeGemini {
  private _apiKey: string;
  private _shrikeEndpoint: string;
  private _shrikeApiKey: string;
  private _failMode: FailMode;
  private _scanTimeout: number;
  private _genAI: GoogleGenAIClient;

  constructor(options: ShrikeGeminiOptions = {}) {
    this._apiKey = options.apiKey || '';
    this._shrikeEndpoint = (options.shrikeEndpoint || DEFAULT_ENDPOINT).replace(/\/$/, '');
    this._shrikeApiKey = options.shrikeApiKey || '';
    this._failMode =
      typeof options.failMode === 'string'
        ? (options.failMode as FailMode)
        : options.failMode || DEFAULT_FAIL_MODE;
    this._scanTimeout = options.scanTimeout || DEFAULT_SCAN_TIMEOUT;

    // Note: All scanning is done via backend API (tier-based: free=L1-L4, paid=L1-L8)
    // No local scanning - backend has full regex patterns (~50+) and normalizers

    // Dynamically import Google Generative AI
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { GoogleGenerativeAI } = require('@google/generative-ai');
      this._genAI = new GoogleGenerativeAI(this._apiKey) as GoogleGenAIClient;
    } catch {
      throw new Error(
        '@google/generative-ai package is not installed. Install it with: npm install @google/generative-ai'
      );
    }
  }

  /**
   * Get a Shrike-protected GenerativeModel.
   */
  getGenerativeModel(params: { model: string; [key: string]: unknown }): ShrikeGenerativeModel {
    return new ShrikeGenerativeModel(params, this);
  }

  /**
   * Alias for getGenerativeModel for Python SDK compatibility.
   */
  GenerativeModel(modelName: string, options: Record<string, unknown> = {}): ShrikeGenerativeModel {
    return this.getGenerativeModel({ model: modelName, ...options });
  }

  /**
   * Extract text content from various input formats.
   */
  _extractContent(contents: GeminiContent): string {
    if (typeof contents === 'string') {
      return contents;
    }

    if (Array.isArray(contents)) {
      const texts: string[] = [];
      for (const item of contents) {
        if (typeof item === 'string') {
          texts.push(item);
        } else if (item.text) {
          texts.push(item.text);
        }
      }
      return texts.join('\n');
    }

    if (typeof contents === 'object') {
      if ('text' in contents && contents.text) {
        return contents.text;
      }
      if ('parts' in contents && contents.parts) {
        return this._extractContent(contents.parts);
      }
    }

    return String(contents);
  }

  /**
   * Scan content before sending to Gemini via backend API.
   *
   * Always calls backend - backend handles tier-based scanning:
   * - Free tier (no API key): L1-L4 (regex, unicode, encoding, token normalization)
   * - Paid tier: L1-L8 (full scan including LLM)
   */
  async _scanContent(contents: GeminiContent): Promise<ScanResult> {
    const textContent = this._extractContent(contents);

    if (!textContent.trim()) {
      return { safe: true, reason: 'No text content to scan' };
    }

    // Always call backend API - tier detection happens server-side
    return this._remoteScan(textContent);
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

  /** Access the underlying Google Generative AI client */
  get genAI(): GoogleGenAIClient {
    return this._genAI;
  }
}

/**
 * Wrapped GenerativeModel with Shrike protection.
 */
export class ShrikeGenerativeModel {
  private _modelParams: { model: string; [key: string]: unknown };
  private _shrikeClient: ShrikeGemini;
  private _model: GoogleGenModel;

  constructor(
    params: { model: string; [key: string]: unknown },
    shrikeClient: ShrikeGemini
  ) {
    this._modelParams = params;
    this._shrikeClient = shrikeClient;

    // Get the underlying model
    this._model = this._shrikeClient.genAI.getGenerativeModel(params);
  }

  /**
   * Generate content with Shrike protection.
   */
  async generateContent(contents: GeminiContent): Promise<unknown> {
    // 1. Scan content BEFORE generating
    const scanResult = await this._shrikeClient._scanContent(contents);

    // 2. Block if unsafe
    if (!scanResult.safe) {
      throw new ShrikeBlockedError(
        scanResult.reason || 'Request blocked by Shrike',
        scanResult.threat_type,
        scanResult.confidence,
        scanResult.violations || []
      );
    }

    // 3. Proxy to Gemini
    return this._model.generateContent(contents);
  }

  /**
   * Stream content generation with Shrike protection.
   */
  async generateContentStream(contents: GeminiContent): Promise<unknown> {
    // 1. Scan content BEFORE streaming starts
    const scanResult = await this._shrikeClient._scanContent(contents);

    // 2. Block if unsafe
    if (!scanResult.safe) {
      throw new ShrikeBlockedError(
        scanResult.reason || 'Request blocked by Shrike',
        scanResult.threat_type,
        scanResult.confidence,
        scanResult.violations || []
      );
    }

    // 3. Proxy to Gemini
    return this._model.generateContentStream(contents);
  }

  /**
   * Start a chat session with Shrike protection.
   */
  startChat(options?: Record<string, unknown>): ShrikeChatSession {
    const chat = this._model.startChat(options);
    return new ShrikeChatSession(chat, this._shrikeClient);
  }

  get modelName(): string {
    return this._modelParams.model;
  }
}

/**
 * Wrapped chat session with Shrike protection.
 */
export class ShrikeChatSession {
  private _chat: GoogleChatSession;
  private _shrikeClient: ShrikeGemini;

  constructor(chat: GoogleChatSession, shrikeClient: ShrikeGemini) {
    this._chat = chat;
    this._shrikeClient = shrikeClient;
  }

  /**
   * Send a message with Shrike protection.
   */
  async sendMessage(content: GeminiContent): Promise<unknown> {
    // 1. Scan content
    const scanResult = await this._shrikeClient._scanContent(content);

    // 2. Block if unsafe
    if (!scanResult.safe) {
      throw new ShrikeBlockedError(
        scanResult.reason || 'Request blocked by Shrike',
        scanResult.threat_type,
        scanResult.confidence,
        scanResult.violations || []
      );
    }

    // 3. Proxy to Gemini
    return this._chat.sendMessage(content);
  }

  /**
   * Send a message with streaming and Shrike protection.
   */
  async sendMessageStream(content: GeminiContent): Promise<unknown> {
    // 1. Scan content
    const scanResult = await this._shrikeClient._scanContent(content);

    // 2. Block if unsafe
    if (!scanResult.safe) {
      throw new ShrikeBlockedError(
        scanResult.reason || 'Request blocked by Shrike',
        scanResult.threat_type,
        scanResult.confidence,
        scanResult.violations || []
      );
    }

    // 3. Proxy to Gemini
    return this._chat.sendMessageStream(content);
  }

  get history(): unknown[] {
    return this._chat.history || [];
  }
}
