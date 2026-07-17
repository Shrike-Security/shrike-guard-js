/**
 * ShrikeGemini - Drop-in replacement for Google Gemini client with security scanning.
 */

import {
  FailMode,
  DEFAULT_ENDPOINT,
  DEFAULT_FAIL_MODE,
  DEFAULT_SCAN_TIMEOUT,
  getSessionId,
  getAgentId,
} from '../config';
import { ShrikeBlockedError, ShrikeScanError } from '../errors';
import { sanitizeScanResponse } from '../sanitizer';
import { getScanHeaders, isBlocked, maybeAddSignupHint, ScanResult, failOpenResult } from '../scanner';

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
 * Minimal typings for the current @google/genai (v2+) client surface.
 * Declared locally so we don't require @google/genai at compile time. The v2
 * SDK is params-object based (`ai.models.generateContent({ model, contents })`)
 * and replaced the legacy `@google/generative-ai` `getGenerativeModel()` shape.
 */
interface GoogleModels {
  generateContent(params: { model: string; contents: unknown; [key: string]: unknown }): Promise<unknown>;
  generateContentStream(params: { model: string; contents: unknown; [key: string]: unknown }): Promise<unknown>;
}

interface GoogleChat {
  sendMessage(params: { message: unknown; [key: string]: unknown }): Promise<unknown>;
  sendMessageStream(params: { message: unknown; [key: string]: unknown }): Promise<unknown>;
  getHistory?(): unknown[];
}

interface GoogleChats {
  create(params: { model: string; [key: string]: unknown }): GoogleChat;
}

/**
 * Minimal interface for the underlying `@google/genai` GoogleGenAI client.
 */
interface GoogleGenAIClient {
  models: GoogleModels;
  chats: GoogleChats;
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

    // Note: All scanning is done via backend API (tier-based: community=L1-L4, pro=L1-L8)
    // No local scanning - backend has full regex patterns (~50+) and normalizers

    if (!this._shrikeApiKey) {
      console.warn('[shrike-guard] No shrikeApiKey provided — running in free tier (regex-only).');
      console.warn('[shrike-guard] For full scanning (LLM analysis, session correlation): npx shrike-mcp --signup');
    }

    // Dynamically import @google/genai (v2+). The current SDK exports
    // `GoogleGenAI` and takes an options object — the legacy `GoogleGenerativeAI`
    // class from `@google/generative-ai` is deprecated and NOT used here.
    try {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { GoogleGenAI } = require('@google/genai');
      this._genAI = new GoogleGenAI({ apiKey: this._apiKey }) as GoogleGenAIClient;
    } catch (err) {
      throw new Error(
        `@google/genai is not installed or failed to initialize. Install it with: npm install @google/genai${
          err instanceof Error ? ` (${err.message})` : ''
        }`
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
   * - Community tier (no API key): L1-L4 (regex, unicode, encoding, token normalization)
   * - Pro tier: L1-L8 (full scan including LLM)
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
      const response = await fetch(`${this._shrikeEndpoint}/api/scan/enforce`, {
        method: 'POST',
        headers: getScanHeaders(this._shrikeApiKey),
        body: JSON.stringify({
          prompt,
          context: {
            session_id: getSessionId(),
            agent_id: getAgentId(),
            source_application: 'shrike-guard-ts',
          },
        }),
        signal: controller.signal,
      });

      if (!response.ok) {
        if (this._failMode === FailMode.OPEN) {
          return failOpenResult(`Scan API error: ${response.status}`);
        }
        throw new ShrikeScanError(`Scan API returned error: ${response.status}`);
      }

      return maybeAddSignupHint(sanitizeScanResponse((await response.json()) as ScanResult), this._shrikeApiKey);
    } catch (error) {
      if (error instanceof ShrikeScanError) {
        throw error;
      }

      const errorMessage = error instanceof Error ? error.message : String(error);

      if (errorMessage.includes('abort')) {
        if (this._failMode === FailMode.OPEN) {
          // No local fallback - just fail open
          logWarning('Scan request timed out, failing open (allowing request)');
          return failOpenResult('Scan timeout, failing open');
        }
        throw new ShrikeScanError("Scan request timed out and fail_mode is 'closed'");
      }

      if (this._failMode === FailMode.OPEN) {
        return failOpenResult(`Scan error: ${errorMessage}`);
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
  private _models: GoogleModels;

  constructor(
    params: { model: string; [key: string]: unknown },
    shrikeClient: ShrikeGemini
  ) {
    this._modelParams = params;
    this._shrikeClient = shrikeClient;

    // v2 SDK is stateless per call: hold the models module and pass the model
    // name on each request rather than materializing a per-model object.
    this._models = this._shrikeClient.genAI.models;
  }

  /**
   * Generate content with Shrike protection.
   */
  async generateContent(contents: GeminiContent): Promise<unknown> {
    // 1. Scan content BEFORE generating
    const scanResult = await this._shrikeClient._scanContent(contents);

    // 2. Block if unsafe
    if (isBlocked(scanResult)) {
      throw new ShrikeBlockedError(
        scanResult.reason || 'Request blocked by Shrike',
        scanResult.threat_type,
        scanResult.confidence,
        scanResult.violations || []
      );
    }

    // 3. Proxy to Gemini
    return this._models.generateContent({ model: this._modelParams.model, contents });
  }

  /**
   * Stream content generation with Shrike protection.
   */
  async generateContentStream(contents: GeminiContent): Promise<unknown> {
    // 1. Scan content BEFORE streaming starts
    const scanResult = await this._shrikeClient._scanContent(contents);

    // 2. Block if unsafe
    if (isBlocked(scanResult)) {
      throw new ShrikeBlockedError(
        scanResult.reason || 'Request blocked by Shrike',
        scanResult.threat_type,
        scanResult.confidence,
        scanResult.violations || []
      );
    }

    // 3. Proxy to Gemini
    return this._models.generateContentStream({ model: this._modelParams.model, contents });
  }

  /**
   * Start a chat session with Shrike protection.
   */
  startChat(options?: Record<string, unknown>): ShrikeChatSession {
    const chat = this._shrikeClient.genAI.chats.create({
      model: this._modelParams.model,
      ...(options || {}),
    });
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
  private _chat: GoogleChat;
  private _shrikeClient: ShrikeGemini;

  constructor(chat: GoogleChat, shrikeClient: ShrikeGemini) {
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
    if (isBlocked(scanResult)) {
      throw new ShrikeBlockedError(
        scanResult.reason || 'Request blocked by Shrike',
        scanResult.threat_type,
        scanResult.confidence,
        scanResult.violations || []
      );
    }

    // 3. Proxy to Gemini
    return this._chat.sendMessage({ message: content });
  }

  /**
   * Send a message with streaming and Shrike protection.
   */
  async sendMessageStream(content: GeminiContent): Promise<unknown> {
    // 1. Scan content
    const scanResult = await this._shrikeClient._scanContent(content);

    // 2. Block if unsafe
    if (isBlocked(scanResult)) {
      throw new ShrikeBlockedError(
        scanResult.reason || 'Request blocked by Shrike',
        scanResult.threat_type,
        scanResult.confidence,
        scanResult.violations || []
      );
    }

    // 3. Proxy to Gemini
    return this._chat.sendMessageStream({ message: content });
  }

  get history(): unknown[] {
    // v2 SDK exposes history via getHistory(); fall back to [] if absent.
    return typeof this._chat.getHistory === 'function' ? this._chat.getHistory() : [];
  }
}
