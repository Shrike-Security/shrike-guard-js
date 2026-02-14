/**
 * HTTP client for the Shrike scan API.
 */

import { DEFAULT_ENDPOINT, DEFAULT_SCAN_TIMEOUT, SDK_NAME } from './config';
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
export interface ScanResult {
  safe: boolean;
  reason?: string;
  threat_type?: string;
  severity?: string;
  confidence?: number | string;
  violations?: unknown[];
  guidance?: string;
  [key: string]: unknown;
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
 *
 * @param shrikeApiKey - The Shrike API key for authentication.
 * @param requestId - Optional request ID for tracing. If not provided, a new UUID will be generated.
 * @returns Dictionary of HTTP headers to include in the request.
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

/**
 * Synchronous HTTP client for the Shrike scan API.
 */
export class ScanClient {
  private readonly apiKey: string;
  private readonly endpoint: string;
  private readonly timeout: number;

  constructor(options: ScanClientOptions) {
    this.apiKey = options.apiKey;
    this.endpoint = (options.endpoint || DEFAULT_ENDPOINT).replace(/\/$/, '');
    this.timeout = options.timeout || DEFAULT_SCAN_TIMEOUT;
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
    // Phase 8b: Client-side size validation to fail fast
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

    const payload: Record<string, string> = { prompt };
    if (context) {
      payload.context = context;
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.endpoint}/scan`, {
        method: 'POST',
        headers: getScanHeaders(this.apiKey),
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Scan API returned error: ${response.status}`);
      }

      return sanitizeScanResponse((await response.json()) as ScanResult);
    } finally {
      clearTimeout(timeoutId);
    }
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
    // Phase 8b: Client-side size validation
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

    const payload = {
      content: query,
      content_type: 'sql',
      context: {
        database: database || '',
        allow_destructive: String(allowDestructive),
      },
    };

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.endpoint}/api/scan/specialized`, {
        method: 'POST',
        headers: getScanHeaders(this.apiKey),
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`SQL scan API returned error: ${response.status}`);
      }

      return sanitizeScanResponse((await response.json()) as ScanResult);
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Scan a file path for security risks.
   *
   * @param path - The file path to validate.
   * @param content - Optional file content to scan for secrets/PII.
   * @returns Scan result with 'safe' boolean and additional details.
   */
  async scanFile(path: string, content?: string): Promise<ScanResult> {
    // Phase 8b: Client-side size validation
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

    const contentType = content ? 'file_content' : 'file_path';
    const payload: Record<string, unknown> = {
      content: path,
      content_type: contentType,
    };
    if (content) {
      payload.context = { file_content: content };
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.endpoint}/api/scan/specialized`, {
        method: 'POST',
        headers: getScanHeaders(this.apiKey),
        body: JSON.stringify(payload),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`File scan API returned error: ${response.status}`);
      }

      return sanitizeScanResponse((await response.json()) as ScanResult);
    } finally {
      clearTimeout(timeoutId);
    }
  }
}
