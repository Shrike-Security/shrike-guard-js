/**
 * PII Pattern Sync — fetches canonical PII patterns from the Shrike backend
 * at startup and updates the client-side redactor so detection coverage
 * matches the backend's Presidio-derived set.
 *
 * On any failure (network, timeout, malformed response, unrecognized threat
 * type) sync keeps the hardcoded bootstrap patterns. Pattern sync is a
 * quality feature, NOT a security boundary — failing closed on it would
 * block legitimate scans.
 *
 * Mirrors mcp/src/utils/piiSync.ts to keep client-side coverage uniform
 * across MCP server and SDK consumers.
 */

import {
  getPIIPatternCount,
  updatePIIPatterns,
  type PIIPattern,
} from './piiRedactor';

interface BackendPIIEntry {
  pattern: string;
  threat_type: string;
  confidence: number;
  description: string;
  /**
   * Authoritative when present (backends as of July 2026 and later).
   * Older backends omit it; the sync falls back to a threat_type-derived
   * prefix so no pattern is ever silently dropped. See fallbackPrefixFor.
   */
  prefix?: string;
}

interface BackendPIIResponse {
  patterns: BackendPIIEntry[];
  total: number;
  version: string;
}

const DEFAULT_SYNC_TIMEOUT_MS = 5000;

/**
 * Derives a client-side redaction prefix from a threat_type when the backend
 * ships without one. Mirrors the backend's derivePIIPrefix() in
 * pii_handler.go and the MCP SDK's fallbackPrefixFor() — strip `pii_` and
 * uppercase. Never returns empty: unknown threat_types become their own
 * uppercase tag (e.g. `pii_wallet_eth` → `WALLET_ETH`).
 *
 * Retired PREFIX_MAP in favor of this + backend-shipped prefixes because the
 * hardcoded allowlist silently dropped any new pattern the backend added
 * (see 2026-07-01 U1 IP-redaction miss). Now no threat_type ever disappears
 * and adding a new backend pattern requires zero SDK changes.
 */
function fallbackPrefixFor(threatType: string): string {
  const stripped = threatType.startsWith('pii_') ? threatType.slice(4) : threatType;
  return stripped.toUpperCase() || 'PII';
}

function threatTypeToName(threatType: string): string {
  return threatType.startsWith('pii_') ? threatType.slice(4) : threatType;
}

function compileRegex(patternStr: string): RegExp | null {
  // Backend regexes are written for Go's RE2 syntax. JS RegExp is mostly
  // compatible; (?i) inline flags need to be stripped and converted to a
  // flag on the constructor.
  try {
    let body = patternStr;
    if (body.startsWith('(?i)')) {
      body = body.slice(4);
    }
    return new RegExp(body, 'gi');
  } catch {
    return null;
  }
}

export interface SyncPIIPatternsOptions {
  /** Backend base URL, e.g. https://api.shrikesecurity.com. */
  endpoint: string;
  /** Optional API key. Sent as `Authorization: Bearer <key>` when provided. */
  apiKey?: string;
  /** Network timeout in milliseconds. Defaults to 5000. */
  timeoutMs?: number;
}

/**
 * Fetches canonical PII patterns from the Shrike backend and applies them
 * to the client-side redactor. Never throws — returns false on any failure
 * and leaves the bootstrap patterns in place.
 *
 * @example
 * ```ts
 * await syncPIIPatterns({
 *   endpoint: 'https://api.shrikesecurity.com',
 *   apiKey: process.env.SHRIKE_API_KEY,
 * });
 * ```
 */
export async function syncPIIPatterns(
  options: SyncPIIPatternsOptions
): Promise<boolean> {
  const fallbackCount = getPIIPatternCount();
  const url = options.endpoint.replace(/\/+$/, '') + '/api/pii/patterns';
  const timeoutMs = options.timeoutMs ?? DEFAULT_SYNC_TIMEOUT_MS;

  const headers: Record<string, string> = {
    Accept: 'application/json',
  };
  if (options.apiKey) {
    headers['Authorization'] = `Bearer ${options.apiKey}`;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  let response: Response;
  try {
    response = await fetch(url, {
      method: 'GET',
      headers,
      signal: controller.signal,
    });
  } catch (err) {
    clearTimeout(timeoutId);
    console.warn(
      `[shrike-guard] PII pattern sync failed (${err instanceof Error ? err.message : 'unknown'}); keeping ${fallbackCount} fallback patterns`
    );
    return false;
  }
  clearTimeout(timeoutId);

  if (!response.ok) {
    console.warn(
      `[shrike-guard] PII pattern sync: backend returned ${response.status}; keeping ${fallbackCount} fallback patterns`
    );
    return false;
  }

  let data: BackendPIIResponse;
  try {
    data = (await response.json()) as BackendPIIResponse;
  } catch {
    console.warn(
      `[shrike-guard] PII pattern sync: malformed JSON; keeping ${fallbackCount} fallback patterns`
    );
    return false;
  }

  const rawPatterns = data.patterns ?? [];
  if (rawPatterns.length === 0) {
    console.warn(
      `[shrike-guard] PII pattern sync: backend returned 0 patterns; keeping ${fallbackCount} fallback patterns`
    );
    return false;
  }

  const converted: PIIPattern[] = [];
  const confidenceByName: Record<string, number> = {};
  let derivedFallbackCount = 0;

  for (const entry of rawPatterns) {
    if (!entry || typeof entry.threat_type !== 'string' || typeof entry.pattern !== 'string') {
      continue;
    }

    // Backend is the source of truth for the redaction tag. If it ships a
    // prefix, use it verbatim. If not (older backends), derive locally so
    // no pattern is ever silently dropped — that's the whole point of
    // retiring PREFIX_MAP.
    let prefix = entry.prefix;
    if (!prefix) {
      prefix = fallbackPrefixFor(entry.threat_type);
      derivedFallbackCount++;
    }

    const regex = compileRegex(entry.pattern);
    if (!regex) {
      console.warn(
        `[shrike-guard] PII pattern sync: skipping unparseable pattern for ${entry.threat_type}`
      );
      continue;
    }

    const name = threatTypeToName(entry.threat_type);
    const confidence = typeof entry.confidence === 'number' ? entry.confidence : 0;
    confidenceByName[name] = Math.max(confidenceByName[name] ?? 0, confidence);
    converted.push({ name, regex, prefix });
  }

  if (derivedFallbackCount > 0) {
    // Not an error — expected for older backends. Log so operators can see
    // if a backend upgrade would give them explicit prefixes.
    console.info(
      `[shrike-guard] PII pattern sync: ${derivedFallbackCount}/${rawPatterns.length} patterns used locally-derived prefix (backend older than 2026-07-02)`
    );
  }

  if (converted.length === 0) {
    console.warn(
      `[shrike-guard] PII pattern sync: all ${rawPatterns.length} backend patterns failed conversion; keeping ${fallbackCount} fallback`
    );
    return false;
  }

  converted.sort(
    (a, b) => (confidenceByName[b.name] ?? 0) - (confidenceByName[a.name] ?? 0)
  );

  updatePIIPatterns(converted);
  console.info(
    `[shrike-guard] PII pattern sync: applied ${converted.length} patterns from backend (was ${fallbackCount}), version=${data.version ?? 'unknown'}`
  );
  return true;
}
