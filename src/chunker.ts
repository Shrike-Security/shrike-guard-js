/**
 * Client-side chunking for large scan inputs.
 *
 * When a scan prompt exceeds AUTO_CHUNK_THRESHOLD, the SDK splits it on
 * natural boundaries (paragraph → line → hard cut), scans each chunk
 * sequentially, and aggregates the results. Sequential fail-fast: the loop
 * stops as soon as any chunk returns a `block` verdict.
 *
 * Why chunk client-side:
 *   1. Small chunks land in the backend cascade's "small content" band —
 *      early-exit triggers sooner, Vertex L7 costs drop.
 *   2. A 90KB monolithic L7 call is subject to "lost in the middle" —
 *      per-chunk calls give each region full attention.
 *   3. Bidirectional cost win: fewer tokens billed to the customer, fewer
 *      billed to us.
 *
 * Known limit (post-launch fix): each chunk carries the same session ID,
 * so L9 turn count inflates by chunk-count. Documented in
 * the adaptive scan-triage design; fix is a backend `chunk_group` field that
 * collapses N chunk-scans into one L9 turn.
 */

import type { ScanResult, ScanViolation, ScanAction } from './scanner';

/** Chunk anything larger than this. Below the threshold, keep single-shot. */
export const AUTO_CHUNK_THRESHOLD = 20 * 1024;

/** Target size per chunk. Sized to land in the backend cascade's small-content band. */
export const CHUNK_TARGET_SIZE = 8 * 1024;

/**
 * Split content on natural boundaries into chunks of ~CHUNK_TARGET_SIZE.
 * Preference order: double-newline paragraphs → single newlines → hard cut.
 * Never produces zero chunks — callers can rely on `chunks.length >= 1`.
 */
export function chunkContent(content: string, targetSize = CHUNK_TARGET_SIZE): string[] {
  if (content.length <= targetSize) {
    return [content];
  }

  const paragraphs = content.split(/\n{2,}/);
  const chunks: string[] = [];
  let current = '';

  const flush = () => {
    if (current.length > 0) {
      chunks.push(current);
      current = '';
    }
  };

  for (const paragraph of paragraphs) {
    if (paragraph.length > targetSize) {
      flush();
      chunks.push(...splitOversizedParagraph(paragraph, targetSize));
      continue;
    }
    if (current.length + paragraph.length + 2 > targetSize) {
      flush();
    }
    current = current.length > 0 ? `${current}\n\n${paragraph}` : paragraph;
  }
  flush();

  return chunks.length > 0 ? chunks : [content];
}

/**
 * A paragraph too big to fit in a chunk gets split on single newlines, then
 * on hard byte boundaries as a last resort. UTF-8-naive because JS strings
 * are UTF-16 code units — a chunk boundary in the middle of a surrogate
 * pair is theoretically possible on hard-cut fallback. That's rare (only
 * hits >8KB paragraphs with no line breaks) and the backend gracefully
 * handles malformed UTF-8 already.
 */
function splitOversizedParagraph(paragraph: string, targetSize: number): string[] {
  const lines = paragraph.split('\n');
  const out: string[] = [];
  let current = '';

  for (const line of lines) {
    if (line.length > targetSize) {
      if (current.length > 0) {
        out.push(current);
        current = '';
      }
      for (let i = 0; i < line.length; i += targetSize) {
        out.push(line.slice(i, i + targetSize));
      }
      continue;
    }
    if (current.length + line.length + 1 > targetSize) {
      out.push(current);
      current = '';
    }
    current = current.length > 0 ? `${current}\n${line}` : line;
  }
  if (current.length > 0) {
    out.push(current);
  }
  return out;
}

/** Action severity ordering used to pick the worst verdict across chunks. */
const ACTION_RANK: Record<ScanAction, number> = {
  allow: 0,
  warn: 1,
  require_approval: 2,
  block: 3,
};

/**
 * Aggregate per-chunk scan results into a single canonical response.
 *
 * Rules:
 *   - safe = all chunks safe
 *   - action / refuse_tier = worst action (block > require_approval > warn > allow)
 *   - threat_type + reason = from first non-safe chunk, tagged with chunk index
 *   - violations = concatenated + deduplicated by (threat_type, severity, action)
 *   - session_state / correlation_patterns = from the last chunk (freshest L9 state)
 *   - recovery = from first non-safe chunk
 *
 * Empty input array returns a safe verdict — caller should never pass it.
 */
export function aggregateChunkResults(results: ScanResult[]): ScanResult {
  if (results.length === 0) {
    return { safe: true, action: 'allow', refuse_tier: 'allow' };
  }
  if (results.length === 1) {
    return results[0];
  }

  let worstAction: ScanAction = 'allow';
  let firstUnsafeIdx = -1;
  let allSafe = true;
  const seenViolations = new Set<string>();
  const dedupedViolations: ScanViolation[] = [];

  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    if (!r.safe) {
      allSafe = false;
      if (firstUnsafeIdx === -1) firstUnsafeIdx = i;
    }
    const action = (r.action || r.refuse_tier || 'allow') as ScanAction;
    if (ACTION_RANK[action] > ACTION_RANK[worstAction]) {
      worstAction = action;
    }
    if (r.violations) {
      for (const v of r.violations) {
        const key = `${v.threat_type || ''}|${v.severity || ''}|${v.action || ''}`;
        if (!seenViolations.has(key)) {
          seenViolations.add(key);
          dedupedViolations.push(v);
        }
      }
    }
  }

  const first = firstUnsafeIdx >= 0 ? results[firstUnsafeIdx] : results[0];
  const last = results[results.length - 1];

  const aggregated: ScanResult = {
    safe: allSafe,
    action: worstAction,
    refuse_tier: worstAction,
    violations: dedupedViolations,
    session_state: last.session_state,
    correlation_patterns: last.correlation_patterns,
    session_risk_score: last.session_risk_score,
  };

  if (!allSafe) {
    aggregated.threat_type = first.threat_type;
    aggregated.severity = first.severity;
    aggregated.reason = first.reason
      ? `[chunk ${firstUnsafeIdx + 1} of ${results.length}] ${first.reason}`
      : `Unsafe content detected in chunk ${firstUnsafeIdx + 1} of ${results.length}`;
    aggregated.recovery = first.recovery;
    aggregated.approval_info = first.approval_info;
  }

  return aggregated;
}
