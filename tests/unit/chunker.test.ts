/**
 * Tests for src/chunker.ts — the client-side auto-chunk path for large scan
 * inputs. Mirrors platform/sdks/python/tests/test_chunker.py.
 */

import {
  AUTO_CHUNK_THRESHOLD,
  CHUNK_TARGET_SIZE,
  aggregateChunkResults,
  chunkContent,
} from '../../src/chunker';
import type { ScanResult } from '../../src/scanner';

describe('chunkContent', () => {
  it('returns single chunk when content fits target size', () => {
    const chunks = chunkContent('short content');
    expect(chunks).toEqual(['short content']);
  });

  it('never returns zero chunks for non-empty input', () => {
    expect(chunkContent('x').length).toBe(1);
  });

  it('never returns zero chunks even when input is empty', () => {
    expect(chunkContent('').length).toBe(1);
  });

  it('splits on paragraph boundaries when possible', () => {
    const p = 'a'.repeat(4000);
    const chunks = chunkContent(`${p}\n\n${p}\n\n${p}`, 5000);
    expect(chunks.length).toBe(3);
    for (const c of chunks) {
      expect(c.length).toBeLessThanOrEqual(5000);
    }
  });

  it('splits oversized paragraph on line boundaries', () => {
    const line = 'a'.repeat(1000);
    const bigParagraph = Array(10).fill(line).join('\n');
    const chunks = chunkContent(bigParagraph, 3500);
    expect(chunks.length).toBeGreaterThan(1);
    for (const c of chunks) {
      expect(c.length).toBeLessThanOrEqual(3500);
    }
  });

  it('hard-cuts a single oversized line as last resort', () => {
    const singleLine = 'a'.repeat(20_000);
    const chunks = chunkContent(singleLine, 5000);
    expect(chunks.length).toBeGreaterThan(1);
    for (const c of chunks) {
      expect(c.length).toBeLessThanOrEqual(5000);
    }
    // Every byte of the original is preserved somewhere
    expect(chunks.join('').length).toBe(20_000);
  });

  it('AUTO_CHUNK_THRESHOLD is 20KB', () => {
    expect(AUTO_CHUNK_THRESHOLD).toBe(20 * 1024);
  });

  it('CHUNK_TARGET_SIZE is 8KB (in cascade small-content band)', () => {
    expect(CHUNK_TARGET_SIZE).toBe(8 * 1024);
  });
});

describe('aggregateChunkResults', () => {
  it('returns safe verdict for empty results', () => {
    const agg = aggregateChunkResults([]);
    expect(agg.safe).toBe(true);
    expect(agg.action).toBe('allow');
  });

  it('returns single result verbatim when only one chunk', () => {
    const input: ScanResult = { safe: false, threat_type: 'x' };
    expect(aggregateChunkResults([input])).toBe(input);
  });

  it('aggregates all safe → overall safe', () => {
    const results: ScanResult[] = [
      { safe: true, action: 'allow' },
      { safe: true, action: 'allow' },
      { safe: true, action: 'allow' },
    ];
    const agg = aggregateChunkResults(results);
    expect(agg.safe).toBe(true);
    expect(agg.action).toBe('allow');
    expect(agg.refuse_tier).toBe('allow');
  });

  it('picks worst action across chunks', () => {
    const results: ScanResult[] = [
      { safe: true, action: 'allow' },
      { safe: true, action: 'warn' },
      { safe: false, action: 'block' },
    ];
    const agg = aggregateChunkResults(results);
    expect(agg.safe).toBe(false);
    expect(agg.action).toBe('block');
    expect(agg.refuse_tier).toBe('block');
  });

  it('tags reason with chunk index when unsafe', () => {
    const results: ScanResult[] = [
      { safe: true, action: 'allow' },
      { safe: false, action: 'block', reason: 'prompt injection detected' },
      { safe: true, action: 'allow' },
    ];
    const agg = aggregateChunkResults(results);
    expect(agg.reason).toContain('chunk 2 of 3');
    expect(agg.reason).toContain('prompt injection detected');
  });

  it('deduplicates violations by (threat_type, severity, action)', () => {
    const results: ScanResult[] = [
      {
        safe: false,
        action: 'block',
        violations: [{ threat_type: 'prompt_injection', severity: 'high', action: 'block' }],
      },
      {
        safe: false,
        action: 'block',
        violations: [
          { threat_type: 'prompt_injection', severity: 'high', action: 'block' }, // dupe
          { threat_type: 'pii_exposure', severity: 'medium', action: 'redact' },
        ],
      },
    ];
    const agg = aggregateChunkResults(results);
    expect(agg.violations?.length).toBe(2);
  });

  it('preserves recovery from first unsafe chunk', () => {
    const results: ScanResult[] = [
      { safe: true, action: 'allow' },
      { safe: false, action: 'block', recovery: { instruction: 'stop and start new session' } },
      { safe: false, action: 'block', recovery: { instruction: 'different, not this one' } },
    ];
    const agg = aggregateChunkResults(results);
    expect(agg.recovery?.instruction).toBe('stop and start new session');
  });

  it('takes session_state from the last chunk (freshest L9 state)', () => {
    const results: ScanResult[] = [
      { safe: true, action: 'allow', session_state: { session_risk_score: 0.1 } },
      { safe: true, action: 'allow', session_state: { session_risk_score: 0.5 } },
    ];
    const agg = aggregateChunkResults(results);
    expect(agg.session_state?.session_risk_score).toBe(0.5);
  });

  it('warn overrides allow but does not exceed require_approval', () => {
    const results: ScanResult[] = [
      { safe: true, action: 'allow' },
      { safe: true, action: 'warn' },
      { safe: false, action: 'require_approval' },
    ];
    const agg = aggregateChunkResults(results);
    expect(agg.action).toBe('require_approval');
  });
});
