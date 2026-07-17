/**
 * Contract FORWARD-COMPATIBILITY suite.
 *
 * This is the stability guardrail for the published client. It pins one
 * promise: an ADDITIVE change on the backend scanner (a new response field,
 * a new threat-type string, a new refuse tier) must NOT
 *   (a) crash a shipped client,
 *   (b) fail OPEN (silently treat a blocked verdict as safe), or
 *   (c) require an emergency republish to stay correct.
 *
 * It is the complement of contract-symmetry.test.ts:
 *   - contract-symmetry pins the PRESERVATION direction (governance fields the
 *     scanner sends survive sanitization).
 *   - this file pins the RESILIENCE direction (things the scanner sends that
 *     the client does NOT yet recognize are handled safely).
 *
 * If any test here fails, a scanner change is one release away from breaking
 * every installed copy of this SDK. Treat a failure as publish-blocking.
 *
 * The identical contract holds for the Python SDK (`_is_blocked`,
 * `sanitize_scan_response`) and the MCP server — this suite is the template
 * to port to those two.
 */

import { isBlocked, ScanClient, type ScanResult } from '../../src/scanner';
import {
  sanitizeScanResponse,
  normalizeThreatType,
  deriveSeverity,
  bucketConfidence,
} from '../../src/sanitizer';

const mockFetch = jest.fn();
global.fetch = mockFetch;

// A verdict cast used only to feed the sanitizer shapes the compiler would
// otherwise reject — these represent bytes the backend could put on the wire.
const wire = (raw: Record<string, unknown>): ScanResult =>
  raw as unknown as ScanResult;

describe('forward-compat: additive scanner changes must not crash the client', () => {
  it('ignores an unrecognized top-level field instead of throwing', () => {
    const raw = wire({
      safe: false,
      action: 'block',
      threat_type: 'jailbreak',
      // A field a FUTURE backend adds that this SDK version has never seen.
      cognitive_load_index: { score: 0.91, band: 'elevated' },
    });
    expect(() => sanitizeScanResponse(raw)).not.toThrow();
    const out = sanitizeScanResponse(raw);
    // The core verdict is intact — the unknown field simply doesn't derail it.
    expect(out.safe).toBe(false);
    expect(out.action).toBe('block');
    expect(out.threat_type).toBe('jailbreak');
  });

  it('passes an unrecognized per-violation field through (allowlist-by-exclusion)', () => {
    const raw = wire({
      safe: false,
      action: 'block',
      violations: [
        {
          threat_type: 'sql_injection',
          severity: 'critical',
          // New attribute a future backend attaches to violations.
          remediation_playbook_id: 'pb-42',
        },
      ],
    });
    const out = sanitizeScanResponse(raw);
    expect(out.violations).toHaveLength(1);
    // New violation fields survive (unlike top-level, which is allowlisted).
    expect((out.violations![0] as Record<string, unknown>).remediation_playbook_id).toBe(
      'pb-42'
    );
    // ...but internal attribution on the violation is still stripped.
    const polluted = wire({
      safe: false,
      violations: [
        { threat_type: 'sql_injection', matched_pattern: 'LEAK', ai_reasoning: 'LEAK' },
      ],
    });
    const cleaned = sanitizeScanResponse(polluted).violations![0] as Record<string, unknown>;
    expect(cleaned).not.toHaveProperty('matched_pattern');
    expect(cleaned).not.toHaveProperty('ai_reasoning');
  });

  it('maps an UNKNOWN threat-type string to "unknown" rather than throwing', () => {
    // The scanner ships a brand-new granular threat type this SDK has never
    // seen. It must degrade to the generic bucket, never crash.
    expect(normalizeThreatType('quantum_prompt_smuggling_v3')).toBe('unknown');
    const out = sanitizeScanResponse(
      wire({ safe: false, action: 'block', threat_type: 'quantum_prompt_smuggling_v3' })
    );
    expect(out.threat_type).toBe('unknown');
    expect(out.guidance).toBeTruthy(); // falls back to the 'unknown' guidance copy
  });

  it('falls back on an UNKNOWN severity string instead of surfacing junk', () => {
    // deriveSeverity only trusts the known enum; anything else derives from the
    // threat type. A future backend severity label cannot leak to the caller.
    expect(deriveSeverity('sql_injection', 'catastrophic')).toBe('critical');
    expect(deriveSeverity('unknown', 'catastrophic')).toBe('medium');
  });

  it('tolerates confidence sent as an unexpected type', () => {
    expect(() => bucketConfidence(undefined)).not.toThrow();
    expect(bucketConfidence(undefined)).toBe('medium');
    // A raw string confidence (wrong type) must not throw through the sanitizer.
    const out = sanitizeScanResponse(
      wire({ safe: false, action: 'block', confidence: 'very-high' as unknown as number })
    );
    expect(out.confidence).toBe('medium');
  });
});

describe('forward-compat: omitted fields degrade safely (backward-compat)', () => {
  it('blocks when `action` is absent but the verdict is unsafe (fail-safe)', () => {
    // An older/simpler backend, or the /enforce path, may omit action and put
    // detail in violations. isBlocked must fall back to `safe`.
    expect(isBlocked(wire({ safe: false }))).toBe(true);
    expect(isBlocked(wire({ safe: true }))).toBe(false);
  });

  it('does not require recovery/session_state to be present', () => {
    const out = sanitizeScanResponse(wire({ safe: true, action: 'allow' }));
    expect(out.safe).toBe(true);
    expect(out).not.toHaveProperty('recovery');
    expect(out).not.toHaveProperty('session_state');
  });
});

describe('forward-compat: malformed shapes must not crash the caller', () => {
  it('drops a non-array `violations` without throwing', () => {
    expect(() =>
      sanitizeScanResponse(wire({ safe: false, violations: { not: 'an array' } as unknown as [] }))
    ).not.toThrow();
  });

  it('filters null / non-object entries inside `violations`', () => {
    const out = sanitizeScanResponse(
      wire({
        safe: false,
        violations: [null, 'a string', { threat_type: 'jailbreak' }] as unknown as [],
      })
    );
    // Only the one valid entry survives; junk is filtered, nothing throws.
    expect(out.violations).toHaveLength(1);
    expect((out.violations![0] as Record<string, unknown>).threat_type).toBe('jailbreak');
  });

  it('does not throw on an empty object body', () => {
    expect(() => sanitizeScanResponse(wire({}))).not.toThrow();
  });
});

describe('forward-compat: refuse-tier enum evolution must fail CLOSED', () => {
  // Pin the KNOWN tiers so a rename on either side breaks CI loudly.
  it('pins known non-blocking tiers as proceed', () => {
    expect(isBlocked(wire({ safe: true, action: 'allow' }))).toBe(false);
    expect(isBlocked(wire({ safe: true, action: 'warn' }))).toBe(false);
  });

  it('pins known blocking tiers as refuse', () => {
    expect(isBlocked(wire({ safe: false, action: 'block' }))).toBe(true);
    expect(isBlocked(wire({ safe: false, action: 'require_approval' }))).toBe(true);
  });

  it('treats an UNKNOWN blocking tier as refuse when the verdict is unsafe', () => {
    // THE CRUX: the scanner introduces a new blocking tier (e.g. "quarantine",
    // "block_and_lock") that this SDK version has never heard of. The verdict
    // still carries safe:false. A shipped client MUST NOT proceed just because
    // it doesn't recognize the tier name — that would be a fail-OPEN and force
    // an emergency republish. Unknown action ⇒ defer to `safe` ⇒ fail closed.
    expect(isBlocked(wire({ safe: false, action: 'quarantine' }))).toBe(true);
    expect(isBlocked(wire({ safe: false, action: 'block_and_lock' }))).toBe(true);
  });

  it('an unknown tier with a safe verdict still proceeds', () => {
    // Symmetric check: a future non-blocking tier the SDK doesn't know, on a
    // safe verdict, must not spuriously start blocking traffic.
    expect(isBlocked(wire({ safe: true, action: 'observe_only' }))).toBe(false);
  });
});

describe('forward-compat: end-to-end through scan() with a future-shaped body', () => {
  beforeEach(() => mockFetch.mockClear());

  it('parses a response carrying unknown fields + a new tier without throwing', async () => {
    mockFetch.mockResolvedValueOnce({
      ok: true,
      json: () =>
        Promise.resolve({
          safe: false,
          action: 'quarantine', // new tier
          threat_type: 'novel_attack_class', // new threat string
          future_governance_signal: { escalate: true }, // new field
          recovery: { guidance: 'stand by' },
        }),
    });
    const client = new ScanClient({ apiKey: 'test-key' });
    const result = await client.scan('some prompt');
    // The full prod path (fetch → sanitize → return) survives the future shape.
    expect(result.safe).toBe(false);
    expect(isBlocked(result)).toBe(true); // fail-closed on the unknown tier
    expect(result.threat_type).toBe('unknown'); // unknown string bucketed
  });
});
