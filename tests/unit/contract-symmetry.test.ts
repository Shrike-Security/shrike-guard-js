/**
 * Cross-language contract-symmetry parity test.
 *
 * Loads the shared fixture at platform/testdata/contract-symmetry/ and
 * asserts that the TypeScript SDK's sanitizeScanResponse preserves every
 * governance field declared as invariant. The identical fixture is
 * consumed by the Python SDK and MCP responseFormatter test suites — if
 * any of the three drifts, that language's CI job fails.
 *
 * See platform/testdata/contract-symmetry/README.md for the design rationale
 * and platform/CLAUDE.md § Contract symmetry for the shipped principle.
 */

import { readFileSync } from 'fs';
import { join } from 'path';

import { sanitizeScanResponse } from '../../src/sanitizer';
import type { ScanResult } from '../../src/scanner';

// ---------------------------------------------------------------------------
// Fixture loading — reach up from platform/sdks/typescript/tests/unit/ to platform/
// ---------------------------------------------------------------------------

const FIXTURE_DIR = join(__dirname, '..', '..', '..', '..', 'testdata', 'contract-symmetry');

function loadFixture<T>(name: string): T {
  return JSON.parse(readFileSync(join(FIXTURE_DIR, name), 'utf-8')) as T;
}

interface CanonicalFixture {
  responses: Record<string, { raw: Record<string, any> }>;
}

interface BranchInvariants {
  must_preserve_top_level: string[];
  session_state_must_preserve: string[];
  recovery_must_preserve: string[];
  violation_must_preserve?: string[];
  violation_must_strip?: string[];
  top_level_must_strip: string[];
}

interface Invariants {
  unsafe_branch: BranchInvariants;
  safe_branch: BranchInvariants;
}

const CANONICAL = loadFixture<CanonicalFixture>('canonical-backend-responses.json');
const INVARIANTS = loadFixture<Invariants>('governance-invariants.json');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function branchFor(raw: Record<string, any>): BranchInvariants {
  const safe = raw.safe !== false;
  return safe ? INVARIANTS.safe_branch : INVARIANTS.unsafe_branch;
}

function eachCase(): Array<[string, Record<string, any>]> {
  return Object.entries(CANONICAL.responses).map(([name, entry]) => [name, entry.raw]);
}

// ---------------------------------------------------------------------------
// Top-level governance fields survive when present on raw
// ---------------------------------------------------------------------------

describe('contract-symmetry parity (TypeScript SDK)', () => {
  it('fixture covers >= 6 canonical cases', () => {
    expect(Object.keys(CANONICAL.responses).length).toBeGreaterThanOrEqual(6);
  });

  it('preserves top-level governance fields when present on raw', () => {
    for (const [_caseName, raw] of eachCase()) {
      const sanitized = sanitizeScanResponse(raw as ScanResult);
      const branch = branchFor(raw);
      for (const field of branch.must_preserve_top_level) {
        const rawValue = raw[field];
        if (rawValue === undefined || rawValue === null) continue;
        expect(sanitized).toHaveProperty(field);
        expect((sanitized as Record<string, unknown>)[field]).toEqual(rawValue);
      }
    }
  });

  it('preserves session_state fields verbatim', () => {
    for (const [_caseName, raw] of eachCase()) {
      const rawSs = raw.session_state;
      if (!rawSs) continue;
      const sanitized = sanitizeScanResponse(raw as ScanResult);
      const ss = (sanitized as Record<string, any>).session_state;
      expect(ss).toBeDefined();
      const branch = branchFor(raw);
      for (const field of branch.session_state_must_preserve) {
        if (!(field in rawSs)) continue;
        expect(ss[field]).toEqual(rawSs[field]);
      }
    }
  });

  it('preserves recovery fields verbatim', () => {
    for (const [_caseName, raw] of eachCase()) {
      const rawRec = raw.recovery;
      if (!rawRec) continue;
      const sanitized = sanitizeScanResponse(raw as ScanResult);
      const rec = (sanitized as Record<string, any>).recovery;
      expect(rec).toBeDefined();
      const branch = branchFor(raw);
      for (const field of branch.recovery_must_preserve) {
        if (!(field in rawRec)) continue;
        expect(rec[field]).toEqual(rawRec[field]);
      }
    }
  });

  it('preserves violations[] with per-item attribution stripped', () => {
    for (const [_caseName, raw] of eachCase()) {
      const rawV: any[] = raw.violations ?? [];
      if (rawV.length === 0) continue;
      const sanitized = sanitizeScanResponse(raw as ScanResult);
      const sv = sanitized.violations;
      expect(sv).toBeDefined();
      expect(Array.isArray(sv)).toBe(true);
      expect(sv!.length).toBe(rawV.length);
      const branch = INVARIANTS.unsafe_branch;
      rawV.forEach((rawItem, i) => {
        const sItem = (sv as any[])[i];
        for (const field of branch.violation_must_preserve ?? []) {
          if (!(field in rawItem)) continue;
          expect(sItem[field]).toEqual(rawItem[field]);
        }
        for (const field of branch.violation_must_strip ?? []) {
          expect(sItem).not.toHaveProperty(field);
        }
      });
    }
  });

  it('strips internal attribution fields from top-level output', () => {
    for (const [_caseName, raw] of eachCase()) {
      const polluted: Record<string, any> = {
        ...raw,
        detected_by: 'L1_regex',
        matched_pattern: 'leaked_pattern_id',
        matched_text: 'leaked text',
        ai_reasoning: 'leaked l7 rationale',
        llm_analysis: { model: 'gemini-2.5-flash' },
        performance_metrics: { total_ms: 42 },
        scan_stage: 'l7_semantic',
      };
      const sanitized = sanitizeScanResponse(polluted as unknown as ScanResult);
      const branch = branchFor(polluted);
      for (const field of branch.top_level_must_strip) {
        expect(sanitized).not.toHaveProperty(field);
      }
    }
  });

  it('preserves the `action` field so isBlocked() stays action-authoritative', () => {
    for (const [_caseName, raw] of eachCase()) {
      const rawAction = raw.action;
      if (rawAction === undefined) continue;
      const sanitized = sanitizeScanResponse(raw as ScanResult);
      expect(sanitized.action).toBe(rawAction);
    }
  });
});
