/**
 * Tests for src/systemPrompt.ts.
 *
 * Mirrors platform/sdks/python/tests/test_system_prompt.py. Locks the
 * ~180-word 'Working with Shrike' block content and shape so silent
 * drift doesn't ship. When the block is intentionally updated, both
 * suites, both SDK constants, the docs page, and the Cookbook UI must
 * change in the same PR.
 */

import { SYSTEM_PROMPT_VERSION, systemPrompt } from '../../src/systemPrompt';

// Whitespace-normalize the block so intentional hard-wrapping (kept
// for system-prompt friendliness) doesn't break substring matches.
const normalized = () => systemPrompt().split(/\s+/).join(' ');

describe('systemPrompt', () => {
  it('returns a non-empty string', () => {
    expect(typeof systemPrompt()).toBe('string');
    expect(systemPrompt().length).toBeGreaterThan(0);
  });

  it('starts with the governed-environment intro', () => {
    expect(systemPrompt().startsWith('You are operating in a Shrike-governed environment.')).toBe(true);
  });

  it('names all four refuse_tier verdict states', () => {
    const result = systemPrompt();
    expect(result).toContain('allow');
    expect(result).toContain('warn');
    expect(result).toContain('block');
    expect(result).toContain('require_approval');
  });

  it('names all three block-feedback prefixes', () => {
    const n = normalized();
    expect(n).toContain('"Shrike blocked your last tool call."');
    expect(n).toContain('"Shrike flagged your last tool call (advisory)."');
    expect(n).toContain('"Shrike is holding your last tool call for approval."');
  });

  it('teaches both halves of the rotation-recommendation contract', () => {
    const result = systemPrompt();
    expect(result).toContain('rotation_recommended');
    expect(result).toContain('suggested_new_session_id');
    expect(result).toContain('per event');
  });

  it('teaches no-verbatim-retry — the single most-common failure mode', () => {
    expect(systemPrompt()).toContain('do not retry the same action verbatim');
  });

  it('teaches that patterns are session-scoped (correlator signals)', () => {
    const n = normalized();
    expect(n).toContain('Patterns triggered');
    expect(n).toContain('correlator signals across your recent turns');
  });

  it('uses collaborator framing, deliberately omits the word "safety"', () => {
    const result = systemPrompt();
    expect(result).toContain('collaborator');
    expect(result.toLowerCase()).not.toContain('safety');
  });

  it('length is within target ~180-word range', () => {
    const wordCount = systemPrompt().split(/\s+/).filter((w) => w.length > 0).length;
    expect(wordCount).toBeGreaterThanOrEqual(150);
    expect(wordCount).toBeLessThanOrEqual(220);
  });

  it('is stable across calls (no randomization)', () => {
    expect(systemPrompt()).toBe(systemPrompt());
  });

  it('exports a semver-shaped version string', () => {
    expect(typeof SYSTEM_PROMPT_VERSION).toBe('string');
    const parts = SYSTEM_PROMPT_VERSION.split('.');
    expect([2, 3]).toContain(parts.length);
    parts.forEach((p) => expect(p).toMatch(/^\d+$/));
  });
});
