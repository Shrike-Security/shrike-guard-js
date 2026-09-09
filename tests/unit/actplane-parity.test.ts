/**
 * Every act-plane channel the backend scans must be reachable from the SDK.
 *
 * This test exists because it would have failed for a year. The backend has
 * scanned eight specialized content types since the act plane shipped; this SDK
 * exposed four of them. `scanCommand` — the highest-volume surface, the one an
 * agent hits before every shell-out, and the exact integration point we pitch —
 * had no method at all. The only way to reach it was to hand-roll an HTTP call
 * or route through the MCP server.
 *
 * Nothing caught that, because "the backend supports it" and "a customer can
 * call it" were two facts with nothing comparing them. This is the comparison.
 *
 * The canonical list is models.SpecializedContentTypes() in the Go backend
 * (common/models/policy.go). It is duplicated here on purpose: the SDK ships to
 * npm without the backend source, so it cannot import the list, and a silent
 * divergence is exactly what this guards. When the backend adds a channel, this
 * list and a method move together — which is the point.
 */

import { ScanClient } from '../../src/scanner';
import * as publicApi from '../../src/index';

/** Mirrors models.SpecializedContentTypes() — keep in sync deliberately. */
const SPECIALIZED_CONTENT_TYPES = [
  'sql',
  'file_path',
  'file_content',
  'web_search',
  'command',
  'a2a_message',
  'agent_card',
  'rag_context',
] as const;

/**
 * How each channel is reached. file_path and file_content share one method
 * (scanFile decides by whether content was supplied), which is why this is a
 * mapping rather than a name transformation.
 */
const CHANNEL_METHODS: Record<(typeof SPECIALIZED_CONTENT_TYPES)[number], string> = {
  sql: 'scanSql',
  file_path: 'scanFile',
  file_content: 'scanFile',
  web_search: 'scanWebSearch',
  command: 'scanCommand',
  a2a_message: 'scanA2AMessage',
  agent_card: 'scanAgentCard',
  rag_context: 'scanRagContext',
};

describe('act-plane parity', () => {
  const guard = new ScanClient({ apiKey: 'test-key' });

  it('declares a method for every specialized content type', () => {
    const missing = SPECIALIZED_CONTENT_TYPES.filter((ct) => !CHANNEL_METHODS[ct]);
    expect(missing).toEqual([]);
  });

  it.each(SPECIALIZED_CONTENT_TYPES)('exposes a callable method for %s', (contentType) => {
    const method = CHANNEL_METHODS[contentType];
    expect(
      typeof (guard as unknown as Record<string, unknown>)[method]
    ).toBe('function');
  });

  it('exports the provenance helper from the package entry point', () => {
    // Defined in scanner.ts is not the same as reachable as
    // `import { attributableToOperator } from 'shrike-guard'`. This shipped
    // unexported once — the same shape as content_origin being computed by the
    // backend and dropped by the sanitizer allow-list. A symbol nobody can
    // import is a symbol nobody has.
    expect(typeof publicApi.attributableToOperator).toBe('function');
    expect(publicApi.attributableToOperator('human_prompt')).toBe(true);
    expect(publicApi.attributableToOperator('agent_action')).toBe(false);
    expect(publicApi.attributableToOperator(undefined)).toBe(false);
  });

  it('can screen an MCP tool definition', () => {
    // Not a specialized content type — its own endpoint and detector — but an
    // act-plane surface. Tool poisoning needs no execution, so a caller that
    // cannot screen a tools/list response has no defence against it at all.
    expect(
      typeof (guard as unknown as Record<string, unknown>).scanMcpSchema
    ).toBe('function');
  });
});
