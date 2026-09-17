/**
 * Shared fixtures for the governance core and the framework conformance
 * suite: canned verdicts, a scripted guard, and a refused-scope error.
 */

import type { Guard } from '../../src/govern';
import type { ScanResult } from '../../src/scanner';

export const ALLOW = { safe: true, refuse_tier: 'allow', violations: [] } as unknown as ScanResult;
export const WARN = { safe: true, refuse_tier: 'warn', violations: [{ threat_type: 'suspicious_path', user_message: 'unusual path' }] } as unknown as ScanResult;
export const BLOCK = { safe: false, refuse_tier: 'block', violations: [{ threat_type: 'data_exfiltration', user_message: 'exfil pattern' }] } as unknown as ScanResult;
export const HOLD = {
  safe: false,
  refuse_tier: 'require_approval',
  approval_info: { threat_type: 'scope_violation', severity: 'high', action_summary: 'command outside scope' },
  recovery: { intent: { declared_purpose: 'reconcile invoices', attempted: 'command', objected_on: 'authorization', objection: 'scope_violation' } },
} as unknown as ScanResult;

export class FakeGuard implements Guard {
  calls: unknown[][] = [];
  declared: Record<string, unknown>[] = [];
  declareRejects?: Error;
  constructor(public verdict: ScanResult = ALLOW, public rejectWith?: Error) {}
  private answer(...call: unknown[]): Promise<ScanResult> {
    this.calls.push(call);
    if (this.rejectWith) return Promise.reject(this.rejectWith);
    return Promise.resolve(this.verdict);
  }
  planes: (string | undefined)[] = [];
  scan(prompt: string, _context?: string, options?: { plane?: string }) {
    this.planes.push(options?.plane);
    return this.answer('prompt', prompt);
  }
  authorizeTool(toolName: string) { return this.answer('authorize', toolName); }
  scanCommand(command: string, cwd?: string) { return this.answer('command', command, cwd); }
  scanFile(path: string, content?: string) { return this.answer(content ? 'file_content' : 'file_path', path, content); }
  scanSql(query: string) { return this.answer('sql', query); }
  scanWebSearch(query: string) { return this.answer('web_search', query); }
  scanRagContext(chunks: string | string[]) { return this.answer('rag_context', chunks); }
  scanA2AMessage(message: string) { return this.answer('a2a_message', message); }
  scanAgentCard(card: string) { return this.answer('agent_card', card); }
  async declareScope(options: { agentId: string; allowedTools?: string[]; purpose?: string }) {
    if (this.declareRejects) throw this.declareRejects;
    const row = { agent_id: options.agentId, allowed_tools: options.allowedTools, purpose: options.purpose };
    this.declared.push(row);
    return row;
  }
}

export function refused(reason = 'widening'): Error {
  return new Error(`declareScope failed: 403 — {"reason":"${reason}"}`);
}
