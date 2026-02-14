/**
 * Response sanitization for IP protection.
 *
 * Mirrors the MCP server's responseFormatter.ts to ensure SDK responses
 * do not expose internal detection methodology, layer details, or patterns.
 */

import type { ScanResult } from './scanner';

/**
 * Standard threat types exposed to SDK users (matches MCP ThreatType enum).
 */
const THREAT_TYPE_MAP: Record<string, string> = {
  // Prompt injection variants
  prompt_injection: 'prompt_injection',
  injection: 'prompt_injection',
  inject: 'prompt_injection',
  instruction_override: 'prompt_injection',
  role_hijacking: 'prompt_injection',
  context_manipulation: 'prompt_injection',
  token_manipulation: 'prompt_injection',
  indirect_injection: 'prompt_injection',
  context_poisoning: 'prompt_injection',
  function_injection: 'prompt_injection',
  memory_injection: 'prompt_injection',
  topic_mismatch: 'prompt_injection',
  // Jailbreak
  jailbreak: 'jailbreak',
  jailbreak_attempt: 'jailbreak',
  safety_bypass: 'jailbreak',
  roleplay: 'jailbreak',
  hypothetical: 'jailbreak',
  completion_baiting: 'jailbreak',
  override: 'jailbreak',
  manipulate: 'jailbreak',
  tonality_drift_profanity: 'jailbreak',
  tonality_drift_casual: 'jailbreak',
  tonality_drift_hostile: 'jailbreak',
  // System prompt leak
  system_prompt_leak: 'system_prompt_leak',
  system_prompt_extraction: 'system_prompt_leak',
  // Data exfiltration
  data_exfiltration: 'data_exfiltration',
  exfiltration: 'data_exfiltration',
  exfiltrate: 'data_exfiltration',
  extract: 'data_exfiltration',
  data_leak: 'data_exfiltration',
  information_disclosure: 'data_exfiltration',
  credential_extraction: 'data_exfiltration',
  // SQL injection
  sql_injection: 'sql_injection',
  sqli: 'sql_injection',
  tautology: 'sql_injection',
  tautology_or: 'sql_injection',
  tautology_and: 'sql_injection',
  union_injection: 'sql_injection',
  stacked_query: 'sql_injection',
  // Path traversal
  path_traversal: 'path_traversal',
  directory_traversal: 'path_traversal',
  path_violation: 'path_traversal',
  file_access: 'path_traversal',
  sensitive_path: 'path_traversal',
  sensitive_extension: 'path_traversal',
  blocked_extension: 'path_traversal',
  // Secrets
  secrets_exposure: 'secrets_exposure',
  secrets: 'secrets_exposure',
  api_key: 'secrets_exposure',
  credential: 'secrets_exposure',
  sensitive_file: 'secrets_exposure',
  content_violation: 'secrets_exposure',
  sensitive_content: 'secrets_exposure',
  secret_key: 'secrets_exposure',
  aws_key: 'secrets_exposure',
  private_key: 'secrets_exposure',
  // PII
  pii_exposure: 'pii_exposure',
  pii: 'pii_exposure',
  pii_leak: 'pii_exposure',
  personal_data: 'pii_exposure',
  pii_in_search: 'pii_exposure',
  pii_extraction: 'pii_exposure',
  ssn: 'pii_exposure',
  credit_card: 'pii_exposure',
  email_exposure: 'pii_exposure',
  phone_number: 'pii_exposure',
  unexpected_pii_leakage: 'pii_exposure',
  // Domain blocking
  blocked_domain: 'blocked_domain',
  suspicious_tld: 'blocked_domain',
  suspicious_domain: 'blocked_domain',
  malicious_url: 'blocked_domain',
  // Toxicity
  toxicity: 'toxicity',
  harmful_content: 'toxicity',
  // Malicious code
  malicious_content: 'malicious_code',
  malicious_code: 'malicious_code',
  reverse_shell: 'malicious_code',
  web_shell: 'malicious_code',
  fork_bomb: 'malicious_code',
  crypto_miner: 'malicious_code',
  persistence: 'malicious_code',
  shell_injection: 'malicious_code',
  // Harmful intent
  harmful_intent: 'harmful_intent',
  dangerous_request: 'harmful_intent',
  // Social engineering
  social_engineering: 'social_engineering',
  emotional: 'social_engineering',
  authority_claim: 'social_engineering',
  // Privilege escalation
  privilege_escalation: 'privilege_escalation',
  // Destructive operation
  destructive_operation: 'destructive_operation',
  // Errors
  scan_error: 'scan_error',
  size_limit_exceeded: 'size_limit_exceeded',
  size_limit: 'size_limit_exceeded',
  timeout: 'scan_error',
};

/**
 * User-friendly guidance (matches MCP THREAT_GUIDANCE).
 */
const THREAT_GUIDANCE: Record<string, string> = {
  prompt_injection:
    'This prompt contains patterns consistent with instruction override attempts.',
  jailbreak:
    'This prompt attempts to bypass safety guidelines. The request has been blocked.',
  system_prompt_leak:
    'The response contains system prompt disclosure. The response has been blocked.',
  data_exfiltration:
    'This prompt may attempt to extract sensitive information.',
  sql_injection: 'This query contains potentially dangerous SQL patterns.',
  path_traversal:
    'This file path attempts to access directories outside the allowed scope.',
  secrets_exposure:
    'This content contains patterns matching API keys, tokens, or credentials.',
  pii_exposure: 'This content contains personally identifiable information.',
  blocked_domain: 'This web search targets a restricted domain.',
  toxicity:
    'This content contains potentially harmful or inappropriate language.',
  malicious_code:
    'This content contains patterns associated with malicious code.',
  harmful_intent:
    'This request contains content associated with harmful intent.',
  social_engineering:
    'This prompt contains social engineering patterns.',
  privilege_escalation:
    'This query attempts to escalate privileges or gain unauthorized access.',
  destructive_operation:
    'This query contains destructive operations. Review carefully.',
  scan_error:
    'The security scan could not be completed. Blocked as precaution.',
  size_limit_exceeded: 'The content exceeds the maximum allowed size.',
  unknown: 'A security concern was detected. Please review the content.',
};

/**
 * Default severity per normalized threat type (matches MCP severity semantics).
 * critical > high > medium > low
 */
const THREAT_SEVERITY: Record<string, string> = {
  prompt_injection: 'high',
  jailbreak: 'high',
  system_prompt_leak: 'high',
  data_exfiltration: 'high',
  sql_injection: 'critical',
  path_traversal: 'high',
  secrets_exposure: 'critical',
  pii_exposure: 'high',
  blocked_domain: 'medium',
  toxicity: 'medium',
  malicious_code: 'critical',
  harmful_intent: 'high',
  social_engineering: 'medium',
  privilege_escalation: 'critical',
  destructive_operation: 'critical',
  scan_error: 'medium',
  size_limit_exceeded: 'low',
  unknown: 'medium',
};

/**
 * Fields that expose internal detection methodology - must be stripped.
 */
const INTERNAL_FIELDS = new Set([
  'detected_by',
  'policy_id',
  'policy_name',
  'matched_pattern',
  'matched_text',
  'pattern',
  'scan_stage',
  'ai_reasoning',
  'llm_analysis',
  'performance_metrics',
  'performance',
]);

/**
 * Normalize internal threat type to standard enum.
 */
export function normalizeThreatType(rawType?: string): string {
  if (!rawType) {
    return 'unknown';
  }
  const normalized = rawType.toLowerCase().replace(/-/g, '_');
  return THREAT_TYPE_MAP[normalized] || 'unknown';
}

/**
 * Derive severity from threat type or pass through raw severity.
 *
 * If the backend provides a severity, validate and use it.
 * Otherwise, derive from the normalized threat type.
 */
export function deriveSeverity(
  threatType: string,
  rawSeverity?: string
): string {
  const validSeverities = new Set(['critical', 'high', 'medium', 'low']);
  if (rawSeverity && validSeverities.has(rawSeverity.toLowerCase())) {
    return rawSeverity.toLowerCase();
  }
  return THREAT_SEVERITY[threatType] || 'medium';
}

/**
 * Convert raw confidence score to bucketed level.
 *
 * Protects IP by not exposing exact detection thresholds.
 */
export function bucketConfidence(score?: number): string {
  if (score === undefined || score === null) {
    return 'medium';
  }
  if (score >= 0.9) {
    return 'high';
  }
  if (score >= 0.7) {
    return 'medium';
  }
  return 'low';
}

/**
 * Sanitize a raw backend scan response for IP protection.
 *
 * Strips internal detection details, normalizes threat types,
 * and buckets confidence scores.
 */
export function sanitizeScanResponse(raw: ScanResult): ScanResult {
  const safe = raw.safe !== false;

  if (safe) {
    return {
      safe: true,
      reason: raw.reason || '',
    };
  }

  // Unsafe: normalize and sanitize
  const threatType = normalizeThreatType(raw.threat_type);
  const confidence = bucketConfidence(
    typeof raw.confidence === 'number' ? raw.confidence : undefined
  );
  const severity = deriveSeverity(
    threatType,
    typeof raw.severity === 'string' ? raw.severity : undefined
  );
  const guidance =
    THREAT_GUIDANCE[threatType] || THREAT_GUIDANCE['unknown'];

  return {
    safe: false,
    threat_type: threatType,
    severity: severity,
    confidence: confidence,
    reason: raw.reason || guidance,
    guidance: guidance,
  };
}

export { THREAT_TYPE_MAP, THREAT_GUIDANCE, THREAT_SEVERITY, INTERNAL_FIELDS };
