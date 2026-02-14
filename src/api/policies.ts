/**
 * Policy API client for Shrike.
 */

import { BaseClient, BaseClientOptions } from './base';

/**
 * Policy rule definition.
 */
export interface PolicyRule {
  type: 'prompt_injection' | 'pii_detection' | 'jailbreak' | 'sql_injection' | 'custom';
  action: 'block' | 'warn' | 'allow';
  threshold?: number;
  patterns?: string[];
  [key: string]: unknown;
}

/**
 * Policy definition.
 */
export interface Policy {
  policy_id: string;
  customer_id: string;
  name: string;
  description?: string;
  rules: PolicyRule[];
  is_default: boolean;
  created_at: string;
  updated_at: string;
}

/**
 * Create policy request.
 */
export interface CreatePolicyRequest {
  name: string;
  description?: string;
  rules: PolicyRule[];
  is_default?: boolean;
}

/**
 * Update policy request.
 */
export interface UpdatePolicyRequest {
  name?: string;
  description?: string;
  rules?: PolicyRule[];
  is_default?: boolean;
}

/**
 * Policy management client for Shrike API.
 */
export class PolicyClient extends BaseClient {
  constructor(options: BaseClientOptions = {}) {
    super(options);
  }

  /**
   * List all policies for the current customer.
   */
  async list(): Promise<Policy[]> {
    return this.request<Policy[]>('GET', '/api/v1/policies');
  }

  /**
   * Get a policy by ID.
   */
  async getPolicy(policyId: string): Promise<Policy> {
    return this.request<Policy>('GET', `/api/v1/policies/${policyId}`);
  }

  /**
   * Create a new policy.
   */
  async create(request: CreatePolicyRequest): Promise<Policy> {
    return this.request<Policy>('POST', '/api/v1/policies', request);
  }

  /**
   * Update an existing policy.
   */
  async update(policyId: string, request: UpdatePolicyRequest): Promise<Policy> {
    return this.request<Policy>('PUT', `/api/v1/policies/${policyId}`, request);
  }

  /**
   * Delete a policy.
   */
  async deletePolicy(policyId: string): Promise<void> {
    await this.request<void>('DELETE', `/api/v1/policies/${policyId}`);
  }
}
