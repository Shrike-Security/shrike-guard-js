/**
 * Agent API client for Shrike.
 */

import { BaseClient, BaseClientOptions } from './base';

/**
 * Agent registration request.
 */
export interface RegisterAgentRequest {
  name: string;
  description?: string;
  policy_id?: string;
}

/**
 * Agent details.
 */
export interface Agent {
  agent_id: string;
  customer_id: string;
  name: string;
  description?: string;
  api_key: string;
  policy_id?: string;
  status: 'active' | 'inactive';
  created_at: string;
  last_heartbeat?: string;
}

/**
 * Heartbeat response.
 */
export interface HeartbeatResponse {
  status: string;
  server_time: string;
}

/**
 * Agent policy.
 */
export interface AgentPolicy {
  policy_id: string;
  name: string;
  rules: PolicyRule[];
}

/**
 * Policy rule.
 */
export interface PolicyRule {
  type: string;
  action: 'block' | 'warn' | 'allow';
  threshold?: number;
  [key: string]: unknown;
}

/**
 * Agent management client for Shrike API.
 */
export class AgentClient extends BaseClient {
  constructor(options: BaseClientOptions = {}) {
    super(options);
  }

  /**
   * Register a new agent.
   * Requires a customer API key.
   */
  async register(request: RegisterAgentRequest): Promise<Agent> {
    return this.request<Agent>('POST', '/api/v1/agents/register', request);
  }

  /**
   * Send a heartbeat from an agent.
   * Requires an agent API key.
   */
  async heartbeat(): Promise<HeartbeatResponse> {
    return this.request<HeartbeatResponse>('POST', '/api/v1/agents/heartbeat');
  }

  /**
   * Get the policies assigned to this agent.
   * Requires an agent API key.
   */
  async getPolicies(): Promise<AgentPolicy[]> {
    return this.request<AgentPolicy[]>('GET', '/api/v1/agents/policies');
  }

  /**
   * List all agents for the current customer.
   * Requires a customer API key.
   */
  async list(): Promise<Agent[]> {
    return this.request<Agent[]>('GET', '/api/v1/agents');
  }

  /**
   * Get an agent by ID.
   */
  async getAgent(agentId: string): Promise<Agent> {
    return this.request<Agent>('GET', `/api/v1/agents/${agentId}`);
  }

  /**
   * Delete an agent.
   */
  async deleteAgent(agentId: string): Promise<void> {
    await this.request<void>('DELETE', `/api/v1/agents/${agentId}`);
  }
}
