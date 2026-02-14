/**
 * API clients for Shrike backend.
 */

export { BaseClient } from './base';
export type { BaseClientOptions } from './base';

export { AuthClient } from './auth';
export type { RegisterRequest, LoginRequest, AuthResponse, UserProfile } from './auth';

export { AgentClient } from './agents';
export type { RegisterAgentRequest, Agent, HeartbeatResponse, AgentPolicy } from './agents';

export { PolicyClient } from './policies';
export type { Policy, PolicyRule, CreatePolicyRequest, UpdatePolicyRequest } from './policies';

export { SandboxClient } from './sandbox';
export type { SandboxScanRequest } from './sandbox';
