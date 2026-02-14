/**
 * Sandbox API client for Shrike.
 */

import { BaseClient, BaseClientOptions } from './base';
import { ScanResult } from '../scanner';

/**
 * Sandbox scan request.
 */
export interface SandboxScanRequest {
  prompt: string;
  context?: string;
  model?: string;
}

/**
 * Sandbox client for testing prompts without affecting production metrics.
 */
export class SandboxClient extends BaseClient {
  constructor(options: BaseClientOptions = {}) {
    super(options);
  }

  /**
   * Scan a prompt in sandbox mode.
   * This does not count against production quotas.
   */
  async scan(request: SandboxScanRequest): Promise<ScanResult> {
    return this.request<ScanResult>('POST', '/api/v1/sandbox/scan', request);
  }
}
