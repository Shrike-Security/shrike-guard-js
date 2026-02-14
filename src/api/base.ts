/**
 * Base API client for Shrike backend.
 */

import { DEFAULT_ENDPOINT } from '../config';
import { getScanHeaders } from '../scanner';

/**
 * Base options for API clients.
 */
export interface BaseClientOptions {
  /** API key for authentication */
  apiKey?: string;
  /** Base URL for the API */
  baseUrl?: string;
  /** Request timeout in milliseconds */
  timeout?: number;
}

/**
 * Base API client with common HTTP functionality.
 */
export class BaseClient {
  protected readonly apiKey: string;
  protected readonly baseUrl: string;
  protected readonly timeout: number;

  constructor(options: BaseClientOptions = {}) {
    this.apiKey = options.apiKey || '';
    this.baseUrl = (options.baseUrl || DEFAULT_ENDPOINT).replace(/\/$/, '');
    this.timeout = options.timeout || 30000;
  }

  /**
   * Make an HTTP request to the API.
   */
  protected async request<T>(
    method: string,
    path: string,
    body?: unknown
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: getScanHeaders(this.apiKey),
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      if (!response.ok) {
        const errorBody = await response.json().catch(() => ({ message: response.statusText })) as { message?: string };
        throw new Error(errorBody.message || `API error: ${response.status}`);
      }

      return response.json() as Promise<T>;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  protected get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path);
  }

  protected post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  protected put<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>('PUT', path, body);
  }

  protected delete<T>(path: string): Promise<T> {
    return this.request<T>('DELETE', path);
  }
}
