/**
 * Authentication API client for Shrike.
 */

import { BaseClient, BaseClientOptions } from './base';

/**
 * Registration request payload.
 */
export interface RegisterRequest {
  email: string;
  password: string;
  company_name?: string;
}

/**
 * Login request payload.
 */
export interface LoginRequest {
  email: string;
  password: string;
}

/**
 * Authentication response with tokens.
 */
export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

/**
 * User profile response.
 */
export interface UserProfile {
  customer_id: string;
  email: string;
  company_name?: string;
  created_at: string;
}

/**
 * Authentication client for Shrike API.
 */
export class AuthClient extends BaseClient {
  constructor(options: BaseClientOptions = {}) {
    super(options);
  }

  /**
   * Register a new customer account.
   */
  async register(request: RegisterRequest): Promise<AuthResponse> {
    return this.request<AuthResponse>('POST', '/api/v1/auth/register', request);
  }

  /**
   * Login with email and password.
   */
  async login(request: LoginRequest): Promise<AuthResponse> {
    return this.request<AuthResponse>('POST', '/api/v1/auth/login', request);
  }

  /**
   * Refresh the access token using a refresh token.
   */
  async refresh(refreshToken: string): Promise<AuthResponse> {
    return this.request<AuthResponse>('POST', '/api/v1/auth/refresh', {
      refresh_token: refreshToken,
    });
  }

  /**
   * Logout and invalidate the current session.
   */
  async logout(): Promise<void> {
    await this.request<void>('POST', '/api/v1/auth/logout');
  }

  /**
   * Get the current user's profile.
   */
  async me(): Promise<UserProfile> {
    return this.request<UserProfile>('GET', '/api/v1/auth/me');
  }
}
