/**
 * Integration tests for authentication flow.
 */

import { AuthClient } from '../../src/api/auth';
import { MockServer, createShrikeMockHandlers } from './mock-server';

describe('Authentication Flow Integration', () => {
  let server: MockServer;
  let authClient: AuthClient;

  beforeAll(async () => {
    server = new MockServer();
    createShrikeMockHandlers(server);
    await server.start();

    authClient = new AuthClient({
      baseUrl: server.url,
    });
  });

  afterAll(async () => {
    await server.stop();
  });

  beforeEach(() => {
    server.clearRequests();
  });

  describe('Registration', () => {
    it('should register a new user', async () => {
      const response = await authClient.register({
        email: 'newuser@example.com',
        password: 'securepassword123',
        company_name: 'New Company',
      });

      expect(response.access_token).toBeDefined();
      expect(response.refresh_token).toBeDefined();
      expect(response.token_type).toBe('Bearer');
      expect(response.expires_in).toBeGreaterThan(0);
    });
  });

  describe('Login', () => {
    it('should login with valid credentials', async () => {
      const response = await authClient.login({
        email: 'test@example.com',
        password: 'password123',
      });

      expect(response.access_token).toBe('mock-access-token');
      expect(response.refresh_token).toBe('mock-refresh-token');
    });

    it('should reject invalid credentials', async () => {
      await expect(
        authClient.login({
          email: 'wrong@example.com',
          password: 'wrongpassword',
        })
      ).rejects.toThrow();
    });
  });

  describe('Get User Profile', () => {
    it('should get the current user profile', async () => {
      const authenticatedClient = new AuthClient({
        baseUrl: server.url,
        apiKey: 'mock-access-token',
      });

      const profile = await authenticatedClient.me();

      expect(profile.customer_id).toBe('cust_123');
      expect(profile.email).toBe('test@example.com');
      expect(profile.company_name).toBe('Test Company');
    });
  });

  describe('Full Auth Flow', () => {
    it('should complete register -> login -> me flow', async () => {
      // 1. Register
      const registerResponse = await authClient.register({
        email: 'flowtest@example.com',
        password: 'testpassword123',
      });
      expect(registerResponse.access_token).toBeDefined();

      // 2. Login
      server.on('POST /api/v1/auth/login', () => ({
        status: 200,
        body: {
          access_token: 'flow-access-token',
          refresh_token: 'flow-refresh-token',
          token_type: 'Bearer',
          expires_in: 3600,
        },
      }));

      const loginResponse = await authClient.login({
        email: 'flowtest@example.com',
        password: 'testpassword123',
      });
      expect(loginResponse.access_token).toBe('flow-access-token');

      // 3. Get profile
      const authenticatedClient = new AuthClient({
        baseUrl: server.url,
        apiKey: loginResponse.access_token,
      });

      const profile = await authenticatedClient.me();
      expect(profile.email).toBeDefined();

      // Verify requests were made
      const requests = server.getRequests();
      expect(requests.some((r) => r.path === '/api/v1/auth/register')).toBe(true);
      expect(requests.some((r) => r.path === '/api/v1/auth/login')).toBe(true);
      expect(requests.some((r) => r.path === '/api/v1/auth/me')).toBe(true);
    });
  });
});
