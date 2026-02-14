/**
 * Mock server utilities for integration testing.
 */

import { createServer, IncomingMessage, ServerResponse, Server } from 'http';

/**
 * Mock API response configuration.
 */
export interface MockResponse {
  status?: number;
  body?: unknown;
  delay?: number;
}

/**
 * Request handler type.
 */
export type RequestHandler = (
  req: IncomingMessage,
  body: string
) => MockResponse | Promise<MockResponse>;

/**
 * Create a mock HTTP server for testing.
 */
export class MockServer {
  private server: Server | null = null;
  private handlers: Map<string, RequestHandler> = new Map();
  private requests: { method: string; path: string; body: string }[] = [];
  private _port = 0;

  /**
   * Start the mock server.
   */
  async start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer(async (req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', (chunk) => chunks.push(chunk));
        req.on('end', async () => {
          const body = Buffer.concat(chunks).toString();
          const path = req.url || '/';
          const method = req.method || 'GET';

          this.requests.push({ method, path, body });

          const key = `${method} ${path}`;
          const handler = this.handlers.get(key) || this.handlers.get(path);

          if (handler) {
            const response = await handler(req, body);
            this.sendResponse(res, response);
          } else {
            this.sendResponse(res, { status: 404, body: { error: 'Not found' } });
          }
        });
      });

      this.server.listen(0, () => {
        const address = this.server!.address();
        if (typeof address === 'object' && address) {
          this._port = address.port;
        }
        resolve();
      });
    });
  }

  /**
   * Stop the mock server.
   */
  async stop(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.server) {
        this.server.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      } else {
        resolve();
      }
    });
  }

  /**
   * Get the server port.
   */
  get port(): number {
    return this._port;
  }

  /**
   * Get the server URL.
   */
  get url(): string {
    return `http://localhost:${this._port}`;
  }

  /**
   * Register a handler for a path.
   */
  on(pathOrKey: string, handler: RequestHandler): void {
    this.handlers.set(pathOrKey, handler);
  }

  /**
   * Get all received requests.
   */
  getRequests(): { method: string; path: string; body: string }[] {
    return [...this.requests];
  }

  /**
   * Clear received requests.
   */
  clearRequests(): void {
    this.requests = [];
  }

  private sendResponse(res: ServerResponse, response: MockResponse): void {
    const status = response.status || 200;
    const body = response.body;
    const delay = response.delay || 0;

    setTimeout(() => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(body));
    }, delay);
  }
}

/**
 * Create common mock handlers for Shrike API.
 */
export function createShrikeMockHandlers(server: MockServer): void {
  // Scan endpoint - safe by default
  server.on('POST /scan', (_req, body) => {
    const { prompt } = JSON.parse(body);

    // Simple mock logic for testing
    if (prompt.toLowerCase().includes('ignore previous')) {
      return {
        status: 200,
        body: {
          safe: false,
          threat_type: 'prompt_injection',
          confidence: 0.95,
          reason: 'Prompt injection detected',
        },
      };
    }

    if (prompt.includes('SSN') || prompt.match(/\d{3}-\d{2}-\d{4}/)) {
      return {
        status: 200,
        body: {
          safe: false,
          threat_type: 'pii',
          confidence: 0.99,
          reason: 'PII detected',
        },
      };
    }

    return {
      status: 200,
      body: { safe: true },
    };
  });

  // Auth endpoints
  server.on('POST /api/v1/auth/login', (_req, body) => {
    const { email, password } = JSON.parse(body);
    if (email === 'test@example.com' && password === 'password123') {
      return {
        status: 200,
        body: {
          access_token: 'mock-access-token',
          refresh_token: 'mock-refresh-token',
          token_type: 'Bearer',
          expires_in: 3600,
        },
      };
    }
    return { status: 401, body: { error: 'Invalid credentials' } };
  });

  server.on('POST /api/v1/auth/register', () => {
    return {
      status: 201,
      body: {
        access_token: 'mock-access-token',
        refresh_token: 'mock-refresh-token',
        token_type: 'Bearer',
        expires_in: 3600,
      },
    };
  });

  server.on('GET /api/v1/auth/me', () => ({
    status: 200,
    body: {
      customer_id: 'cust_123',
      email: 'test@example.com',
      company_name: 'Test Company',
      created_at: new Date().toISOString(),
    },
  }));

  // Specialized scan endpoints
  server.on('POST /api/scan/specialized', (_req, body) => {
    const { content, content_type } = JSON.parse(body);

    if (content_type === 'sql') {
      if (content.includes("'1'='1'") || content.includes('DROP TABLE')) {
        return {
          status: 200,
          body: {
            safe: false,
            threat_type: 'sql_injection',
            reason: 'SQL injection detected',
          },
        };
      }
    }

    if (content_type === 'file_path' || content_type === 'file_content') {
      if (content.includes('..') || content.includes('/etc/passwd')) {
        return {
          status: 200,
          body: {
            safe: false,
            threat_type: 'path_traversal',
            reason: 'Path traversal detected',
          },
        };
      }
    }

    return { status: 200, body: { safe: true } };
  });
}
