/**
 * Unit tests for Shrike Guard scanner.
 */

import { getScanHeaders, ScanClient } from '../../src/scanner';
import { VERSION } from '../../src/version';
import { SDK_NAME, DEFAULT_ENDPOINT } from '../../src/config';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

describe('getScanHeaders', () => {
  it('should generate correct headers with API key', () => {
    const headers = getScanHeaders('test-api-key');

    expect(headers['Authorization']).toBe('Bearer test-api-key');
    expect(headers['Content-Type']).toBe('application/json');
    expect(headers['X-Shrike-SDK']).toBe(SDK_NAME);
    expect(headers['X-Shrike-SDK-Version']).toBe(VERSION);
    expect(headers['X-Shrike-Request-ID']).toBeDefined();
  });

  it('should use provided request ID', () => {
    const headers = getScanHeaders('test-key', 'custom-request-id');
    expect(headers['X-Shrike-Request-ID']).toBe('custom-request-id');
  });

  it('should generate UUID when no request ID provided', () => {
    const headers1 = getScanHeaders('test-key');
    const headers2 = getScanHeaders('test-key');

    // UUIDs should be different
    expect(headers1['X-Shrike-Request-ID']).not.toBe(headers2['X-Shrike-Request-ID']);

    // Should be valid UUID format
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    expect(headers1['X-Shrike-Request-ID']).toMatch(uuidRegex);
  });
});

describe('ScanClient', () => {
  beforeEach(() => {
    mockFetch.mockClear();
  });

  it('should initialize with default options', () => {
    const client = new ScanClient({ apiKey: 'test-key' });
    expect(client).toBeDefined();
  });

  it('should initialize with custom options', () => {
    const client = new ScanClient({
      apiKey: 'test-key',
      endpoint: 'https://custom.endpoint.com/',
      timeout: 5000,
    });
    expect(client).toBeDefined();
  });

  describe('scan', () => {
    it('should scan a prompt successfully', async () => {
      const mockResponse = { safe: true, reason: 'No threats detected' };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const client = new ScanClient({ apiKey: 'test-key' });
      const result = await client.scan('Hello, world!');

      expect(result).toEqual(mockResponse);
      expect(mockFetch).toHaveBeenCalledWith(
        `${DEFAULT_ENDPOINT}/scan`,
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ prompt: 'Hello, world!' }),
        })
      );
    });

    it('should include context when provided', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ safe: true }),
      });

      const client = new ScanClient({ apiKey: 'test-key' });
      await client.scan('Test prompt', 'Test context');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: JSON.stringify({ prompt: 'Test prompt', context: 'Test context' }),
        })
      );
    });

    it('should handle API errors', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 401,
      });

      const client = new ScanClient({ apiKey: 'test-key' });
      await expect(client.scan('Test')).rejects.toThrow('Scan API returned error: 401');
    });
  });

  describe('scanSql', () => {
    it('should scan SQL queries', async () => {
      const mockResponse = { safe: true };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const client = new ScanClient({ apiKey: 'test-key' });
      const result = await client.scanSql('SELECT * FROM users');

      expect(result).toEqual({ safe: true, reason: '' });
      expect(mockFetch).toHaveBeenCalledWith(
        `${DEFAULT_ENDPOINT}/api/scan/specialized`,
        expect.objectContaining({
          method: 'POST',
          body: expect.stringContaining('"content_type":"sql"'),
        })
      );
    });

    it('should include database context', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ safe: true }),
      });

      const client = new ScanClient({ apiKey: 'test-key' });
      await client.scanSql('SELECT * FROM users', 'production_db');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: expect.stringContaining('"database":"production_db"'),
        })
      );
    });
  });

  describe('scanFile', () => {
    it('should scan file paths', async () => {
      const mockResponse = { safe: true };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const client = new ScanClient({ apiKey: 'test-key' });
      const result = await client.scanFile('/etc/passwd');

      expect(result).toEqual({ safe: true, reason: '' });
      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: expect.stringContaining('"content_type":"file_path"'),
        })
      );
    });

    it('should scan file content when provided', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ safe: true }),
      });

      const client = new ScanClient({ apiKey: 'test-key' });
      await client.scanFile('/tmp/config.json', '{"api_key": "secret"}');

      expect(mockFetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          body: expect.stringContaining('"content_type":"file_content"'),
        })
      );
    });
  });
});
