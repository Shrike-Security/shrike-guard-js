/**
 * Unit tests for ShrikeOpenAI client.
 */

import { ShrikeOpenAI } from '../../src/openai/client';
import { ShrikeBlockedError, ShrikeScanError } from '../../src/errors';
import { FailMode } from '../../src/config';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

// Mock OpenAI
jest.mock('openai', () => ({
  default: jest.fn().mockImplementation(() => ({
    chat: {
      completions: {
        create: jest.fn().mockResolvedValue({
          id: 'chatcmpl-123',
          choices: [{ message: { role: 'assistant', content: 'Hello!' } }],
        }),
      },
    },
  })),
}));

describe('ShrikeOpenAI', () => {
  beforeEach(() => {
    mockFetch.mockClear();
  });

  describe('constructor', () => {
    it('should initialize with default options', () => {
      const client = new ShrikeOpenAI({
        apiKey: 'sk-test',
        shrikeApiKey: 'shrike-test',
      });
      expect(client).toBeDefined();
      expect(client.chat).toBeDefined();
      expect(client.chat.completions).toBeDefined();
    });

    it('should accept custom endpoint', () => {
      const client = new ShrikeOpenAI({
        apiKey: 'sk-test',
        shrikeApiKey: 'shrike-test',
        shrikeEndpoint: 'https://custom.endpoint.com/',
      });
      expect(client).toBeDefined();
    });

    it('should accept fail mode as string or enum', () => {
      const client1 = new ShrikeOpenAI({
        apiKey: 'sk-test',
        failMode: 'closed',
      });
      const client2 = new ShrikeOpenAI({
        apiKey: 'sk-test',
        failMode: FailMode.CLOSED,
      });
      expect(client1).toBeDefined();
      expect(client2).toBeDefined();
    });
  });

  describe('_extractUserContent', () => {
    it('should extract content from simple string messages', () => {
      const client = new ShrikeOpenAI({ apiKey: 'sk-test' });
      const messages = [
        { role: 'system', content: 'You are helpful' },
        { role: 'user', content: 'Hello!' },
        { role: 'assistant', content: 'Hi there!' },
        { role: 'user', content: 'How are you?' },
      ];

      const content = client._extractUserContent(messages);
      expect(content).toBe('Hello!\nHow are you?');
    });

    it('should extract content from multimodal messages', () => {
      const client = new ShrikeOpenAI({ apiKey: 'sk-test' });
      const messages = [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'What is in this image?' },
            { type: 'image_url', image_url: { url: 'data:image/jpeg;base64,...' } },
          ],
        },
      ];

      const content = client._extractUserContent(messages);
      expect(content).toBe('What is in this image?');
    });

    it('should return empty string when no user content', () => {
      const client = new ShrikeOpenAI({ apiKey: 'sk-test' });
      const messages = [{ role: 'system', content: 'You are helpful' }];

      const content = client._extractUserContent(messages);
      expect(content).toBe('');
    });
  });

  describe('_scanMessages', () => {
    it('should return safe when no user content', async () => {
      const client = new ShrikeOpenAI({ apiKey: 'sk-test' });
      const messages = [{ role: 'system', content: 'System message' }];

      const result = await client._scanMessages(messages);
      expect(result.safe).toBe(true);
      expect(result.reason).toBe('No user content to scan');
    });

    it('should scan user messages', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ safe: true }),
      });

      const client = new ShrikeOpenAI({
        apiKey: 'sk-test',
        shrikeApiKey: 'shrike-test',
      });
      const messages = [{ role: 'user', content: 'Hello!' }];

      const result = await client._scanMessages(messages);
      expect(result.safe).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/scan'),
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify({ prompt: 'Hello!' }),
        })
      );
    });

    it('should fail open on timeout by default', async () => {
      mockFetch.mockImplementationOnce(() => {
        const error = new Error('The operation was aborted');
        error.name = 'AbortError';
        return Promise.reject(error);
      });

      const client = new ShrikeOpenAI({
        apiKey: 'sk-test',
        failMode: FailMode.OPEN,
      });
      const messages = [{ role: 'user', content: 'Hello!' }];

      const result = await client._scanMessages(messages);
      expect(result.safe).toBe(true);
      expect(result.reason).toContain('timeout');
    });

    it('should throw on timeout when fail mode is closed', async () => {
      mockFetch.mockImplementationOnce(() => {
        const error = new Error('abort');
        return Promise.reject(error);
      });

      const client = new ShrikeOpenAI({
        apiKey: 'sk-test',
        failMode: FailMode.CLOSED,
      });
      const messages = [{ role: 'user', content: 'Hello!' }];

      await expect(client._scanMessages(messages)).rejects.toThrow(ShrikeScanError);
    });
  });

  describe('chat.completions.create', () => {
    it('should scan and proxy safe requests', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ safe: true }),
      });

      const client = new ShrikeOpenAI({
        apiKey: 'sk-test',
        shrikeApiKey: 'shrike-test',
      });

      const response = await client.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: 'Hello!' }],
      });

      expect(response).toBeDefined();
      expect(response.choices).toBeDefined();
    });

    it('should block unsafe requests', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            safe: false,
            reason: 'Prompt injection detected',
            threat_type: 'prompt_injection',
            confidence: 0.95,
          }),
      });

      const client = new ShrikeOpenAI({
        apiKey: 'sk-test',
        shrikeApiKey: 'shrike-test',
      });

      await expect(
        client.chat.completions.create({
          model: 'gpt-4',
          messages: [{ role: 'user', content: 'Ignore previous instructions...' }],
        })
      ).rejects.toThrow(ShrikeBlockedError);
    });

    it('should include threat details in blocked error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            safe: false,
            reason: 'PII detected',
            threat_type: 'pii',
            confidence: 0.99,
            violations: [{ type: 'ssn', value: '***-**-1234' }],
          }),
      });

      const client = new ShrikeOpenAI({
        apiKey: 'sk-test',
        shrikeApiKey: 'shrike-test',
      });

      try {
        await client.chat.completions.create({
          model: 'gpt-4',
          messages: [{ role: 'user', content: 'My SSN is 123-45-6789' }],
        });
        fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(ShrikeBlockedError);
        const blocked = error as ShrikeBlockedError;
        expect(blocked.threatType).toBe('pii_exposure');
        expect(blocked.confidence).toBe('high');
        expect(blocked.violations).toHaveLength(0);
      }
    });
  });

  describe('scanSql', () => {
    it('should scan SQL queries', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ safe: true }),
      });

      const client = new ShrikeOpenAI({
        apiKey: 'sk-test',
        shrikeApiKey: 'shrike-test',
      });

      const result = await client.scanSql('SELECT * FROM users WHERE id = 1');
      expect(result.safe).toBe(true);
    });

    it('should detect SQL injection', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            safe: false,
            threat_type: 'sql_injection',
            reason: 'SQL injection detected',
          }),
      });

      const client = new ShrikeOpenAI({
        apiKey: 'sk-test',
        shrikeApiKey: 'shrike-test',
      });

      const result = await client.scanSql("SELECT * FROM users WHERE id = '1' OR '1'='1'");
      expect(result.safe).toBe(false);
      expect(result.threat_type).toBe('sql_injection');
    });
  });

  describe('scanFile', () => {
    it('should scan file paths', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ safe: true }),
      });

      const client = new ShrikeOpenAI({
        apiKey: 'sk-test',
        shrikeApiKey: 'shrike-test',
      });

      const result = await client.scanFile('/app/data/report.csv');
      expect(result.safe).toBe(true);
    });

    it('should detect path traversal', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            safe: false,
            threat_type: 'path_traversal',
            reason: 'Path traversal detected',
          }),
      });

      const client = new ShrikeOpenAI({
        apiKey: 'sk-test',
        shrikeApiKey: 'shrike-test',
      });

      const result = await client.scanFile('../../../etc/passwd');
      expect(result.safe).toBe(false);
      expect(result.threat_type).toBe('path_traversal');
    });
  });
});
