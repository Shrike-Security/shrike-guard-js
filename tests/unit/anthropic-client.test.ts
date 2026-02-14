/**
 * Unit tests for ShrikeAnthropic client.
 */

import { ShrikeAnthropic } from '../../src/anthropic/client';
import { ShrikeBlockedError, ShrikeScanError } from '../../src/errors';
import { FailMode } from '../../src/config';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

// Mock Anthropic SDK
jest.mock('@anthropic-ai/sdk', () => ({
  default: jest.fn().mockImplementation(() => ({
    messages: {
      create: jest.fn().mockResolvedValue({
        id: 'msg_test_123',
        type: 'message',
        role: 'assistant',
        content: [{ type: 'text', text: 'Hello from Claude!' }],
        model: 'claude-3-opus-20240229',
        stop_reason: 'end_turn',
      }),
    },
  })),
}));

describe('ShrikeAnthropic', () => {
  beforeEach(() => {
    mockFetch.mockClear();
  });

  describe('constructor', () => {
    it('should initialize with default options', () => {
      const client = new ShrikeAnthropic({
        apiKey: 'sk-ant-test',
        shrikeApiKey: 'shrike-test',
      });
      expect(client).toBeDefined();
      expect(client.messages).toBeDefined();
    });

    it('should accept custom endpoint', () => {
      const client = new ShrikeAnthropic({
        apiKey: 'sk-ant-test',
        shrikeApiKey: 'shrike-test',
        shrikeEndpoint: 'https://custom.endpoint.com/',
      });
      expect(client).toBeDefined();
    });

    it('should accept fail mode as string or enum', () => {
      const client1 = new ShrikeAnthropic({
        apiKey: 'sk-ant-test',
        failMode: 'closed',
      });
      const client2 = new ShrikeAnthropic({
        apiKey: 'sk-ant-test',
        failMode: FailMode.CLOSED,
      });
      expect(client1).toBeDefined();
      expect(client2).toBeDefined();
    });
  });

  describe('_extractUserContent', () => {
    it('should extract content from simple string messages', () => {
      const client = new ShrikeAnthropic({ apiKey: 'sk-ant-test' });
      const messages = [
        { role: 'user', content: 'Hello!' },
        { role: 'assistant', content: 'Hi there!' },
        { role: 'user', content: 'How are you?' },
      ];

      const content = client._extractUserContent(messages);
      expect(content).toBe('Hello!\nHow are you?');
    });

    it('should extract content from content block messages', () => {
      const client = new ShrikeAnthropic({ apiKey: 'sk-ant-test' });
      const messages = [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'What is in this image?' },
            { type: 'image', source: { type: 'base64', data: '...' } },
          ],
        },
      ];

      const content = client._extractUserContent(messages);
      expect(content).toBe('What is in this image?');
    });

    it('should return empty string when no user content', () => {
      const client = new ShrikeAnthropic({ apiKey: 'sk-ant-test' });
      const messages = [
        { role: 'assistant', content: 'I am the assistant' },
      ];

      const content = client._extractUserContent(messages);
      expect(content).toBe('');
    });

    it('should handle multiple content blocks', () => {
      const client = new ShrikeAnthropic({ apiKey: 'sk-ant-test' });
      const messages = [
        {
          role: 'user',
          content: [
            { type: 'text', text: 'First part' },
            { type: 'text', text: 'Second part' },
          ],
        },
      ];

      const content = client._extractUserContent(messages);
      expect(content).toBe('First part\nSecond part');
    });
  });

  describe('_scanMessages', () => {
    it('should return safe when no user content', async () => {
      const client = new ShrikeAnthropic({ apiKey: 'sk-ant-test' });
      const messages = [{ role: 'assistant', content: 'System message' }];

      const result = await client._scanMessages(messages);
      expect(result.safe).toBe(true);
      expect(result.reason).toBe('No user content to scan');
    });

    it('should scan user messages via backend', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ safe: true }),
      });

      const client = new ShrikeAnthropic({
        apiKey: 'sk-ant-test',
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

      const client = new ShrikeAnthropic({
        apiKey: 'sk-ant-test',
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

      const client = new ShrikeAnthropic({
        apiKey: 'sk-ant-test',
        failMode: FailMode.CLOSED,
      });
      const messages = [{ role: 'user', content: 'Hello!' }];

      await expect(client._scanMessages(messages)).rejects.toThrow(ShrikeScanError);
    });

    it('should fail open on network error by default', async () => {
      mockFetch.mockImplementationOnce(() =>
        Promise.reject(new Error('Network error'))
      );

      const client = new ShrikeAnthropic({
        apiKey: 'sk-ant-test',
        failMode: FailMode.OPEN,
      });
      const messages = [{ role: 'user', content: 'Hello!' }];

      const result = await client._scanMessages(messages);
      expect(result.safe).toBe(true);
    });

    it('should fail open on HTTP error by default', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
      });

      const client = new ShrikeAnthropic({
        apiKey: 'sk-ant-test',
        failMode: FailMode.OPEN,
      });
      const messages = [{ role: 'user', content: 'Hello!' }];

      const result = await client._scanMessages(messages);
      expect(result.safe).toBe(true);
      expect(result.reason).toContain('500');
    });

    it('should throw on HTTP error when fail mode is closed', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
      });

      const client = new ShrikeAnthropic({
        apiKey: 'sk-ant-test',
        failMode: FailMode.CLOSED,
      });
      const messages = [{ role: 'user', content: 'Hello!' }];

      await expect(client._scanMessages(messages)).rejects.toThrow(ShrikeScanError);
    });
  });

  describe('messages.create', () => {
    it('should scan and proxy safe requests', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ safe: true }),
      });

      const client = new ShrikeAnthropic({
        apiKey: 'sk-ant-test',
        shrikeApiKey: 'shrike-test',
      });

      const response = await client.messages.create({
        model: 'claude-3-opus-20240229',
        max_tokens: 1024,
        messages: [{ role: 'user', content: 'Hello!' }],
      });

      expect(response).toBeDefined();
      expect(response.content).toBeDefined();
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

      const client = new ShrikeAnthropic({
        apiKey: 'sk-ant-test',
        shrikeApiKey: 'shrike-test',
      });

      await expect(
        client.messages.create({
          model: 'claude-3-opus-20240229',
          max_tokens: 1024,
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

      const client = new ShrikeAnthropic({
        apiKey: 'sk-ant-test',
        shrikeApiKey: 'shrike-test',
      });

      try {
        await client.messages.create({
          model: 'claude-3-opus-20240229',
          max_tokens: 1024,
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
});
