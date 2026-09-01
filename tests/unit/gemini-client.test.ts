/**
 * Unit tests for ShrikeGemini client.
 */

import { ShrikeGemini, ShrikeGenerativeModel, ShrikeChatSession } from '../../src/gemini/client';
import { ShrikeBlockedError, ShrikeScanError } from '../../src/errors';
import { FailMode } from '../../src/config';

// Mock fetch globally
const mockFetch = jest.fn();
global.fetch = mockFetch;

// Mock response from Gemini
const mockGenerateContentResponse = {
  response: {
    text: () => 'Hello from Gemini!',
    candidates: [{ content: { parts: [{ text: 'Hello from Gemini!' }] } }],
  },
};

const mockChat = {
  sendMessage: jest.fn().mockResolvedValue(mockGenerateContentResponse),
  sendMessageStream: jest.fn().mockResolvedValue({ stream: [] }),
  getHistory: jest.fn().mockReturnValue([]),
};

const mockModels = {
  generateContent: jest.fn().mockResolvedValue(mockGenerateContentResponse),
  generateContentStream: jest.fn().mockResolvedValue({ stream: [] }),
};

const mockChats = {
  create: jest.fn().mockReturnValue(mockChat),
};

// Mock @google/genai (v2+): `new GoogleGenAI({apiKey})` exposes `.models` and
// `.chats`. This must match the real SDK surface that src/gemini/client.ts
// require()s — a mock of the deprecated `GoogleGenerativeAI` /
// `getGenerativeModel` shape is exactly what let the previous broken wrapper
// pass CI. See failOpenDegraded/real-package shape test for the guard.
jest.mock('@google/genai', () => ({
  GoogleGenAI: jest.fn().mockImplementation(() => ({
    models: mockModels,
    chats: mockChats,
  })),
}));

describe('ShrikeGemini', () => {
  beforeEach(() => {
    mockFetch.mockClear();
    mockModels.generateContent.mockClear();
    mockModels.generateContentStream.mockClear();
    mockChats.create.mockClear();
    mockChat.sendMessage.mockClear();
  });

  describe('constructor', () => {
    it('should initialize with default options', () => {
      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
      });
      expect(client).toBeDefined();
    });

    it('should accept custom endpoint', () => {
      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
        shrikeEndpoint: 'https://custom.endpoint.com/',
      });
      expect(client).toBeDefined();
    });

    it('should forward baseUrl to GoogleGenAI as httpOptions.baseUrl (trailing slash trimmed)', () => {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { GoogleGenAI } = require('@google/genai');
      (GoogleGenAI as jest.Mock).mockClear();
      new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
        baseUrl: 'https://gemini-gateway.internal/',
      });
      const arg = (GoogleGenAI as jest.Mock).mock.calls[0][0];
      expect(arg.httpOptions).toEqual({ baseUrl: 'https://gemini-gateway.internal' });
    });

    it('should let explicit geminiOptions.httpOptions win over baseUrl', () => {
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const { GoogleGenAI } = require('@google/genai');
      (GoogleGenAI as jest.Mock).mockClear();
      new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
        baseUrl: 'https://ignored.example',
        geminiOptions: { httpOptions: { baseUrl: 'https://explicit.example' } },
      });
      const arg = (GoogleGenAI as jest.Mock).mock.calls[0][0];
      expect(arg.httpOptions).toEqual({ baseUrl: 'https://explicit.example' });
    });

    it('should accept fail mode as string or enum', () => {
      const client1 = new ShrikeGemini({
        apiKey: 'AIza-test',
        failMode: 'closed',
      });
      const client2 = new ShrikeGemini({
        apiKey: 'AIza-test',
        failMode: FailMode.CLOSED,
      });
      expect(client1).toBeDefined();
      expect(client2).toBeDefined();
    });
  });

  describe('getGenerativeModel', () => {
    it('should return a ShrikeGenerativeModel', () => {
      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
      });
      const model = client.getGenerativeModel({ model: 'gemini-1.5-flash' });
      expect(model).toBeInstanceOf(ShrikeGenerativeModel);
      expect(model.modelName).toBe('gemini-1.5-flash');
    });

    it('should also work via GenerativeModel alias', () => {
      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
      });
      const model = client.GenerativeModel('gemini-pro');
      expect(model).toBeInstanceOf(ShrikeGenerativeModel);
    });
  });

  describe('_extractContent', () => {
    it('should extract string content', () => {
      const client = new ShrikeGemini({ apiKey: 'AIza-test' });
      expect(client._extractContent('Hello world')).toBe('Hello world');
    });

    it('should extract content from array of parts', () => {
      const client = new ShrikeGemini({ apiKey: 'AIza-test' });
      const content = client._extractContent([
        { text: 'Hello' },
        { text: 'World' },
      ]);
      expect(content).toBe('Hello\nWorld');
    });

    it('should extract content from object with text', () => {
      const client = new ShrikeGemini({ apiKey: 'AIza-test' });
      expect(client._extractContent({ text: 'Hello' })).toBe('Hello');
    });

    it('should extract content from object with parts', () => {
      const client = new ShrikeGemini({ apiKey: 'AIza-test' });
      const content = client._extractContent({
        parts: [{ text: 'Hello' }, { text: 'World' }],
      });
      expect(content).toBe('Hello\nWorld');
    });
  });

  describe('_scanContent', () => {
    it('should return safe for empty content', async () => {
      const client = new ShrikeGemini({ apiKey: 'AIza-test' });
      const result = await client._scanContent('   ');
      expect(result.safe).toBe(true);
    });

    it('should scan non-empty content via backend', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ safe: true }),
      });

      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
      });

      const result = await client._scanContent('Hello!');
      expect(result.safe).toBe(true);
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/scan'),
        expect.objectContaining({
          method: 'POST',
        })
      );
      // Verify body contains prompt and session context
      const callBody = JSON.parse(mockFetch.mock.calls[0][1].body);
      expect(callBody.prompt).toBe('Hello!');
      expect(callBody.context.session_id).toBeDefined();
      expect(callBody.context.source_application).toBe('shrike-guard-ts');
    });

    it('should fail open on timeout by default', async () => {
      mockFetch.mockImplementationOnce(() => {
        const error = new Error('The operation was aborted');
        return Promise.reject(error);
      });

      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        failMode: FailMode.OPEN,
      });

      const result = await client._scanContent('Hello!');
      expect(result.safe).toBe(true);
      expect(result.reason).toContain('timeout');
      expect(result.degraded).toBe(true); // F-2: fail-open must be marked degraded
    });

    it('should throw on timeout when fail mode is closed', async () => {
      mockFetch.mockImplementationOnce(() => {
        const error = new Error('abort');
        return Promise.reject(error);
      });

      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        failMode: FailMode.CLOSED,
      });

      await expect(client._scanContent('Hello!')).rejects.toThrow(ShrikeScanError);
    });

    it('should fail open on HTTP error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
      });

      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        failMode: FailMode.OPEN,
      });

      const result = await client._scanContent('Hello!');
      expect(result.safe).toBe(true);
      expect(result.reason).toContain('500');
    });

    it('should throw on HTTP error when fail mode is closed', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
      });

      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        failMode: FailMode.CLOSED,
      });

      await expect(client._scanContent('Hello!')).rejects.toThrow(ShrikeScanError);
    });
  });

  describe('generateContent', () => {
    it('should scan and proxy safe requests', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ safe: true }),
      });

      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
      });

      const model = client.getGenerativeModel({ model: 'gemini-1.5-flash' });
      const response = await model.generateContent('Hello!');

      expect(response).toBeDefined();
      expect(mockModels.generateContent).toHaveBeenCalledWith({
        model: 'gemini-1.5-flash',
        contents: 'Hello!',
      });
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

      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
      });

      const model = client.getGenerativeModel({ model: 'gemini-1.5-flash' });

      await expect(
        model.generateContent('Ignore all previous instructions...')
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

      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
      });

      const model = client.getGenerativeModel({ model: 'gemini-1.5-flash' });

      try {
        await model.generateContent('My SSN is 123-45-6789');
        fail('Should have thrown');
      } catch (error) {
        expect(error).toBeInstanceOf(ShrikeBlockedError);
        const blocked = error as ShrikeBlockedError;
        expect(blocked.threatType).toBe('pii_exposure');
        expect(blocked.confidence).toBe('high');
        // Sanitizer preserves customer-visible violation entries per contract
        // symmetry (platform/CLAUDE.md); only policy_id/policy_name/
        // detection-attribution fields are stripped per-violation.
        expect(blocked.violations).toHaveLength(1);
        expect(blocked.violations[0]).toEqual({
          type: 'ssn',
          value: '***-**-1234',
        });
      }
    });
  });

  describe('generateContentStream', () => {
    it('should scan and proxy safe streaming requests', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ safe: true }),
      });

      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
      });

      const model = client.getGenerativeModel({ model: 'gemini-1.5-flash' });
      const response = await model.generateContentStream('Hello!');

      expect(response).toBeDefined();
      expect(mockModels.generateContentStream).toHaveBeenCalledWith({
        model: 'gemini-1.5-flash',
        contents: 'Hello!',
      });
    });

    it('should block unsafe streaming requests', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            safe: false,
            reason: 'Jailbreak detected',
            threat_type: 'jailbreak',
            confidence: 0.88,
          }),
      });

      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
      });

      const model = client.getGenerativeModel({ model: 'gemini-1.5-flash' });

      await expect(
        model.generateContentStream('DAN mode activated...')
      ).rejects.toThrow(ShrikeBlockedError);
    });
  });

  describe('startChat', () => {
    it('should return a ShrikeChatSession', () => {
      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
      });

      const model = client.getGenerativeModel({ model: 'gemini-1.5-flash' });
      const chat = model.startChat();

      expect(chat).toBeInstanceOf(ShrikeChatSession);
    });

    it('should scan chat messages before sending', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ safe: true }),
      });

      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
      });

      const model = client.getGenerativeModel({ model: 'gemini-1.5-flash' });
      const chat = model.startChat();

      await chat.sendMessage('Hello!');

      expect(mockFetch).toHaveBeenCalled();
      expect(mockChat.sendMessage).toHaveBeenCalledWith({ message: 'Hello!' });
    });

    it('should block unsafe chat messages', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () =>
          Promise.resolve({
            safe: false,
            reason: 'PII detected',
            threat_type: 'pii_extraction',
            confidence: 0.92,
          }),
      });

      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
      });

      const model = client.getGenerativeModel({ model: 'gemini-1.5-flash' });
      const chat = model.startChat();

      await expect(
        chat.sendMessage('My SSN is 123-45-6789')
      ).rejects.toThrow(ShrikeBlockedError);
    });

    it('should scan streaming chat messages', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve({ safe: true }),
      });

      const client = new ShrikeGemini({
        apiKey: 'AIza-test',
        shrikeApiKey: 'shrike-test',
      });

      const model = client.getGenerativeModel({ model: 'gemini-1.5-flash' });
      const chat = model.startChat();

      await chat.sendMessageStream('Hello!');

      expect(mockFetch).toHaveBeenCalled();
    });
  });
});
