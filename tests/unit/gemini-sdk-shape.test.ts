/**
 * Real-package shape guard for @google/genai.
 *
 * Deliberately does NOT jest.mock('@google/genai') — it loads the ACTUAL
 * installed SDK and asserts the surface our Gemini wrapper depends on. This is
 * the test the previous wrapper lacked: every other Gemini test mocks the SDK,
 * so a class-name / API-shape mismatch (`GoogleGenerativeAI` vs `GoogleGenAI`,
 * `getGenerativeModel()` vs `ai.models.generateContent()`) shipped a wrapper
 * that threw at construction against the package it declared. If Google renames
 * or restructures the SDK again, this fails at CI instead of in production.
 */

import { ShrikeGemini } from '../../src/gemini/client';

describe('@google/genai real-package shape', () => {
  it('exports GoogleGenAI with .models.generateContent(...) and .chats.create(...)', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const genai = require('@google/genai');
    expect(typeof genai.GoogleGenAI).toBe('function');

    const ai = new genai.GoogleGenAI({ apiKey: 'test-key' });
    expect(ai.models).toBeDefined();
    expect(typeof ai.models.generateContent).toBe('function');
    expect(typeof ai.models.generateContentStream).toBe('function');
    expect(ai.chats).toBeDefined();
    expect(typeof ai.chats.create).toBe('function');
  });

  it('ShrikeGemini constructs against the real SDK without throwing', () => {
    const client = new ShrikeGemini({ apiKey: 'test-key', shrikeApiKey: 'shrike-test' });
    const model = client.getGenerativeModel({ model: 'gemini-2.0-flash' });
    expect(model).toBeDefined();
  });
});
