/**
 * Real-package shape guard for the OpenAI and Anthropic SDKs.
 *
 * Deliberately does NOT jest.mock() the providers — it loads the ACTUAL
 * installed packages and asserts the surface our wrappers call
 * (`client.chat.completions.create`, `client.messages.create`). Every other
 * wrapper test mocks these, so an upstream rename/restructure would slip
 * through — the same failure mode that shipped the broken Gemini wrapper.
 * See gemini-sdk-shape.test.ts for the Gemini equivalent.
 */

describe('provider SDK real-package shapes', () => {
  it('openai exposes chat.completions.create', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require('openai');
    const OpenAI = mod.default ?? mod.OpenAI;
    expect(typeof OpenAI).toBe('function');
    const client = new OpenAI({ apiKey: 'test-key' });
    expect(typeof client.chat.completions.create).toBe('function');
  });

  it('@anthropic-ai/sdk exposes messages.create', () => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const mod = require('@anthropic-ai/sdk');
    const Anthropic = mod.default ?? mod.Anthropic;
    expect(typeof Anthropic).toBe('function');
    const client = new Anthropic({ apiKey: 'test-key' });
    expect(typeof client.messages.create).toBe('function');
  });
});
