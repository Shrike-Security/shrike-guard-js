# Shrike Guard

[![npm version](https://badge.fury.io/js/shrike-guard.svg)](https://badge.fury.io/js/shrike-guard)
[![Node.js 18+](https://img.shields.io/badge/node-18+-green.svg)](https://nodejs.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Shrike Guard** is a TypeScript SDK that provides security protection for your LLM applications. It wraps OpenAI, Anthropic (Claude), and Google Gemini clients to automatically scan all prompts for security threats before they reach the LLM.

## Features

- **Drop-in replacement** for OpenAI, Anthropic, and Gemini clients
- **Automatic prompt scanning** for:
  - Prompt injection attacks
  - PII/sensitive data leakage
  - Jailbreak attempts
  - SQL injection
  - Path traversal
- **Fail-safe modes**: Choose between fail-open (default) or fail-closed behavior
- **CJS + ESM**: Dual build via tsup, works everywhere
- **Subpath imports**: `shrike-guard/openai`, `shrike-guard/anthropic`, `shrike-guard/gemini`
- **Zero code changes**: Just replace your import

## What Shrike Detects

Shrike's backend runs a 9-layer detection cascade with **86+ security rules** across **6 compliance frameworks**:

| Framework | Rules | Coverage |
|-----------|-------|----------|
| **HIPAA** | 19 | Protected health information (PHI) — 19 Safe Harbor identifiers |
| **SOC 2** | 21 | Secrets, credentials, API keys, cloud tokens |
| **ISO 27001** | 19 | Information security — passwords, tokens, certificates |
| **PCI-DSS** | 8 | Cardholder data — PAN, CVV, expiry, track data, PINs |
| **GDPR** | 11 | EU personal data — names, addresses, national IDs |
| **WebMCP Tool Safety** | 8 | MCP tool description injection, data exfiltration |

Plus built-in detection for prompt injection, jailbreaks, social engineering, dangerous requests, and 130+ threat patterns.

### Tiers

| Tier | Pipeline | Cost |
|------|----------|------|
| **Community** | Full 9-layer cascade (L1-L8) | Free |
| **Enterprise** | Full 9-layer cascade + priority processing, higher rate limits, custom policies | Paid |

**Get your free API key:**

1. Register at [shrikesecurity.com/signup](https://shrikesecurity.com/signup)
2. Or via the API:
   ```bash
   curl -X POST https://api.shrikesecurity.com/agent/api/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email": "you@company.com", "password": "...", "company": "Acme", "role": "developer"}'
   ```
3. Your API key (`shrike_...`) is returned in the response — use it as `shrikeApiKey` in the SDK.

## Installation

```bash
npm install shrike-guard
```

Install the LLM provider(s) you use as peer dependencies:

```bash
# OpenAI
npm install openai

# Anthropic (Claude)
npm install @anthropic-ai/sdk

# Google Gemini
npm install @google/generative-ai
```

## Quick Start

### OpenAI

```typescript
import { ShrikeOpenAI } from 'shrike-guard/openai';

const client = new ShrikeOpenAI({
  apiKey: 'sk-...',           // Your OpenAI API key
  shrikeApiKey: 'shrike-...', // Your Shrike API key
});

const response = await client.chat.completions.create({
  model: 'gpt-4',
  messages: [{ role: 'user', content: 'Hello, how are you?' }],
});

console.log(response.choices[0].message.content);
```

### Anthropic (Claude)

```typescript
import { ShrikeAnthropic } from 'shrike-guard/anthropic';

const client = new ShrikeAnthropic({
  apiKey: 'sk-ant-...',
  shrikeApiKey: 'shrike-...',
});

const message = await client.messages.create({
  model: 'claude-3-opus-20240229',
  max_tokens: 1024,
  messages: [{ role: 'user', content: 'Hello!' }],
});
```

### Google Gemini

```typescript
import { ShrikeGemini } from 'shrike-guard/gemini';

const client = new ShrikeGemini({
  apiKey: 'AIza...',
  shrikeApiKey: 'shrike-...',
});

const model = client.getGenerativeModel({ model: 'gemini-1.5-flash' });
const response = await model.generateContent('Hello!');
```

## Configuration

### Fail Modes

Choose how the SDK behaves when the security scan fails (timeout, network error, etc.):

```typescript
import { ShrikeOpenAI } from 'shrike-guard/openai';

// Fail-open (default): Allow requests if scan fails
// Best for: Most applications where availability is important
const client = new ShrikeOpenAI({
  apiKey: 'sk-...',
  shrikeApiKey: 'shrike-...',
  failMode: 'open',
});

// Fail-closed: Block requests if scan fails
// Best for: Security-critical applications
const strictClient = new ShrikeOpenAI({
  apiKey: 'sk-...',
  shrikeApiKey: 'shrike-...',
  failMode: 'closed',
});
```

### Timeout Configuration

```typescript
const client = new ShrikeOpenAI({
  apiKey: 'sk-...',
  shrikeApiKey: 'shrike-...',
  scanTimeout: 5000, // Timeout in milliseconds (default: 10000)
});
```

### Custom Endpoint

For self-hosted Shrike deployments:

```typescript
const client = new ShrikeOpenAI({
  apiKey: 'sk-...',
  shrikeApiKey: 'shrike-...',
  shrikeEndpoint: 'https://your-shrike-instance.com',
});
```

## SQL and File Scanning

The OpenAI client also provides standalone scanning for SQL queries and file paths:

```typescript
import { ShrikeOpenAI } from 'shrike-guard/openai';

const client = new ShrikeOpenAI({
  apiKey: 'sk-...',
  shrikeApiKey: 'shrike-...',
});

// Scan SQL queries for injection attacks
const sqlResult = await client.scanSql('SELECT * FROM users WHERE id = 1');
if (!sqlResult.safe) {
  console.log(`SQL threat: ${sqlResult.reason}`);
}

// Scan file paths for path traversal
const fileResult = await client.scanFile('/app/data/output.csv');

// Scan file content for secrets
const contentResult = await client.scanFile('/tmp/config.py', 'api_key = "sk-..."');
```

## Error Handling

```typescript
import { ShrikeOpenAI } from 'shrike-guard/openai';
import { ShrikeBlockedError, ShrikeScanError } from 'shrike-guard';

const client = new ShrikeOpenAI({
  apiKey: 'sk-...',
  shrikeApiKey: 'shrike-...',
  failMode: 'closed',
});

try {
  const response = await client.chat.completions.create({
    model: 'gpt-4',
    messages: [{ role: 'user', content: 'Some prompt...' }],
  });
} catch (error) {
  if (error instanceof ShrikeBlockedError) {
    // Prompt was blocked due to security threat
    console.log(`Blocked: ${error.message}`);
    console.log(`Threat type: ${error.threatType}`);
    console.log(`Confidence: ${error.confidence}`);
    console.log(`Violations: ${error.violations}`);
  } else if (error instanceof ShrikeScanError) {
    // Scan failed (only raised with failMode: 'closed')
    console.log(`Scan error: ${error.message}`);
  }
}
```

## Low-Level Scan Client

For more control, use the scan client directly:

```typescript
import { ScanClient } from 'shrike-guard';

const scanner = new ScanClient({ apiKey: 'shrike-...' });

const result = await scanner.scan('Check this prompt for threats');

if (result.safe) {
  console.log('Prompt is safe!');
} else {
  console.log(`Threat detected: ${result.reason}`);
}
```

## Compatibility

- **Node.js**: 18+
- **TypeScript**: 5.0+
- **LLM SDKs**:
  - OpenAI SDK `>=4.0.0`
  - Anthropic SDK `>=0.18.0`
  - Google Generative AI `>=0.3.0`

## Environment Variables

```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export SHRIKE_API_KEY="shrike-..."
export SHRIKE_ENDPOINT="https://your-shrike-instance.com"
```

## Scope and Limitations

| Scanned | Not Scanned |
|---------|-------------|
| Input prompts (user messages) | Streaming output from LLM |
| Multi-modal text content | Image/audio content |
| SQL queries | Non-chat API calls |
| File paths and content | |

### Why Input-Only Scanning?

Shrike Guard focuses on **pre-flight protection** - blocking malicious prompts BEFORE they reach the LLM. This:
- Prevents prompt injection attacks at the source
- Has zero latency impact on LLM responses
- Catches 95%+ of threats (attacks are in the INPUT)

## License

Apache 2.0

## Support

- Documentation: https://docs.shrike.security/sdk/typescript
- Issues: https://github.com/Shrike-Security/shrike-guard-js/issues
- Email: support@shrike.security
