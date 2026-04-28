# Shrike Guard

[![npm version](https://badge.fury.io/js/shrike-guard.svg)](https://badge.fury.io/js/shrike-guard)
[![Node.js 18+](https://img.shields.io/badge/node-18+-green.svg)](https://nodejs.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Shrike Guard** is a TypeScript SDK for the [Shrike](https://shrikesecurity.com) platform — AI governance for every AI interaction. It wraps OpenAI, Anthropic (Claude), and Google Gemini clients to automatically evaluate all prompts against policy before they reach the LLM. Whether you're governing a customer-facing chatbot, securing developer AI tools, or managing autonomous agent actions — the same multi-layered cognitive pipeline evaluates every interaction.

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

Shrike's backend runs a multi-stage detection pipeline with security rules across **7 compliance frameworks**:

| Framework | Coverage |
|-----------|----------|
| **GDPR** | EU personal data — names, addresses, national IDs |
| **HIPAA** | Protected health information (PHI) |
| **ISO 27001** | Information security — passwords, tokens, certificates |
| **SOC 2** | Secrets, credentials, API keys, cloud tokens |
| **NIST** | AI risk management (IR 8596), cybersecurity framework (CSF 2.0) |
| **PCI-DSS** | Cardholder data — PAN, CVV, expiry, track data |
| **WebMCP** | MCP tool description injection, data exfiltration |

Plus built-in detection for prompt injection, jailbreaks, social engineering, and dangerous requests.

### Tiers

Detection depth depends on your tier. All tiers get the same SDK wrappers — tiers control which backend layers run.

| | Anonymous | Community | Pro | Enterprise |
|---|---|---|---|---|
| Detection Layers | L1-L5 | L1-L7 | L1-L8 | L1-L9 |
| API Key | Not needed | Free signup | Paid | Paid |
| Rate Limit | — | 10/min | 100/min | 1,000/min |
| Scans/month | — | 1,000 | 25,000 | 1,000,000 |

**Anonymous** (no API key): Pattern-based detection (L1-L5). **Community** (free): Adds LLM-powered semantic analysis. Register at [shrikesecurity.com/signup](https://shrikesecurity.com/signup) — instant, no credit card.

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

Shrike Guard focuses on **pre-flight protection** — blocking malicious prompts BEFORE they reach the LLM. This:
- Prevents prompt injection attacks at the source
- Has zero latency impact on LLM responses
- Catches the vast majority of threats at the input layer

## Other Integration Surfaces

Shrike Guard is one of several ways to integrate with the Shrike platform:

- **MCP Server** — `npx shrike-mcp` ([GitHub](https://github.com/Shrike-Security/shrike-mcp))
- **Python SDK** — `pip install shrike-guard` ([GitHub](https://github.com/Shrike-Security/shrike-guard-python))
- **REST API** — `POST https://api.shrikesecurity.com/agent/scan`
- **LLM Gateway** — Change one URL, scan everything
- **Browser Extension** — Chrome/Edge for ChatGPT, Claude, Gemini
- **Dashboard** — [shrikesecurity.com](https://shrikesecurity.com)

## Use Cases

| Scenario | How Shrike Guard Helps |
|---|---|
| **Customer chatbot** | Wrap your OpenAI/Anthropic client. Every user message scanned for injection before it reaches the model. |
| **Internal RAG pipeline** | Scan retrieved context + user queries for PII leakage and injection attempts. |
| **AI coding assistant** | Scan prompts for proprietary code patterns before they leave your environment. |
| **Agent orchestration** | Scan every tool call and LLM request in your LangChain/CrewAI/AutoGen pipeline. |

## Alternatives

Looking for an AI security SDK? Here's how Shrike Guard compares:

| Feature | Shrike Guard | Lakera | Prompt Armor |
|---|---|---|---|
| Drop-in OpenAI/Anthropic/Gemini wrapper | Yes | No | No |
| Multi-layered evaluation pipeline | Yes | Limited | Limited |
| PII detection + redaction | Yes | Partial | No |
| Session correlation | Yes (Enterprise) | No | No |
| Free tier (no API key) | Yes | No | No |
| Open source client | Yes (Apache 2.0) | No | No |

## License

Apache 2.0

## Support

- [Shrike](https://shrikesecurity.com) — Sign up, dashboard, docs
- [Documentation](https://shrikesecurity.com/docs) — Quick start, API reference
- [GitHub Issues](https://github.com/Shrike-Security/shrike-guard-js/issues) — Bug reports
- [MCP Server](https://github.com/Shrike-Security/shrike-mcp) — For MCP/agent integration
- [Python SDK](https://github.com/Shrike-Security/shrike-guard-python) — Python equivalent
