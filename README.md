# Shrike Guard

[![npm version](https://badge.fury.io/js/shrike-guard.svg)](https://badge.fury.io/js/shrike-guard)
[![Node.js 18+](https://img.shields.io/badge/node-18+-green.svg)](https://nodejs.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

**Shrike Guard** is a TypeScript SDK for the [Shrike](https://shrikesecurity.com) platform — AI governance for every AI interaction. It wraps OpenAI, Anthropic (Claude), and Google Gemini clients to automatically evaluate all prompts against policy before they reach the LLM. Whether you're governing a customer-facing chatbot, securing developer AI tools, or managing autonomous agent actions — the same 9-layer cognitive pipeline evaluates every interaction.

It scans two different things. **Prompts and responses**, which is what a guardrail library normally means. And **agent actions** — the shell command, the SQL query, the web search, the retrieved document, the MCP tool definition — screened before they run, which is where an autonomous agent actually causes harm. See [Scanning agent actions](#scanning-agent-actions-shell-commands-sql-web-search-rag-mcp-tools).

## Features

- **Drop-in replacement** for OpenAI, Anthropic, and Gemini clients
- **Automatic prompt scanning** for:
  - Prompt injection attacks
  - PII/sensitive data leakage
  - Jailbreak attempts
  - SQL injection
  - Path traversal
- **Pre-execution scanning for agent actions**: shell commands, SQL, file writes, web searches, RAG context, agent-to-agent messages, agent cards, and MCP tool schemas
- **Content provenance** (`content_origin`): every verdict says whether a human typed it, the model wrote it, the agent is about to do it, or it arrived from outside
- **Fail-safe modes**: Defaults to fail-closed (Zero Trust posture); opt into fail-open explicitly when availability outranks enforcement
- **CJS + ESM**: Dual build via tsup, works everywhere
- **Subpath imports**: `shrike-guard/openai`, `shrike-guard/anthropic`, `shrike-guard/gemini`
- **Zero code changes**: Just replace your import

## What Shrike Detects

Shrike's 9-layer cognitive pipeline includes sensitive-data detection aligned to 5 major regulatory frameworks:

| Framework | Coverage |
|-----------|----------|
| **GDPR** | EU personal data — names, addresses, national IDs |
| **HIPAA** | Protected health information (PHI) |
| **ISO 27001** | Information security — passwords, tokens, certificates |
| **SOC 2** | Secrets, credentials, API keys, cloud tokens |
| **NIST** | AI risk management (IR 8596), cybersecurity framework (CSF 2.0) |

Detection coverage is not a certification claim — see [shrikesecurity.com/compliance](https://shrikesecurity.com/compliance) for our current certification status. Plus built-in detection for prompt injection, jailbreaks, social engineering, and dangerous requests.

### Tiers

Detection depth depends on your tier. All tiers get the same SDK wrappers — tiers control which backend layers run.

| | Anonymous | Community | Pro | Enterprise |
|---|---|---|---|---|
| Detection Layers | L1-L5 | L1-L5 | L1-L9 (full) | L1-L9 (full) |
| API Key | Not needed | Free signup | Paid | Paid |
| Rate Limit | — | 10/min | 100/min | 1,000/min |
| Scans/month | — | 1,000 | 25,000 | 1,000,000 |

**Anonymous** (no API key): Pattern-based detection (L1-L5). **Community** (free): Same L1-L5 detection with a dashboard and higher limits; LLM-powered semantic analysis (L6-L9) is Pro+. Register at [shrikesecurity.com/signup](https://shrikesecurity.com/signup) — instant, no credit card.

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
npm install @google/genai
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

// Fail-closed (default): Block requests if scan fails
// Best for: Production security workloads. If the Shrike backend is down,
// the SDK raises ShrikeScanError instead of allowing traffic through unguarded.
const client = new ShrikeOpenAI({
  apiKey: 'sk-...',
  shrikeApiKey: 'shrike-...',
  failMode: 'closed', // This is the default
});

// Fail-open: Allow requests if scan fails
// Best for: Non-production experiments, internal tools where availability must
// outrank enforcement. Trades the guard's enforcement promise for uptime.
const permissiveClient = new ShrikeOpenAI({
  apiKey: 'sk-...',
  shrikeApiKey: 'shrike-...',
  failMode: 'open',
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

### Sessions: one per unit of work, not one per process

Shrike correlates risk across a session. After a refusal, later actions in the
same session are held until the session recovers. That is the multi-turn
defence, and it means the session id has to mean one unit of work: one agent
run, one conversation, one user's request.

By default the SDK scans under one id for the whole process. That suits a CLI,
a worker, or a single agent. It does not suit a server that scans on behalf of
many end users, because every user then shares one risk score, and one user's
refusal counts against the next user's action.

Build one client at startup and derive a per-request view from it. The view
shares the rate limiter, so it costs nothing to make one per request and it
cannot multiply your rate budget:

```typescript
import { ScanClient } from 'shrike-guard';

const guard = new ScanClient({ apiKey: 'shrike-...' });   // once, at startup

app.post('/act', async (req, res) => {                     // per request
  const scoped = guard.forSession(req.session.id);
  const verdict = await scoped.scanCommand(req.body.command);
  if (verdict.refuse_tier !== 'allow') {
    ...
  }
});
```

Or pin the identity at construction when one client serves one unit of work:

```typescript
const client = new ScanClient({ apiKey: 'shrike-...', sessionId: 'job-42', agentId: 'ingest' });
```

`agentId` is separate on purpose: it names *which agent* a scope is enforced
against and who an incident is attributed to. Set it when one process drives
several distinct agents.

The SDK warns once per process when it is scanning under the shared default.
Set `SHRIKE_SUPPRESS_SESSION_WARNING=1` to silence it once you have decided
the default is what you want.

### Local and self-hosted LLMs

Shrike governs the model you point it at — it does not have to be a hosted
frontier API. Local runtimes like [Ollama](https://ollama.com),
[vLLM](https://docs.vllm.ai), and LM Studio expose an OpenAI-compatible
endpoint, so `ShrikeOpenAI` guards them by forwarding a `baseURL` through
`openaiOptions`:

```typescript
import { ShrikeOpenAI } from 'shrike-guard/openai';

// Ollama serving llama3 locally, governed by Shrike before every call
const client = new ShrikeOpenAI({
  apiKey: 'ollama', // local servers ignore the value
  shrikeApiKey: 'shrike-...', // governance still runs server-side
  openaiOptions: { baseURL: 'http://localhost:11434/v1' },
});

const response = await client.chat.completions.create({
  model: 'llama3',
  messages: [{ role: 'user', content: 'Summarize this ticket…' }],
});
```

The same pattern works for Anthropic-compatible gateways via
`anthropicOptions.baseURL`. For Gemini, use the `baseUrl` option (added in
4.0.5), applied as `httpOptions.baseUrl` on the `@google/genai` client:

```typescript
import { ShrikeGemini } from 'shrike-guard/gemini';

const client = new ShrikeGemini({
  apiKey: '…',
  shrikeApiKey: 'shrike-...',
  baseUrl: 'https://your-gemini-gateway.example',
});
```

The prompt still leaves your process to reach the Shrike backend for scanning;
the *model call* stays on your local/self-hosted endpoint.

## Scanning agent actions (shell commands, SQL, web search, RAG, MCP tools)

Scanning the prompt protects the model. It does not protect the shell. An agent
that was never told anything malicious can still be talked into running
`curl … | sh` by a poisoned README, and the prompt scan has no view of that.

`ScanClient` exposes a method per action channel. Call the one that matches
what the agent is about to do, before it does it:

| Channel | Method | Screens for |
|---|---|---|
| Shell command | `scanCommand(command, cwd?)` | destructive commands, data exfiltration, credential dumps, embedded SQL injection |
| SQL query | `scanSql(query, database?, allowDestructive?)` | SQL injection, unauthorized destructive statements |
| File path | `scanFile(path)` | path traversal, writes outside the working tree |
| File content | `scanFile(path, content)` | secrets, credentials, PII before they land on disk |
| Web search | `scanWebSearch(query)` | searches that acquire attack tooling, credentials, or evasion tradecraft |
| RAG context | `scanRagContext(chunks, query?)` | indirect prompt injection in retrieved documents |
| Agent message | `scanA2AMessage(message, options?)` | instructions smuggled between agents |
| Agent card | `scanAgentCard(card, verifySignature?)` | capability misrepresentation in A2A discovery |
| MCP tool schema | `scanMcpSchema(name, description, inputSchema?)` | tool poisoning in `tools/list` responses |

```typescript
import { ScanClient } from 'shrike-guard';

const scanner = new ScanClient({ apiKey: 'shrike-...' });

// Before shelling out
const cmd = await scanner.scanCommand('psql -c "SELECT * FROM users"', '/srv/app');
if (!cmd.safe) throw new Error(`Refused: ${cmd.reason}`);

// Before querying
const sql = await scanner.scanSql('SELECT * FROM users WHERE id = $1', 'postgres');

// Before writing
const write = await scanner.scanFile('/tmp/config.py', 'api_key = "sk-..."');

// Before searching the web
const search = await scanner.scanWebSearch('sql injection prevention owasp');
```

A shell command is not one thing. `scanCommand` decomposes it, so SQL passed to
`psql -c`, `mysql -e`, or a heredoc is scanned as SQL rather than as an opaque
string of shell text.

### Indirect prompt injection in RAG pipelines

Retrieved chunks are text somebody else wrote. They are the standard carrier for
indirect prompt injection: the user asks nothing unusual, the document tells the
model what to do, and the model complies. Scan on the way in, not after the
model has acted:

```typescript
const chunks = await vectorStore.similaritySearch(userQuery, 5);

const verdict = await scanner.scanRagContext(
  chunks.map((c) => c.pageContent),
  userQuery,
);

if (!verdict.safe) {
  // The retrieved context is hostile, not the user's question.
  console.warn(`Poisoned context: ${verdict.reason}`);
}
```

### MCP tool poisoning

An MCP tool description is read by the model as guidance. A hostile server can
put instructions in the `description` field of a tool that never executes, and
the agent will act on them at registration time. Screen every entry of a
`tools/list` response from a server you do not control:

```typescript
const { tools } = await mcpClient.listTools();

for (const tool of tools) {
  const verdict = await scanner.scanMcpSchema(
    tool.name,
    tool.description ?? '',
    tool.inputSchema,
  );
  if (!verdict.safe) {
    console.warn(`Not registering ${tool.name}: ${verdict.reason}`);
    continue;
  }
  register(tool);
}
```

Screening happens once per tool at registration, not on every call.

## Who is answerable: `content_origin`

Every verdict carries `content_origin`, which says where the scanned content
came from. It answers the question a verdict alone cannot: *was that my prompt,
or the agent acting on its own?*

| Value | Meaning |
|---|---|
| `human_prompt` | the operator typed it |
| `agent_output` | the model generated it |
| `agent_action` | the agent is about to do it (every act-plane channel) |
| `third_party` | it arrived from outside: a tool result, a retrieved document, a peer agent |

```typescript
import { attributableToOperator } from 'shrike-guard';

const verdict = await scanner.scanRagContext(chunks);

if (!verdict.safe) {
  if (attributableToOperator(verdict.content_origin)) {
    showUser(`Your request was blocked: ${verdict.reason}`);
  } else {
    // The agent poisoned its own context. Telling the user "your request
    // was blocked" would be both wrong and unhelpful.
    log.warn('agent-side refusal', verdict.reason);
    retryWithCleanContext();
  }
}
```

Unknown content types resolve to `agent_action`, never to `human_prompt`:
attributing an unattributable action to the operator is the one error that is
never safe to make by default.

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
  - Google Gen AI SDK (`@google/genai`) `>=1.0.0`

## Environment Variables

```bash
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export SHRIKE_API_KEY="shrike-..."
export SHRIKE_ENDPOINT="https://your-shrike-instance.com"
export SHRIKE_AGENT_ID="ingest"                 # names this process's agent; see Sessions
export SHRIKE_SUPPRESS_SESSION_WARNING=1        # once you have decided the shared session is right
```

## Scope and Limitations

| Scanned | Not Scanned |
|---------|-------------|
| Input prompts (user messages) | Streaming output from LLM |
| Multi-modal text content | Image/audio content |
| SQL queries | Non-chat API calls |
| File paths and content | |
| Shell commands | |
| Web search queries | |
| Retrieved RAG context | |
| Agent-to-agent messages and agent cards | |
| MCP tool schemas | |

### Why Pre-Execution Scanning?

Shrike Guard focuses on **pre-flight protection** — evaluating a prompt before it
reaches the LLM, and an action before it runs. This:
- Prevents prompt injection attacks at the source
- Has zero latency impact on LLM responses
- Puts the decision point before the side effect, where refusing still costs nothing

An action already taken cannot be un-taken by detecting it afterwards. That is the
distinction between this and after-the-fact monitoring: the verdict arrives while
refusing is still free.

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
| **Coding agents that shell out** | `scanCommand` before every `exec`. Destructive commands, exfiltration, and SQL smuggled through `psql -c` are caught before the process starts. |
| **Internal RAG pipeline** | `scanRagContext` on retrieved chunks for indirect prompt injection, plus PII leakage on the query. |
| **MCP clients** | `scanMcpSchema` on every `tools/list` entry from a server you do not control, to catch tool poisoning at registration. |
| **Multi-agent systems** | `scanA2AMessage` and `scanAgentCard` for instructions smuggled between agents. |
| **Agent orchestration** | Scan every tool call and LLM request in your LangChain/LangGraph/CrewAI/AutoGen pipeline. |

## How This Differs From a Prompt Scanner

If you are evaluating TypeScript or JavaScript AI security SDKs, this is the
distinction worth testing against your own workload.

Most guardrail libraries answer one question: **is this text hostile?** They read
the prompt, and sometimes the response. That is necessary, and Shrike Guard does
it through a 9-layer cascade with PII redaction and multi-turn session
correlation.

But an autonomous agent does not cause harm by saying something. It causes harm
by *doing* something: running a command, writing a file, querying a database,
calling a tool. Shrike Guard scans those too, before they execute:

- **A verdict per action channel** — shell commands, SQL, file writes, web
  searches, RAG context, agent-to-agent messages, agent cards, MCP tool schemas.
  See [Scanning agent actions](#scanning-agent-actions-shell-commands-sql-web-search-rag-mcp-tools).
- **Pre-execution, not after the fact.** The verdict arrives while refusing is
  still free. An action already taken cannot be un-taken by detecting it.
- **Provenance on every verdict** (`content_origin`) — whether a human typed it,
  the model wrote it, the agent is about to do it, or it arrived from outside.
- **A governance contract, not just a boolean** — `refuse_tier`
  (allow / warn / require_approval / block), a `recovery` block telling the agent
  how to proceed legitimately, and `session_state`. Present on safe verdicts too.
- **Drop-in wrappers** for OpenAI, Anthropic, and Gemini, so the prompt-scanning
  half needs no code changes.
- **Free tier with no API key**, and an Apache 2.0 client you can read.

## License

Apache 2.0

## Support

- [Shrike](https://shrikesecurity.com) — Sign up, dashboard, docs
- [Documentation](https://shrikesecurity.com/docs) — Quick start, API reference
- [GitHub Issues](https://github.com/Shrike-Security/shrike-guard-js/issues) — Bug reports
- [MCP Server](https://github.com/Shrike-Security/shrike-mcp) — For MCP/agent integration
- [Python SDK](https://github.com/Shrike-Security/shrike-guard-python) — Python equivalent
