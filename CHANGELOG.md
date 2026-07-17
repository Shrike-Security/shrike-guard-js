# Changelog

## [4.0.3] - 2026-07-17

### Fixed
- **`X-Shrike-SDK-Version` header now reports the real version.** `version.ts` shipped a hardcoded `VERSION = '1.5.0'` that had drifted from `package.json`, so every scan stamped the audit header `1.5.0` regardless of the installed version. `VERSION` is now derived from `package.json` at build time (matching the Python SDK, which reads distribution metadata) and guarded by `tests/unit/version.test.ts` so it can't drift again.
- **README Gemini setup corrected.** The install snippet said `npm install @google/generative-ai` (the legacy package) while the wrapper requires `@google/genai`; following the README broke Gemini setup. Updated the install command and the compatibility note to `@google/genai >=1.0.0`.

## [4.0.2] - 2026-07-16

### Security
- **Fail-open verdicts now carry `degraded: true` on every provider wrapper.** Previously the OpenAI, Anthropic, and Gemini wrappers returned a plain allow verdict when `failMode: 'open'` was set and the backend was unreachable, so a caller could not distinguish "scanned and clean" from "not scanned, enforcement skipped." All fail-open returns now route through a single `failOpenResult()` constructor, and `degraded?: boolean` is part of the exported `ScanResult` type. The default remains fail-**closed**; this affects only callers who explicitly opt into fail-open.

### Fixed
- **Gemini wrapper now works against `@google/genai`.** It previously required `@google/genai` but instantiated the legacy `@google/generative-ai` class (`GoogleGenerativeAI`) and called `getGenerativeModel()`, so it threw at construction against the package it declared. Migrated to the current v2 SDK surface (`GoogleGenAI` + `ai.models.generateContent(...)` / `ai.chats.create(...)`); the public `getGenerativeModel().generateContent()` facade is unchanged. Dependency raised to `@google/genai >=1.0.0` (tested against 2.12). Added a real-package shape test so an SDK rename can't silently ship broken again.
- Corrected the `ShrikeScanError` docstring, which incorrectly described `fail_mode='open'` as the default. The default is `fail_mode='closed'` (secure by default across the 4.x line) — behavior unchanged; documentation-only. (Supersedes the unreleased 4.0.1.)

## [4.0.0] - 2026-07-13

### Version alignment (no breaking changes)
All Shrike client surfaces — MCP server (`shrike-mcp`), TypeScript SDK, and Python SDK — now share a single version line starting at 4.0.0. The major-version jump from 1.5.0 signals the alignment, not an API break: every 1.5.0 program runs unchanged on 4.0.0.

### Added
- **Client-side auto-chunk for large inputs.** Prompts over 20KB are automatically split on natural boundaries (paragraph → line → hard cut) into ~8KB chunks and scanned sequentially with fail-fast on the first blocking verdict. Applies to `ScanClient.scan()`. New `chunker` module exports `AUTO_CHUNK_THRESHOLD`, `CHUNK_TARGET_SIZE`, `chunkContent()`, and `aggregateChunkResults()` for callers who want to drive chunking directly.
- **Aggregation contract:** worst-action wins across chunks; violations dedup by (threat_type, severity, action); `session_state` from the last scanned chunk; `recovery` from the first blocking chunk.

### Why
Large single-shot scan inputs (agent transcripts, RAG context dumps, file contents) previously rode through the cascade as one oversized request — slower verdicts and more LLM-layer tokens burned per scan. Chunked inputs land in the backend cascade's small-content band, which allows earlier early-exit on clean content and cheaper verdicts on both sides of the wire. Fail-fast on the first blocked chunk means a threat at the top of a large document blocks without paying to scan the rest.

## [1.5.0] - 2026-07-06

### Added
- **Resilience primitives — `CircuitBreaker`, `CircuitOpenError`, `CircuitState`, `retryWithBackoff`** (mirrors Python SDK). Three-state breaker with configurable `failureThreshold` (5), `successThreshold` (2), `timeout` (30s), and `maxHalfOpenRequests` (3). Under a partial backend outage the breaker short-circuits repeated failures fast rather than letting `fail_mode: "closed"` produce a blocked-response storm. `retryWithBackoff` treats `CircuitOpenError` as non-retryable by default.
- **`AuthClient` re-exported at package root** (previously only reachable via `shrike-guard/api`). Matches the Python SDK's placement — `import { AuthClient } from 'shrike-guard'` now works.

### Why
Cross-language SDK parity. The Python SDK ships `CircuitBreaker` + `retry_with_backoff`; this brings the TypeScript SDK to feature-equivalence so customers flipping between languages see identical failure semantics under real outage conditions.

## [1.4.0] - 2026-07-02

### Added
- **Client-side PII redaction.** `redactPII()`, `rehydratePII()`, `getRedactionSummary()`, `updatePIIPatterns()`, and `getPIIPatternCount()` exported from the root entry point. Detects and tokenizes 20+ PII types (SSN, credit card, email, phone, address, medical record, wallet, etc.) BEFORE the prompt leaves customer environment — Shrike backend never sees the raw PII.
- **`syncPIIPatterns({ endpoint, apiKey })`** — one-shot startup call fetches the canonical Presidio-derived pattern set from the Shrike backend so client-side detection stays uniform with the server-side scan. Fails safe: on any error (network / timeout / malformed) the bootstrap patterns stay in place; sync never blocks scans.
- **Backend-owned prefix contract.** The recognizer ships its client-side redaction tag (e.g. `[IP_1]`) as part of the pattern payload; the client uses it verbatim. When the backend omits the field (pre-2026-07-02 releases), the SDK derives the prefix from the threat_type. No pattern is ever silently dropped for an unmapped prefix. Adding a new backend pattern requires zero SDK changes.

### Why
Client-side redaction removes PII before it crosses the network to Shrike's backend — defense-in-depth for HIPAA / PCI / GLBA / CMMC workloads on top of the BAA/DPA that already covers transmission. The `syncPIIPatterns` step keeps client patterns in step with backend patterns without shipping SDK updates every time Presidio adds a recognizer.

### Fixed
- gemini-client test mock import matches the runtime `@google/genai` package (upstream renamed from `@google/generative-ai`).

## [1.1.0] - 2026-02-19

### Added
- "What Shrike Detects" section in README: 86+ rules across 6 compliance frameworks
- CHANGELOG.md

### Changed
- Updated backend tier description: all tiers now get full 9-layer cascade (L1-L8)

## [1.0.1] - 2026-01-20

### Fixed
- Minor bug fixes and documentation updates

## [1.0.0] - 2026-01-15

### Added
- Initial release
- Drop-in OpenAI, Anthropic, and Gemini client wrappers
- Automatic prompt scanning via Shrike backend
- Fail-open and fail-closed modes
- Subpath imports (shrike-guard/openai, /anthropic, /gemini)
- SQL injection and file scanning
- Response sanitization (IP protection)
- API management clients (auth, policies, agents, sandbox)
