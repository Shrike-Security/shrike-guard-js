// SDK version — derived from package.json at build time (tsup/esbuild inlines
// the JSON literal, resolveJsonModule is on), so it can never drift from the
// published version. It was previously a hardcoded '1.5.0' that fell out of
// sync with package.json (4.0.2) and mis-stamped X-Shrike-SDK-Version on every
// scan. Guarded by tests/unit/version.test.ts. Mirrors the Python SDK, which
// derives __version__ from installed distribution metadata.
import { version } from '../package.json';

export const VERSION: string = version;
