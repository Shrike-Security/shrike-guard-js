/**
 * Guard: the SDK VERSION constant must equal package.json's version.
 *
 * VERSION is stamped as the `X-Shrike-SDK-Version` header on every scan
 * (scanner.ts). 4.0.2 shipped with a hardcoded `1.5.0` that had drifted from
 * package.json 4.0.2, so every TS-SDK scan reported the wrong version to the
 * backend. version.ts now derives from package.json; this test fails if anyone
 * reintroduces a hardcoded literal. Mirrors the Python SDK's test_version.py.
 */
import { VERSION } from '../../src/version';
import pkg from '../../package.json';

describe('SDK version stamping (X-Shrike-SDK-Version)', () => {
  it('VERSION equals package.json version — cannot drift', () => {
    expect(VERSION).toBe(pkg.version);
  });

  it('is valid semver and not the legacy hardcoded 1.5.0', () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+/);
    expect(VERSION).not.toBe('1.5.0');
  });
});
