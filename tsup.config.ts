import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'openai/index': 'src/openai/index.ts',
    'anthropic/index': 'src/anthropic/index.ts',
    'gemini/index': 'src/gemini/index.ts',
    'api/index': 'src/api/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
});
