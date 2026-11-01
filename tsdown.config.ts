import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: ['src/index.ts'],
  format: 'esm',
  sourcemap: true,
  clean: true,
  // The Action runs from the committed dist with no node_modules, so dependencies must be inlined.
  noExternal: [/^@actions\//],
})
