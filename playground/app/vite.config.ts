import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'

// API the UI talks to. PAYKIT_PLAYGROUND_API_URL points the proxy at an
// already-running playground API (local or remote) instead of the one
// `pnpm dev` launches. Otherwise the local API port comes from
// PLAYGROUND_PORT — override at boot if :3000 is taken by another dev
// server (pay-web-ui, etc.) — e.g. `PLAYGROUND_PORT=3050 pnpm dev`.
const PLAYGROUND_PORT = process.env.PLAYGROUND_PORT || '3000'
const target = process.env.PAYKIT_PLAYGROUND_API_URL || `http://localhost:${PLAYGROUND_PORT}`
const proxy = { target, changeOrigin: false }

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      crypto: fileURLToPath(new URL('./src/lib/nodeCryptoShim.ts', import.meta.url)),
    },
  },
  // `@solana/pay-kit` (+ `@solana/mpp`, `@x402/*`) are local `file:` deps whose
  // content changes faster than their version, so Vite's dep cache goes stale.
  // Re-optimize on every dev start while they're vendored locally; drop this
  // once they're published to npm.
  optimizeDeps: { force: true },
  server: {
    port: 5173,
    proxy: {
      // Preserve the browser-facing Host. x402 v2 binds PAYMENT-REQUIRED's
      // absolute resource URL to Response.url, so rewriting Host to the API's
      // internal origin makes every proxied challenge invalid.
      '/openapi.json': proxy,
      '/api': proxy, // priced routes (/api/v1/*) + meta (health, faucet, docs)
      '^/x402/': proxy, // legacy x402 demo API routes kept for compatibility
      '/__402': proxy, // session side-channels: delivery reserve + settle-receipt poll
    },
  },
})
