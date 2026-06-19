import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// API the UI talks to. PAYKIT_PLAYGROUND_API_URL points the proxy at an
// already-running playground API (local or remote) instead of the one
// `pnpm dev` launches. Otherwise the local API port comes from
// PLAYGROUND_PORT — override at boot if :3000 is taken by another dev
// server (pay-web-ui, etc.) — e.g. `PLAYGROUND_PORT=3050 pnpm dev`.
const PLAYGROUND_PORT = process.env.PLAYGROUND_PORT || '3000'
const target = process.env.PAYKIT_PLAYGROUND_API_URL || `http://localhost:${PLAYGROUND_PORT}`

export default defineConfig({
  plugins: [react()],
  // `@solana/pay-kit` (+ `@solana/mpp`, `@x402/*`) are local `file:` deps whose
  // content changes faster than their version, so Vite's dep cache goes stale.
  // Re-optimize on every dev start while they're vendored locally; drop this
  // once they're published to npm.
  optimizeDeps: { force: true },
  server: {
    port: 5173,
    proxy: {
      '/openapi.json': target,
      '/api': target, // priced routes (/api/v1/*) + meta (health, faucet, docs)
      '/sessions': target, // session receipt poll
      '/__402': target, // session delivery side-channel
    },
  },
})
