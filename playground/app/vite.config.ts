import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Playground server port. Override at boot if :3000 is taken by another dev
// server (pay-web-ui, etc.) — e.g. `PLAYGROUND_PORT=3050 pnpm dev`.
const PLAYGROUND_PORT = process.env.PLAYGROUND_PORT || '3000'
const target = `http://localhost:${PLAYGROUND_PORT}`

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Long-lived NDJSON stream — disable proxy timeout so the pay
      // session can take its time settling on-chain. Without this, Vite's
      // default proxy timeout aborts the response and the browser shows
      // "Load failed" with no detail.
      '/api/v1/sessions/gemini': {
        target,
        changeOrigin: true,
        timeout: 0,
        proxyTimeout: 0,
      },
      '/api': target,
      '/x402': target,
      '/facilitator': target,
      '/sessions': target,
      '/mpp': target,
    },
  },
})
