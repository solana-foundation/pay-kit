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
      '/api': target,
      '/x402': target,
      '/facilitator': target,
      '/sessions': target,
      // SessionFetchClient's delivery-reservation side channel.
      '/__402': target,
      '/mpp': target,
    },
  },
})
