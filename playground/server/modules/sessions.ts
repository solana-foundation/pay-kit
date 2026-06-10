import type { Express, Request, Response } from 'express'
import type { SidecarHandle } from '../shared/sidecar.js'

/**
 * Reverse-proxy /sessions/* to the `pay` sidecar binary.
 *
 * Headers are passed through unchanged; the sidecar handles the MPP session
 * handshake, voucher verification, and metered delivery. If no sidecar is
 * running, we 503 with a structured payload the UI can render as an install
 * banner.
 */
export function registerSessions(app: Express, sidecar: SidecarHandle): void {
  if (sidecar.url) {
    app.all('/sessions/*', async (req: Request, res: Response) => {
      const target = `${sidecar.url}${req.originalUrl}`
      try {
        const init: RequestInit = {
          method: req.method,
          headers: passThroughHeaders(req),
          body: ['GET', 'HEAD'].includes(req.method) ? undefined : JSON.stringify(req.body),
        }
        const upstream = await fetch(target, init)
        res.status(upstream.status)
        upstream.headers.forEach((v, k) => res.setHeader(k, v))
        const buf = Buffer.from(await upstream.arrayBuffer())
        res.end(buf)
      } catch (err) {
        res.status(502).json({
          error: 'sidecar_unreachable',
          message: err instanceof Error ? err.message : String(err),
        })
      }
    })
    return
  }

  // No sidecar — return a structured 503 with install instructions.
  app.all('/sessions/*', (_req: Request, res: Response) => {
    res.status(503).json({
      error: 'sessions_unavailable',
      reason: sidecar.reason,
      detail: sidecar.detail ?? 'Sessions require the `pay` CLI sidecar.',
      install: 'brew install pay  # or: npm install -g @solana/pay',
    })
  })
}

function passThroughHeaders(req: Request): HeadersInit {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(req.headers)) {
    if (v === undefined) continue
    if (k === 'host' || k === 'connection' || k === 'content-length') continue
    out[k] = Array.isArray(v) ? v[0]! : String(v)
  }
  return out
}
