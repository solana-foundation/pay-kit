import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { colors } from './utils.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

/** Result of trying to spawn the `pay` CLI as a sessions sidecar. */
export interface SidecarHandle {
  url: string | null
  reason: 'spawned' | 'not-installed' | 'failed' | 'disabled'
  detail?: string
  process?: ChildProcess
}

/** Probe `which pay` so we can show a helpful banner if absent. */
function findPay(): string | null {
  const candidates = [
    process.env.PAY_CLI_PATH,
    '/opt/homebrew/bin/pay',
    '/usr/local/bin/pay',
    '/usr/bin/pay',
  ].filter((v): v is string => !!v)
  for (const c of candidates) {
    if (existsSync(c)) return c
  }
  return null
}

/**
 * Start the `pay` CLI as a sidecar serving the bundled sessions config.
 *
 * Returns the sidecar URL once it is responding to a health probe, or a
 * structured reason describing why it could not start. The playground server
 * proxies `/sessions/*` to this URL; if it's null, the Sessions page shows
 * an install banner.
 */
export async function startSessionsSidecar(): Promise<SidecarHandle> {
  if (process.env.PLAYGROUND_DISABLE_SIDECAR === '1') {
    return { url: null, reason: 'disabled' }
  }

  const bin = findPay()
  if (!bin) {
    return {
      url: null,
      reason: 'not-installed',
      detail: 'The `pay` CLI is not on PATH. Install it with `brew install pay` to enable Sessions.',
    }
  }

  const configPath = path.resolve(__dirname, '..', 'sidecar', 'sessions.yml')
  if (!existsSync(configPath)) {
    return { url: null, reason: 'failed', detail: `Sidecar config missing at ${configPath}` }
  }

  const port = Number(process.env.SIDECAR_PORT ?? '18402')
  const args = ['--sandbox', 'server', 'start', configPath, '--port', String(port)]

  const proc = spawn(bin, args, {
    env: { ...process.env, RUST_LOG: 'warn' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })

  proc.stdout?.on('data', (chunk: Buffer) => process.stdout.write(colors.dim(`[pay] ${chunk}`)))
  proc.stderr?.on('data', (chunk: Buffer) => process.stderr.write(colors.dim(`[pay] ${chunk}`)))

  const exited = new Promise<{ code: number | null }>((resolve) =>
    proc.once('exit', (code) => resolve({ code })),
  )

  const url = `http://127.0.0.1:${port}`
  // Probe the sidecar for up to 5 seconds.
  const deadline = Date.now() + 5000
  while (Date.now() < deadline) {
    if (proc.exitCode !== null) {
      const code = (await exited).code
      return {
        url: null,
        reason: 'failed',
        detail: `Sidecar exited with code ${code} before becoming ready.`,
      }
    }
    try {
      const res = await fetch(`${url}/health`, { signal: AbortSignal.timeout(750) })
      if (res.ok) return { url, reason: 'spawned', process: proc }
    } catch {
      /* keep trying */
    }
    await new Promise((r) => setTimeout(r, 250))
  }

  // Probe failed but the process is alive — return as spawned anyway since
  // the route might just lack a /health endpoint.
  if (proc.exitCode === null) {
    return { url, reason: 'spawned', process: proc, detail: 'health probe timed out — sidecar may still be starting' }
  }

  return { url: null, reason: 'failed', detail: 'Sidecar did not become ready within 5s.' }
}

/** Best-effort graceful shutdown. */
export function stopSidecar(handle: SidecarHandle): void {
  if (handle.process && handle.process.exitCode === null) {
    try {
      handle.process.kill('SIGTERM')
    } catch {
      /* ignore */
    }
  }
}
