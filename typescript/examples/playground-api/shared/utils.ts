import type { Request as ExpressReq } from 'express'

const RESET = '\x1b[0m'
const dim = (s: string) => `\x1b[2m${s}${RESET}`
const green = (s: string) => `\x1b[32m${s}${RESET}`
const cyan = (s: string) => `\x1b[36m${s}${RESET}`
const yellow = (s: string) => `\x1b[33m${s}${RESET}`
const magenta = (s: string) => `\x1b[35m${s}${RESET}`
const red = (s: string) => `\x1b[31m${s}${RESET}`
const bold = (s: string) => `\x1b[1m${s}${RESET}`

export const colors = { dim, green, cyan, yellow, magenta, red, bold }

/** Convert an Express request to a Web API Request that the kit's mppx accepts. */
export function toWebRequest(req: ExpressReq): globalThis.Request {
  const headers = new Headers()
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue
    headers.set(key, Array.isArray(value) ? value[0]! : String(value))
  }
  const protocol = (req.headers['x-forwarded-proto'] as string | undefined) ?? req.protocol ?? 'http'
  const url = `${protocol}://${req.get('host')}${req.originalUrl}`
  const init: RequestInit = { method: req.method, headers }
  if (req.method !== 'GET' && req.method !== 'HEAD' && req.body) {
    init.body = JSON.stringify(req.body)
  }
  return new globalThis.Request(url, init)
}

/** Log a settlement-signature link for quick eyeball debugging in the terminal. */
export function logTx(path: string, reference: string): void {
  const studio = process.env.STUDIO_PORT ?? '18488'
  console.log(`  ${green('✓')} ${path}  ${dim('tx:')} ${cyan(`http://localhost:${studio}/?t=${reference}`)}`)
}

/** Log a payment receipt link for quick eyeball debugging in the terminal. */
export function logPayment(path: string, response: Response): void {
  const receipt = response.headers.get('Payment-Receipt')
  if (!receipt) return
  try {
    const json = JSON.parse(Buffer.from(receipt, 'base64url').toString()) as { reference?: string }
    if (json.reference) logTx(path, json.reference)
  } catch {
    /* Receipt format may vary — ignore */
  }
}

export async function rpcCall(rpcUrl: string, method: string, params: unknown[]): Promise<unknown> {
  const res = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    signal: AbortSignal.timeout(8000),
  })
  const data = (await res.json()) as { result?: unknown; error?: { message: string } }
  if (data.error) throw new Error(`${method}: ${data.error.message}`)
  return data.result
}
