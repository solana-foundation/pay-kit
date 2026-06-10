import { Mppx, solana } from '@solana/mpp/client'
import { getSigner, RPC_URL } from './wallet'
import type { FlowProgress } from '../types'

interface ProgressEvent {
  type: string
  amount?: string
  currency?: string
  mint?: string
  recipient?: string
  feePayerKey?: string
  decimals?: number
  signature?: string
  transaction?: string
  [extra: string]: unknown
}

let chargeMppx: ReturnType<typeof Mppx.create> | null = null
let subMppx: ReturnType<typeof Mppx.create> | null = null
let progressCallback: ((e: ProgressEvent) => void) | null = null

async function getChargeMppx() {
  if (!chargeMppx) {
    const signer = await getSigner()
    const method = solana.charge({
      signer,
      rpcUrl: RPC_URL,
      onProgress: (e: unknown) => progressCallback?.(e as ProgressEvent),
    } as Parameters<typeof solana.charge>[0])
    chargeMppx = Mppx.create({ methods: [method] })
  }
  return chargeMppx
}

async function getSubscriptionMppx() {
  if (!subMppx) {
    const signer = await getSigner()
    const method = solana.subscription({
      signer,
      rpcUrl: RPC_URL,
      onProgress: (e: unknown) => progressCallback?.(e as ProgressEvent),
    } as Parameters<typeof solana.subscription>[0])
    subMppx = Mppx.create({ methods: [method] })
  }
  return subMppx
}

interface Options {
  /** Hint about which primitive is being exercised — picks which mppx instance to use. */
  primitive?: 'charge' | 'subscription' | 'session' | 'x402'
  init?: RequestInit
}

/**
 * Runs a payment-aware fetch and emits a typed event stream that the UI can render.
 *
 * Handles charges, subscriptions (via the kit), and x402 (the kit's mppx already
 * negotiates over the challenge header). Sessions go through the sidecar — for now
 * the page renders a static trace if the sidecar isn't available.
 */
export async function* payAndFetch(url: string, opts: Options = {}): AsyncGenerator<FlowProgress> {
  const method = opts.init?.method ?? 'GET'
  yield { type: 'request', url, method }

  const queue: FlowProgress[] = []
  let wake: (() => void) | null = null

  progressCallback = (event) => {
    switch (event.type) {
      case 'challenge':
        queue.push({
          type: 'challenge',
          amount: event.amount ?? '0',
          currency: event.currency ?? event.mint ?? 'USDC',
          recipient: event.recipient ?? '',
          feePayerKey: event.feePayerKey,
          decimals: event.decimals,
        })
        break
      case 'signing':
        queue.push({ type: 'signing' })
        break
      case 'paying':
        queue.push({ type: 'paying' })
        break
      case 'confirming':
        queue.push({ type: 'confirming', signature: event.signature ?? '' })
        break
      case 'paid':
        queue.push({ type: 'paid', signature: event.signature ?? '' })
        break
      case 'activated':
        queue.push({ type: 'activated', signature: event.signature ?? '' })
        break
      case 'signed':
        return
    }
    wake?.()
  }

  const started = performance.now()
  try {
    const mppx = opts.primitive === 'subscription' ? await getSubscriptionMppx() : await getChargeMppx()
    const fetchPromise = mppx.fetch(url, opts.init)

    while (true) {
      if (queue.length > 0) {
        yield queue.shift()!
        continue
      }
      const result = await Promise.race([
        fetchPromise.then((r: Response) => ({ done: true as const, response: r })),
        new Promise<{ done: false }>((r) => (wake = () => r({ done: false }))),
      ])
      if (result.done) {
        while (queue.length > 0) yield queue.shift()!
        const response = result.response
        const headers: Record<string, string> = {}
        response.headers.forEach((v, k) => (headers[k] = v))
        const latencyMs = Math.round(performance.now() - started)
        try {
          const data = await response.clone().json()
          yield { type: 'success', data, status: response.status, headers, latencyMs }
        } catch {
          const text = await response.text()
          yield {
            type: 'success',
            data: text,
            status: response.status,
            headers,
            latencyMs,
          }
        }
        return
      }
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    yield { type: 'error', message }
  } finally {
    progressCallback = null
  }
}

/** Reset cached MPP clients (call after wallet reset). */
export function resetMppxClients() {
  chargeMppx = null
  subMppx = null
}
