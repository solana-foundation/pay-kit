import { Mppx, solana } from '@solana/mpp/client'
import { createPaymentChannelSessionOpener, createSessionFetch, type SessionFetchClient } from '@solana/mpp/client'
import { getSigner, RPC_URL } from './wallet'
import type { FlowProgress } from '../types'

// Capture the native fetch BEFORE Mppx.create() runs anywhere — Mppx polyfills
// globalThis.fetch by default, which would otherwise hijack the session client's
// 402 retry and throw "No method found for challenges: solana.session" because
// the charge/subscription Mppx instances don't register the session method.
const nativeFetch: typeof globalThis.fetch = globalThis.fetch.bind(globalThis)

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
let sessionFetch: SessionFetchClient | null = null
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

let lastSessionChannelId: string | null = null

function getSessionFetch(): SessionFetchClient {
  if (!sessionFetch) {
    sessionFetch = createSessionFetch({
      // Use the captured-at-module-load native fetch so Mppx's polyfill of
      // globalThis.fetch (installed when charge/subscription Mppx instances
      // construct) doesn't intercept and misdispatch our session 402s.
      fetch: nativeFetch,
      // Real payment-channel opens: the wallet keypair pre-signs the open
      // transaction (deposit comes from its airdropped USDC) and the server
      // completes + broadcasts it. The signer only exists after onboarding,
      // so resolve it lazily per open.
      opener: async args => {
        const signer = await getSigner()
        return createPaymentChannelSessionOpener({ rpcUrl: RPC_URL, signer })(args)
      },
      onEvent: (event) => {
        switch (event.type) {
          case 'challenge':
            progressCallback?.({
              type: 'challenge',
              amount: event.challenge.request.cap,
              currency: event.challenge.request.currency,
              recipient: event.challenge.request.recipient,
              decimals: event.challenge.request.decimals,
            })
            break
          case 'open':
            lastSessionChannelId = event.open.session.channelId
            break
          case 'watermark':
            progressCallback?.({
              type: 'voucher',
              cumulative: event.cumulativeAmount,
              delta: event.deltaAmount,
            })
            break
        }
      },
    })
  }
  return sessionFetch
}

/** Poll the playground's receipt endpoint until the channel reports a settle
 * signature, or until `timeoutMs` elapses. Returns null on timeout. */
/** Pull the settle tx signature out of a base64url Payment-Receipt header. */
function receiptReference(receiptB64: string | undefined): string | null {
  if (!receiptB64) return null
  try {
    const json = JSON.parse(atob(receiptB64.replace(/-/g, '+').replace(/_/g, '/'))) as { reference?: string }
    return json.reference ?? null
  } catch {
    return null
  }
}

async function pollSessionReceipt(channelId: string, timeoutMs = 10_000): Promise<string | null> {
  const deadline = performance.now() + timeoutMs
  while (performance.now() < deadline) {
    try {
      const res = await nativeFetch(`/sessions/receipt/${encodeURIComponent(channelId)}`)
      if (res.ok) {
        const body = (await res.json()) as { settledSignature: string | null; finalized: boolean }
        if (body.settledSignature) return body.settledSignature
      }
    } catch {
      /* keep polling */
    }
    await new Promise((r) => setTimeout(r, 750))
  }
  return null
}

/** Yield `data:` payloads from an SSE byte stream, one event at a time. */
async function* readSseData(body: ReadableStream<Uint8Array>): AsyncGenerator<string> {
  const reader = body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  try {
    while (true) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += decoder.decode(value, { stream: true })
      let idx: number
      while ((idx = buffer.indexOf('\n\n')) !== -1) {
        const block = buffer.slice(0, idx)
        buffer = buffer.slice(idx + 2)
        for (const line of block.split('\n')) {
          if (line.startsWith('data: ')) yield line.slice('data: '.length)
        }
      }
    }
  } finally {
    reader.releaseLock()
  }
}

interface Options {
  /** Hint about which primitive is being exercised — picks which mppx instance to use. */
  primitive?: 'charge' | 'subscription' | 'session' | 'x402'
  /** Per-delivery price in base units (sessions only) — used as the fallback
   * voucher amount when the response doesn't carry per-chunk costs. */
  unitPrice?: string
  init?: RequestInit
}

/**
 * Runs a payment-aware fetch and emits a typed event stream that the UI can render.
 *
 * Handles charges, subscriptions (via the kit), and x402 (the kit's mppx already
 * negotiates over the challenge header). Sessions go through the kit's
 * SessionFetchClient: it opens a payment channel on the 402 challenge, then we
 * record the metered cumulative amount per delivered chunk so signed vouchers
 * are committed back to the server, and flush before reporting success.
 */
export async function* payAndFetch(url: string, opts: Options = {}): AsyncGenerator<FlowProgress> {
  const method = opts.init?.method ?? 'GET'
  yield { type: 'request', url, method }

  const queue: FlowProgress[] = []
  let wake: (() => void) | null = null
  let sawPaid = false

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
        sawPaid = true
        queue.push({ type: 'paid', signature: event.signature ?? '' })
        break
      case 'activated':
        queue.push({ type: 'activated', signature: event.signature ?? '' })
        break
      case 'voucher':
        queue.push({
          type: 'voucher',
          cumulative: String(event.cumulative ?? '0'),
          delta: String(event.delta ?? '0'),
        })
        break
      case 'signed':
        return
    }
    wake?.()
  }

  const started = performance.now()
  try {
    const fetchPromise: Promise<Response> =
      opts.primitive === 'session'
        ? // SessionFetchClient resolves its delivery-reservation URL against
          // the resource URL, so sessions need an absolute URL.
          getSessionFetch().fetch(new URL(url, location.origin).toString(), opts.init)
        : (opts.primitive === 'subscription' ? await getSubscriptionMppx() : await getChargeMppx())
            .fetch(url, opts.init)

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

        let data: unknown
        if (opts.primitive === 'session' && response.ok) {
          // Meter the delivery: report the cumulative owed amount as chunks
          // arrive so the SessionFetchClient signs vouchers and commits them
          // back to the server, then flush the final watermark.
          const client = getSessionFetch()
          const unitPrice = BigInt(opts.unitPrice ?? '0')
          let cumulative = BigInt(client.targetCumulativeAmount ?? client.cumulativeAmount)
          if ((headers['content-type'] ?? '').includes('text/event-stream') && response.body) {
            const chunks: string[] = []
            for await (const payload of readSseData(response.body)) {
              if (payload === '[DONE]') continue
              let cost = unitPrice
              try {
                const parsed = JSON.parse(payload) as { chunk?: string; cost?: string }
                if (typeof parsed.chunk === 'string') chunks.push(parsed.chunk)
                if (parsed.cost !== undefined) cost = BigInt(parsed.cost)
              } catch {
                chunks.push(payload)
              }
              if (cost > 0n) {
                cumulative += cost
                client.recordCumulative(cumulative)
              }
              // Surface the partial body so the UI renders the stream live
              // instead of waiting for the final success event.
              yield {
                type: 'chunk',
                text: chunks.join(''),
                status: response.status,
                headers,
                latencyMs: Math.round(performance.now() - started),
              }
              while (queue.length > 0) yield queue.shift()!
            }
            data = chunks.join('')
          } else {
            try {
              data = await response.clone().json()
            } catch {
              data = await response.text()
            }
            if (unitPrice > 0n) client.recordCumulative(cumulative + unitPrice)
          }
          await client.flush()
          while (queue.length > 0) yield queue.shift()!
        } else {
          try {
            data = await response.clone().json()
          } catch {
            data = await response.text()
          }
        }

        // With server-side broadcast the client never emits paying/paid —
        // the settle signature only comes back in the Payment-Receipt
        // header. Surface it so the Broadcast / Settled steps complete.
        if (response.ok && !sawPaid) {
          const signature = receiptReference(headers['payment-receipt'])
          if (signature) {
            yield { type: 'paying' }
            yield { type: 'paid', signature }
            sawPaid = true
          }
        }

        const latencyMs = Math.round(performance.now() - started)
        yield { type: 'success', data, status: response.status, headers, latencyMs }

        // For sessions, poll the playground's receipt endpoint to surface the
        // on-chain settle signature once the idle-close watchdog fires.
        if (opts.primitive === 'session' && lastSessionChannelId) {
          const channelId = lastSessionChannelId
          lastSessionChannelId = null
          const sig = await pollSessionReceipt(channelId)
          if (sig) yield { type: 'paid', signature: sig }
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
  sessionFetch = null
}
