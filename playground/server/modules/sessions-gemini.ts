import type { Express, Request, Response as ExpressResponse } from 'express'
import { GoogleGenAI } from '@google/genai'
import {
  createServerOpenedPaymentChannelSessionOpener,
  createSessionFetch,
  createSessionUsageMeter,
  serializeSessionCredential,
  stripRequestHeaders,
  type SessionFetchEvent,
  type SessionFetchOpenState,
} from '@solana/mpp/client'

// Ported from ~/Coding/pay-web-ui/apps/web/src/app/api/101/gemini/* — a Gemini
// SDK streaming demo routed through a local `pay` proxy. The proxy speaks the
// MPP session protocol on the front side and forwards to Gemini upstream; we
// open a payment channel, meter token-by-token billing in μUSD precision, and
// close the session on completion to receive an on-chain settlement receipt.
//
// Required at runtime:
//   - `pay --sandbox proxy --gemini` (or equivalent) listening on `:1402`.
//   - `GEMINI_DEMO_SDK_API_KEY` env var. If unset, falls back to
//     `pay-proxy-local` (the proxy may ignore or reject this).

const DEFAULT_MODEL = 'gemini-2.5-flash'
const DEFAULT_PROXY_BASE_URL = 'http://127.0.0.1:1402'
const LIVE_COMMIT_INTERVAL_MS = 1_000
// Force the route to terminate if no event reaches the client for this long.
// Without this, a hung `pay` proxy → SDK retry loop would leave the NDJSON
// connection idle long enough for Safari to surface "Load failed".
const STREAM_IDLE_TIMEOUT_MS = 15_000
const STREAM_HEARTBEAT_MS = 4_000
const GEMINI_DEMO_PROMPT =
  'Write exactly 500 words in one sentence. No title, list, line breaks, or commentary.'
const SURFNET_RPC_URL = 'https://402.surfnet.dev:8899'

interface GeminiUsage {
  candidatesTokenCount?: number
  promptTokenCount?: number
  thoughtsTokenCount?: number
  totalTokenCount?: number
}

interface PaymentEvent {
  detail: string
  label: string
  state: 'error' | 'success' | 'working'
}

interface VoucherUpdate {
  baselineCumulativeAmount?: string
  cumulativeAmount: string
  cumulativeUsdc: string
  currency: string
  decimals?: number
  deliveryId?: string
  deltaAmount?: string
  minVoucherDeltaAmount?: string
  sessionId: string
  source: 'committed' | 'local-meter'
}

interface ReceiptUpdate {
  explorerUrl: string
  transactionId: string
}

type DemoStreamEvent =
  | { type: 'meta'; model: string; proxyBaseUrl: string }
  | { type: 'payment'; event: PaymentEvent }
  | { type: 'delta'; text: string }
  | { type: 'usage'; modelVersion?: string; usage?: GeminiUsage }
  | { type: 'error'; error: string }
  | { type: 'receipt'; receipt: ReceiptUpdate }
  | { type: 'done'; model: string; modelVersion?: string; usage?: GeminiUsage }
  | { type: 'voucher'; voucher: VoucherUpdate }

type StreamEmit = (event: DemoStreamEvent) => void

export function registerSessionsGemini(app: Express): void {
  app.post('/api/v1/sessions/gemini', async (req: Request, res: ExpressResponse) => {
    const body = (req.body ?? {}) as { demoSessionId?: string }
    const demoSessionId = typeof body.demoSessionId === 'string' ? body.demoSessionId : undefined
    const model = DEFAULT_MODEL
    const proxyBaseUrl = normalizeBaseUrl(process.env.GEMINI_PROXY_BASE_URL ?? DEFAULT_PROXY_BASE_URL)

    res.setHeader('content-type', 'application/x-ndjson; charset=utf-8')
    res.setHeader('cache-control', 'no-cache, no-transform')
    res.setHeader('x-accel-buffering', 'no')
    res.flushHeaders()

    // Track last-byte-out time so a hung downstream can't leave the response
    // idle (Safari aborts idle chunked responses → "Load failed").
    let lastEmitAt = Date.now()
    let closed = false
    const emit: StreamEmit = (event) => {
      if (closed) return
      lastEmitAt = Date.now()
      res.write(`${JSON.stringify(event)}\n`)
    }
    const heartbeat = setInterval(() => {
      if (closed) return
      // Whitespace keepalive — invisible to the NDJSON line-splitter on the
      // client (lines are split on `\n`; a leading space on an empty line
      // produces an empty trimmed line that drainLines() filters out).
      res.write(' \n')
    }, STREAM_HEARTBEAT_MS)
    const idleWatchdog = setInterval(() => {
      if (closed) return
      if (Date.now() - lastEmitAt > STREAM_IDLE_TIMEOUT_MS) {
        emit({
          event: {
            detail:
              'Stream idle for >15s. The pay proxy at 127.0.0.1:1402 may be retrying a failed on-chain call — check `pay` logs for the underlying error (common cause: incompatible payment-channels program in the local validator).',
            label: 'Watchdog',
            state: 'error',
          },
          type: 'payment',
        })
        emit({ error: 'Stream idle timeout — see Events panel for details.', type: 'error' })
        closeStream()
      }
    }, 1_000)
    const closeStream = () => {
      if (closed) return
      closed = true
      clearInterval(heartbeat)
      clearInterval(idleWatchdog)
      try {
        res.end()
      } catch {
        /* already ended */
      }
    }
    req.on('close', closeStream)

    const ai = new GoogleGenAI({
      apiKey: process.env.GEMINI_DEMO_SDK_API_KEY ?? 'pay-proxy-local',
      httpOptions: {
        apiVersion: 'v1beta',
        baseUrl: proxyBaseUrl,
        timeout: 120_000,
      },
    })

    let modelVersion: string | undefined
    let usage: GeminiUsage | undefined
    let sessionOpen: SessionFetchOpenState | undefined
    let sessionBaselineCumulativeAmount: string | undefined

    const baseFetch = globalThis.fetch.bind(globalThis)
    const sessionClient = createSessionFetch({
      fetch: baseFetch,
      liveCommitIntervalMs: LIVE_COMMIT_INTERVAL_MS,
      onEvent: (event) => {
        if (event.type === 'open') {
          sessionOpen = event.open
          sessionBaselineCumulativeAmount = event.open.session.cumulativeAmount
        }
        emitSessionFetchEvent(emit, event, sessionOpen, {
          baselineCumulativeAmount: sessionBaselineCumulativeAmount,
        })
      },
      opener: createServerOpenedPaymentChannelSessionOpener({ source: demoSessionId }),
      prepareRequest: stripRequestHeaders(['x-goog-api-key']),
    })
    const meter = createSessionUsageMeter<GeminiUsage>({
      client: sessionClient,
      priceUsage: (nextUsage, context) =>
        priceGeminiUsage({
          baselineCumulativeAmount: context.baselineCumulativeAmount,
          currentCumulativeAmount: context.targetCumulativeAmount ?? context.currentCumulativeAmount,
          minVoucherDeltaAmount: context.open.challenge.request.minVoucherDelta ?? '1',
          model,
          usage: nextUsage,
        }),
    })

    emit({ model, proxyBaseUrl, type: 'meta' })

    try {
      emitPayment(emit, { detail: 'Gemini SDK stream prepared', label: 'SDK', state: 'working' })
      await meter.withPatchedFetch(async () => {
        const config = geminiGenerationConfig(model)
        const stream = await ai.models.generateContentStream({
          ...(config ? { config } : {}),
          contents: GEMINI_DEMO_PROMPT,
          model,
        })

        for await (const chunk of stream) {
          const text = chunk.text ?? ''
          if (text) emit({ text, type: 'delta' })
          if (chunk.modelVersion) modelVersion = chunk.modelVersion
          const nextUsage = formatUsage(chunk.usageMetadata)
          if (nextUsage || chunk.modelVersion) {
            usage = nextUsage ?? usage
            emit({
              ...(modelVersion ? { modelVersion } : {}),
              type: 'usage',
              ...(usage ? { usage } : {}),
            })
            if (usage) meter.recordUsage(usage)
          }
        }
      })

      await meter.flush(usage)

      let receipt: ReceiptUpdate | undefined
      try {
        receipt = await closeSessionForReceipt({ model, open: sessionOpen, proxyBaseUrl })
      } catch (error) {
        emitPayment(emit, { detail: messageFromError(error), label: 'Receipt', state: 'error' })
        return
      }
      if (receipt) {
        emit({ receipt, type: 'receipt' })
        emitPayment(emit, { detail: 'Settlement transaction submitted', label: 'Receipt', state: 'success' })
      }

      emit({
        model,
        ...(modelVersion ? { modelVersion } : {}),
        type: 'done',
        ...(usage ? { usage } : {}),
      })
    } catch (error) {
      // Surface the proxy's underlying error verbatim so users can see
      // chain-level failures (e.g. `unsupported BPF instruction` from a
      // surfpool/program mismatch) without tailing pay logs.
      emitPayment(emit, {
        detail: messageFromError(error),
        label: 'Proxy',
        state: 'error',
      })
      emit({ error: messageFromError(error), type: 'error' })
    } finally {
      closeStream()
    }
  })
}

async function closeSessionForReceipt({
  model,
  open,
  proxyBaseUrl,
}: {
  model: string
  open: SessionFetchOpenState | undefined
  proxyBaseUrl: string
}): Promise<ReceiptUpdate | undefined> {
  if (!open) return undefined
  const closeAction = await open.session.closeAction()
  const authorization = serializeSessionCredential({
    challenge: open.challenge,
    payload: closeAction,
    source: open.source,
  })
  const response = await fetch(`${proxyBaseUrl}/v1beta/models/${model}:streamGenerateContent`, {
    body: '{}',
    headers: {
      accept: 'application/json',
      authorization,
      'content-type': 'application/json',
    },
    method: 'POST',
  })
  const payload = (await response.json().catch(() => null)) as unknown
  if (!response.ok) {
    const message =
      isRecord(payload) && typeof payload.message === 'string' ? payload.message : 'Session close failed.'
    throw new Error(message)
  }
  const transactionId = transactionIdFromCloseResponse(payload)
  if (!transactionId) return undefined
  return {
    explorerUrl: surfnetTransactionReceiptUrl(transactionId),
    transactionId,
  }
}

function transactionIdFromCloseResponse(payload: unknown): string | undefined {
  if (!isRecord(payload)) return undefined
  const transactionId = (payload as Record<string, unknown>).transactionId ?? (payload as Record<string, unknown>).signature
  return typeof transactionId === 'string' && transactionId.length > 0 ? transactionId : undefined
}

// ── Stream-event helpers ──

function emitSessionFetchEvent(
  emit: StreamEmit,
  event: SessionFetchEvent,
  open: SessionFetchOpenState | undefined,
  options: { baselineCumulativeAmount?: string } = {},
): void {
  switch (event.type) {
    case 'challenge':
      emitPayment(emit, { detail: 'Session challenge received', label: 'Payment', state: 'working' })
      return
    case 'open':
      emitPayment(emit, {
        detail: `Session open ${shortId(event.open.session.channelId)}`,
        label: 'Payment',
        state: 'working',
      })
      emitVoucher(emit, event.open, event.open.session.cumulativeAmount, undefined, {
        baselineCumulativeAmount: options.baselineCumulativeAmount,
      })
      return
    case 'retry':
      emitPayment(emit, {
        detail: `Paid retry returned ${event.response.status}`,
        label: 'Proxy',
        state: event.response.ok ? 'success' : 'error',
      })
      return
    case 'watermark':
      if (open) {
        emitVoucher(emit, open, event.cumulativeAmount, event.deltaAmount, {
          baselineCumulativeAmount: options.baselineCumulativeAmount,
        })
      }
      return
    case 'commit':
      if (open) {
        emitVoucher(emit, open, event.receipt.cumulative, event.receipt.amount, {
          baselineCumulativeAmount: options.baselineCumulativeAmount,
          deliveryId: event.receipt.deliveryId,
          source: 'committed',
        })
      }
      emitPayment(emit, {
        detail: `Commit accepted ${formatReceiptAmount(event.receipt.amount, open)}`,
        label: 'Commit',
        state: 'success',
      })
      return
  }
}

function emitPayment(emit: StreamEmit, event: PaymentEvent): void {
  emit({ event, type: 'payment' })
}

function emitVoucher(
  emit: StreamEmit,
  open: SessionFetchOpenState,
  cumulativeAmount: string,
  deltaAmount = open.challenge.request.minVoucherDelta ?? '1',
  options: {
    baselineCumulativeAmount?: string
    deliveryId?: string
    source?: VoucherUpdate['source']
  } = {},
): void {
  const currency = open.challenge.request.currency
  const decimals = open.challenge.request.decimals ?? 6
  const minVoucherDeltaAmount = open.challenge.request.minVoucherDelta ?? '1'
  emit({
    type: 'voucher',
    voucher: {
      baselineCumulativeAmount: options.baselineCumulativeAmount ?? open.session.cumulativeAmount,
      cumulativeAmount,
      cumulativeUsdc: formatBaseUnits(cumulativeAmount, decimals, currency),
      currency,
      decimals,
      ...(options.deliveryId ? { deliveryId: options.deliveryId } : {}),
      deltaAmount,
      minVoucherDeltaAmount,
      sessionId: open.session.channelId,
      source: options.source ?? 'local-meter',
    },
  })
}

function formatReceiptAmount(amount: string, open: SessionFetchOpenState | undefined): string {
  if (!open) return amount
  return formatBaseUnits(amount, open.challenge.request.decimals ?? 6, open.challenge.request.currency)
}

// ── Gemini metering (ported) ──

interface UnitPrice {
  microUsdPerUnit: number
  tokensPerUnit: number
}

function geminiMeter(model: string): { input: UnitPrice; output: UnitPrice } {
  if (model.includes('gemini-2.5-flash-lite') || model.includes('gemini-2.0-flash')) {
    return {
      input: { microUsdPerUnit: 1, tokensPerUnit: 10 },
      output: { microUsdPerUnit: 2, tokensPerUnit: 5 },
    }
  }
  if (model.includes('gemini-2.5-pro')) {
    return {
      input: { microUsdPerUnit: 5, tokensPerUnit: 4 },
      output: { microUsdPerUnit: 10, tokensPerUnit: 1 },
    }
  }
  return {
    input: { microUsdPerUnit: 3, tokensPerUnit: 10 },
    output: { microUsdPerUnit: 5, tokensPerUnit: 2 },
  }
}

function tokenPriceAmount(tokens: number, price: UnitPrice): bigint {
  const units = Math.ceil(tokens / price.tokensPerUnit)
  return BigInt(units) * BigInt(price.microUsdPerUnit)
}

function priceGeminiUsage({
  baselineCumulativeAmount,
  currentCumulativeAmount,
  minVoucherDeltaAmount,
  model,
  usage,
}: {
  baselineCumulativeAmount: string
  currentCumulativeAmount: string
  minVoucherDeltaAmount: string
  model: string
  usage: GeminiUsage
}): { cumulativeAmount: string; deltaAmount: string } | null {
  const meter = geminiMeter(model)
  const inputTokens = usage.promptTokenCount ?? 0
  const meteredOutputTokens = Math.max(0, (usage.totalTokenCount ?? 0) - inputTokens)
  const outputTokens = Math.max(usage.candidatesTokenCount ?? 0, meteredOutputTokens)
  const rawAmount = tokenPriceAmount(inputTokens, meter.input) + tokenPriceAmount(outputTokens, meter.output)
  const minDelta = parsePositiveBigInt(minVoucherDeltaAmount) ?? BigInt(1)
  const roundedAmount = rawAmount === BigInt(0) ? BigInt(0) : roundUp(rawAmount, minDelta)
  const baseline = parseBigIntOrZero(baselineCumulativeAmount)
  const current = parseBigIntOrZero(currentCumulativeAmount)
  const cumulativeAmount = baseline + roundedAmount
  const deltaAmount = cumulativeAmount > current ? cumulativeAmount - current : BigInt(0)
  if (deltaAmount === BigInt(0)) return null
  return { cumulativeAmount: cumulativeAmount.toString(), deltaAmount: deltaAmount.toString() }
}

function geminiGenerationConfig(model: string) {
  if (model.includes('gemini-2.5-flash')) {
    return { thinkingConfig: { includeThoughts: false as const, thinkingBudget: 0 as const } }
  }
  return undefined
}

// ── Formatting helpers ──

function formatUsage(usage: unknown): GeminiUsage | undefined {
  if (!isRecord(usage)) return undefined
  const u = usage as Record<string, unknown>
  const out: GeminiUsage = {}
  if (typeof u.candidatesTokenCount === 'number') out.candidatesTokenCount = u.candidatesTokenCount
  if (typeof u.promptTokenCount === 'number') out.promptTokenCount = u.promptTokenCount
  if (typeof u.thoughtsTokenCount === 'number') out.thoughtsTokenCount = u.thoughtsTokenCount
  if (typeof u.totalTokenCount === 'number') out.totalTokenCount = u.totalTokenCount
  return out
}

function normalizeBaseUrl(url: string): string {
  return url.endsWith('/') ? url.slice(0, -1) : url
}

function shortId(value: string): string {
  return `${value.slice(0, 4)}...${value.slice(-4)}`
}

function formatBaseUnits(amount: string, decimals: number, currency: string): string {
  try {
    const value = BigInt(amount)
    const scale = BigInt(10) ** BigInt(decimals)
    const whole = value / scale
    const fractional = (value % scale).toString().padStart(decimals, '0')
    return `${whole.toString()}.${fractional} ${currencyLabel(currency)}`
  } catch {
    return `${amount} ${currencyLabel(currency)}`
  }
}

function currencyLabel(currency: string): string {
  return currency.length > 12 ? 'USDC' : currency
}

function messageFromError(error: unknown): string {
  if (error instanceof Error) return error.message
  return 'Gemini proxy request failed.'
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null
}

function parseBigIntOrZero(value: string): bigint {
  try {
    return BigInt(value)
  } catch {
    return BigInt(0)
  }
}

function parsePositiveBigInt(value: string): bigint | undefined {
  try {
    const parsed = BigInt(value)
    return parsed > BigInt(0) ? parsed : undefined
  } catch {
    return undefined
  }
}

function roundUp(value: bigint, step: bigint): bigint {
  const remainder = value % step
  return remainder === BigInt(0) ? value : value + step - remainder
}

function surfnetTransactionReceiptUrl(transactionId: string): string {
  const params = new URLSearchParams({
    cluster: 'custom',
    customUrl: SURFNET_RPC_URL,
    view: 'receipt',
  })
  return `https://explorer.solana.com/tx/${transactionId}?${params.toString()}`
}
