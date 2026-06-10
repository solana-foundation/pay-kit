import type { GeminiDemoResponse, GeminiDemoStreamEvent, VoucherState } from './types'

export const GEMINI_DEMO_PROMPT =
  'Write exactly 500 words in one sentence. No title, list, line breaks, or commentary.'

export function initialDemoResponse(voucher: VoucherState | null): GeminiDemoResponse {
  return {
    paymentEvents: [],
    proxyBaseUrl: 'http://127.0.0.1:1402',
    text: '',
    ...(voucher ? { voucher } : {}),
  }
}

export function applyDemoEvent(current: GeminiDemoResponse | null, event: GeminiDemoStreamEvent): GeminiDemoResponse {
  const base: GeminiDemoResponse = current ?? { paymentEvents: [], text: '' }
  switch (event.type) {
    case 'meta':
      return { ...base, model: event.model, proxyBaseUrl: event.proxyBaseUrl }
    case 'payment':
      return { ...base, paymentEvents: [...(base.paymentEvents ?? []), event.event] }
    case 'voucher':
      return { ...base, voucher: event.voucher }
    case 'receipt':
      return { ...base, receipt: event.receipt }
    case 'delta':
      return { ...base, text: `${base.text ?? ''}${event.text}` }
    case 'usage':
      return {
        ...base,
        ...(event.modelVersion ? { modelVersion: event.modelVersion } : {}),
        ...(event.usage ? { usage: event.usage } : {}),
      }
    case 'done':
      return {
        ...base,
        model: event.model,
        ...(event.modelVersion ? { modelVersion: event.modelVersion } : {}),
        ...(event.usage ? { usage: event.usage } : {}),
      }
    case 'error':
      return { ...base, error: event.error }
  }
}

export function createDemoSessionId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(36).slice(2)}`
}

export function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === 'AbortError'
}

export async function readDemoStream(
  body: ReadableStream<Uint8Array>,
  onEvent: (event: GeminiDemoStreamEvent) => Promise<void> | void,
): Promise<void> {
  const reader = body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    buffer += decoder.decode(value, { stream: true })
    buffer = await drainLines(buffer, onEvent)
  }
  buffer += decoder.decode()
  await drainLines(`${buffer}\n`, onEvent)
}

async function drainLines(
  buffer: string,
  onEvent: (event: GeminiDemoStreamEvent) => Promise<void> | void,
): Promise<string> {
  const lines = buffer.split('\n')
  const remainder = lines.pop() ?? ''
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed) continue
    await onEvent(JSON.parse(trimmed) as GeminiDemoStreamEvent)
  }
  return remainder
}
