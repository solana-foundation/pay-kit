import { useMemo, useRef, useState } from 'react'
import { GeminiRequestCard } from '../components/gemini/GeminiRequestCard'
import {
  applyDemoEvent,
  createDemoSessionId,
  initialDemoResponse,
  isAbortError,
  readDemoStream,
} from '../lib/gemini/state'
import type { GeminiDemoResponse, RunState, VoucherState } from '../lib/gemini/types'

export function Sessions({ onBalanceChange }: { onBalanceChange?: () => void }) {
  void onBalanceChange
  const [runState, setRunState] = useState<RunState>('idle')
  const [response, setResponse] = useState<GeminiDemoResponse | null>(null)
  const [voucher, setVoucher] = useState<VoucherState | null>(null)
  const abortRef = useRef<AbortController | null>(null)
  const demoSessionIdRef = useRef(createDemoSessionId())

  const events = useMemo(() => response?.paymentEvents ?? [], [response])
  const currentVoucher = response?.voucher ?? voucher
  const canRun = runState !== 'running'

  async function run() {
    if (!canRun) return
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller

    setRunState('running')
    setResponse(initialDemoResponse(voucher))

    let terminalState: RunState | null = null

    try {
      const res = await fetch('/api/v1/sessions/gemini', {
        body: JSON.stringify({ demoSessionId: demoSessionIdRef.current }),
        headers: { 'content-type': 'application/json' },
        method: 'POST',
        signal: controller.signal,
      })
      const streamBody = await demoStreamBody(res)
      await readDemoStream(streamBody, async (streamEvent) => {
        if (streamEvent.type === 'done') terminalState = 'success'
        if (streamEvent.type === 'error') terminalState = 'error'
        if (streamEvent.type === 'voucher') setVoucher(streamEvent.voucher)
        setResponse((current) => applyDemoEvent(current, streamEvent))
      })
      setRunState((state) => (state === 'running' ? (terminalState ?? 'success') : state))
    } catch (error) {
      if (isAbortError(error)) return
      const raw = error instanceof Error ? error.message : 'Request failed.'
      // Safari surfaces any network failure as a bare "Load failed". Translate
      // it into something actionable — the most likely cause is the playground
      // server being down, or the NDJSON stream hitting the proxy's idle
      // timeout while the pay proxy retries an on-chain settlement.
      const friendly =
        raw === 'Load failed' || raw === 'Failed to fetch' || raw.includes('NetworkError')
          ? 'Stream interrupted. Common causes: the playground server is not running on :3000, or the `pay` proxy at :1402 is hung retrying a failed settlement — check the proxy logs for the underlying error.'
          : raw
      setResponse((current) => ({
        ...(current ?? {}),
        error: friendly,
      }))
      setRunState('error')
    } finally {
      if (abortRef.current === controller) abortRef.current = null
    }
  }

  function reset() {
    abortRef.current?.abort()
    abortRef.current = null
    demoSessionIdRef.current = createDemoSessionId()
    setResponse(null)
    setVoucher(null)
    setRunState('idle')
  }

  return (
    <>
      <div className="page-head">
        <span className="path">Realtime LLM token billing</span>
        <span className="desc">μUSD precision — paid stream through a local Pay session proxy</span>
      </div>

      <div className="banner">
        Requires a <code>pay</code> proxy on <code>127.0.0.1:1402</code> that forwards to{' '}
        <code>generativelanguage.googleapis.com</code>. Start it with <code>pay --sandbox proxy</code> (or the
        debugger gateway). The Gemini SDK call flows through the proxy; the session client opens a payment channel,
        meters tokens in μUSD, and commits vouchers as the stream arrives.
      </div>

      <div className="gemini-page">
        <GeminiRequestCard
          canRun={canRun}
          events={events}
          onReset={reset}
          onRun={run}
          response={response}
          runState={runState}
          voucher={currentVoucher}
        />
      </div>
    </>
  )
}

async function demoStreamBody(response: Response): Promise<ReadableStream<Uint8Array>> {
  const contentType = response.headers.get('content-type') ?? ''
  if (response.ok && response.body && contentType.includes('application/x-ndjson')) return response.body
  const payload = (await response.json().catch(() => null)) as { error?: string } | null
  throw new Error(payload?.error ?? `Request failed with ${response.status}`)
}
