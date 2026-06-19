import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { RequestBuilder } from './RequestBuilder'
import { FlowTimeline } from './FlowTimeline'
import { EventLog } from './EventLog'
import { ResponsePane } from './ResponsePane'
import { CodeTabs } from './CodeTabs'
import { payAndFetch } from '../lib/flow'
import { buildUrl } from '../lib/snippets'
import type {
  Endpoint,
  FlowProgress,
  FlowStep,
  LogLine,
  Primitive,
  ResponsePayload,
} from '../types'
import { fmtUnits } from '../lib/format'

interface Props {
  endpoints: Endpoint[]
  primitive: Primitive
  /** Disabled-state notice (e.g. "install pay to enable Sessions"). */
  banner?: React.ReactNode
  /** When true, Send is disabled. */
  disabled?: boolean
  disabledReason?: string
  /** Called when a successful response is rendered (balance changed). */
  onBalanceChange?: () => void
}

function makeSteps(primitive: Primitive): FlowStep[] {
  if (primitive === 'subscription') {
    return [
      { key: 'req', label: 'Request', status: 'in-progress' },
      { key: '402', label: '402 Payment Required', status: 'pending' },
      { key: 'sign', label: 'Sign activation tx', status: 'pending' },
      { key: 'broadcast', label: 'Broadcast', status: 'pending' },
      { key: 'activate', label: 'Subscription activated', status: 'pending' },
      { key: 'ok', label: 'Resource delivered', status: 'pending' },
    ]
  }
  if (primitive === 'session') {
    return [
      { key: 'req', label: 'Open channel', status: 'in-progress' },
      { key: 'voucher', label: 'Sign vouchers', status: 'pending' },
      { key: 'deliver', label: 'Metered delivery', status: 'pending' },
    ]
  }
  return [
    { key: 'req', label: 'Request', status: 'in-progress' },
    { key: '402', label: '402 Payment Required', status: 'pending' },
    { key: 'sign', label: 'Sign USDC transfer', status: 'pending' },
    { key: 'broadcast', label: 'Broadcast', status: 'pending' },
    { key: 'settle', label: 'Settled on-chain', status: 'pending' },
    { key: 'ok', label: 'Resource delivered', status: 'pending' },
  ]
}

function nowIso(): string {
  return new Date().toISOString()
}

export function EndpointWorkbench({
  endpoints,
  primitive,
  banner,
  disabled,
  disabledReason,
  onBalanceChange,
}: Props) {
  const [searchParams, setSearchParams] = useSearchParams()
  const epId = searchParams.get('ep')
  const endpoint = useMemo<Endpoint | null>(() => {
    if (!endpoints.length) return null
    return endpoints.find((e) => e.id === epId) ?? endpoints[0] ?? null
  }, [endpoints, epId])

  const [paramValues, setParamValues] = useState<Record<string, string>>({})
  const [steps, setSteps] = useState<FlowStep[]>([])
  const [log, setLog] = useState<LogLine[]>([])
  const [response, setResponse] = useState<ResponsePayload | null>(null)
  const [running, setRunning] = useState(false)
  const [tab, setTab] = useState<'response' | 'code'>('response')
  // Which protocol to pay with when the endpoint accepts more than one.
  const [protocol, setProtocol] = useState<'mpp' | 'x402'>('mpp')
  const logId = useRef(0)
  const dual = (endpoint?.protocols?.length ?? 0) > 1

  // Reset state when the endpoint changes.
  useEffect(() => {
    setParamValues({})
    setSteps([])
    setLog([])
    setResponse(null)
    setRunning(false)
    setProtocol(endpoint?.protocols?.includes('mpp') ? 'mpp' : endpoint?.protocols?.[0] ?? 'mpp')
  }, [endpoint?.id])

  // If the URL doesn't pin an endpoint, set the first one as the default.
  useEffect(() => {
    if (!epId && endpoint && endpoints.length > 0) {
      setSearchParams({ ep: endpoint.id }, { replace: true })
    }
  }, [epId, endpoint, endpoints, setSearchParams])

  const pushLog = useCallback(
    (message: string, kind: LogLine['kind'], detail?: string, link?: LogLine['link']) => {
      // Compute the entry (incl. its id) outside the updater so `setLog` stays
      // pure — a nested setState here would double-fire under StrictMode and
      // log every line twice.
      const entry: LogLine = { id: logId.current++, ts: nowIso(), message, kind, detail, link }
      setLog((prev) => [...prev, entry])
    },
    [],
  )

  const advance = useCallback(
    (key: string, status: FlowStep['status'], ts?: string) => {
      setSteps((prev) =>
        prev.map((s) => (s.key === key ? { ...s, status, ts: ts ?? s.ts ?? nowIso() } : s)),
      )
    },
    [],
  )

  const handleSend = async () => {
    if (!endpoint || running || disabled) return
    setRunning(true)
    setResponse(null)
    setSteps(makeSteps(primitive))
    const url = buildUrl(endpoint, paramValues)
    pushLog(`${endpoint.method} ${url}`, 'req')

    try {
      for await (const step of runFlow(endpoint, url, paramValues, primitive, dual ? protocol : undefined)) {
        handleProgress(step, advance, pushLog, setResponse)
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      pushLog(`Error: ${msg}`, 'error')
      setResponse({ kind: 'error', message: msg })
    } finally {
      setRunning(false)
      onBalanceChange?.()
    }
  }

  const handleReset = () => {
    setSteps([])
    setLog([])
    setResponse(null)
  }

  if (!endpoint) {
    return (
      <div style={{ padding: 24, color: 'var(--fg-muted)', fontSize: 13 }}>
        No endpoints registered for this primitive.
      </div>
    )
  }

  return (
    <>
      <div className="page-head">
        <span className={`method ${endpoint.method}`}>{endpoint.method}</span>
        <span className="path">{endpoint.path}</span>
        <span className="desc">{endpoint.description}</span>
        {dual && (
          <div className="protocol-toggle" role="group" aria-label="Payment protocol">
            {endpoint.protocols!.map((p) => (
              <button
                key={p}
                type="button"
                className={`protocol-opt${protocol === p ? ' active' : ''}`}
                onClick={() => setProtocol(p)}
                disabled={running}
              >
                {p}
              </button>
            ))}
          </div>
        )}
        <span className={`cost${endpoint.cost === 'free' ? ' free' : ''}`}>{endpoint.cost}</span>
      </div>

      {banner}

      <RequestBuilder
        endpoint={endpoint}
        paramValues={paramValues}
        onParamChange={(name, value) => setParamValues((prev) => ({ ...prev, [name]: value }))}
        onSend={handleSend}
        onReset={handleReset}
        running={running}
        disabled={disabled}
        disabledReason={disabledReason}
      />

      <div className="trace">
        <div className="trace-flow">
          <FlowTimeline
            steps={steps}
            failed={response?.kind === 'error'}
            success={response !== null && response.kind !== 'error' && (response.status ?? 0) < 300}
          />
        </div>
        <div className="trace-right">
          <div className="trace-tabs">
            <button className={`trace-tab${tab === 'response' ? ' active' : ''}`} onClick={() => setTab('response')}>
              Response
            </button>
            <button className={`trace-tab${tab === 'code' ? ' active' : ''}`} onClick={() => setTab('code')}>
              Code
            </button>
          </div>
          <div className="trace-content">
            {tab === 'response' ? (
              <ResponsePane payload={response} running={running} />
            ) : (
              <CodeTabs endpoint={endpoint} paramValues={paramValues} baseUrl={location.origin} />
            )}
          </div>
        </div>
        <div className="trace-log">
          <EventLog log={log} onClear={() => setLog([])} />
        </div>
      </div>
    </>
  )
}

async function* runFlow(
  endpoint: Endpoint,
  url: string,
  paramValues: Record<string, string>,
  primitive: Primitive,
  protocol?: 'mpp' | 'x402',
): AsyncGenerator<FlowProgress> {
  void paramValues
  for await (const step of payAndFetch(url, {
    primitive,
    protocol,
    unitPrice: endpoint.unitPrice,
    init: { method: endpoint.method },
  })) {
    yield step
  }
}

/**
 * Build a pay.sh receipt link for a settled signature. The playground
 * always settles against the Solana Payment Sandbox, so the receipt
 * page needs the sandbox network hint to find the transaction.
 */
function receiptLink(signature: string): LogLine['link'] {
  if (!signature) return undefined
  return { href: `https://pay.sh/receipt/${signature}?network=sandbox`, label: 'View receipt' }
}

function handleProgress(
  progress: FlowProgress,
  advance: (key: string, status: FlowStep['status'], ts?: string) => void,
  pushLog: (message: string, kind: LogLine['kind'], detail?: string, link?: LogLine['link']) => void,
  setResponse: (p: ResponsePayload) => void,
): void {
  switch (progress.type) {
    case 'request':
      advance('req', 'completed')
      break
    case 'challenge': {
      const decimals = progress.decimals ?? 6
      pushLog(
        `402 Payment Required: ${fmtUnits(progress.amount, decimals, currencySymbol(progress.currency))}`,
        'x402',
      )
      advance('402', 'completed')
      break
    }
    case 'signing':
      pushLog('Signing transaction', 'info')
      advance('sign', 'completed')
      break
    case 'paying':
      pushLog('Broadcasting transaction', 'info')
      advance('broadcast', 'completed')
      break
    case 'confirming':
      pushLog(`Confirming ${progress.signature.slice(0, 12)}…`, 'dim')
      break
    case 'paid':
      pushLog(`Settled on-chain: ${progress.signature.slice(0, 16)}…`, 'ok', undefined, receiptLink(progress.signature))
      advance('settle', 'completed')
      break
    case 'activated':
      pushLog(
        `Subscription activated: ${progress.signature.slice(0, 16)}…`,
        'ok',
        undefined,
        receiptLink(progress.signature),
      )
      advance('activate', 'completed')
      break
    case 'voucher':
      pushLog(`Voucher signed (cumulative ${fmtUnits(progress.cumulative, 6, 'USDC')})`, 'info')
      advance('voucher', 'completed')
      break
    case 'chunk':
      // Streamed (SSE) responses render progressively; the final success
      // event overwrites this with the complete body and total latency.
      setResponse({
        kind: 'text',
        text: progress.text,
        status: progress.status,
        headers: progress.headers,
        latencyMs: progress.latencyMs,
      })
      break
    case 'success': {
      advance('ok', 'completed')
      advance('deliver', 'completed')
      const detail =
        typeof progress.data === 'string'
          ? progress.data
          : JSON.stringify(progress.data, null, 2)
      pushLog(`${progress.status} OK`, 'ok', detail.length > 600 ? detail.slice(0, 600) + '…' : detail)
      const payload: ResponsePayload =
        typeof progress.data === 'string'
          ? {
              kind: 'text',
              text: progress.data,
              status: progress.status,
              headers: progress.headers,
              latencyMs: progress.latencyMs,
            }
          : {
              kind: 'json',
              data: progress.data,
              status: progress.status,
              headers: progress.headers,
              latencyMs: progress.latencyMs,
            }
      setResponse(payload)
      break
    }
    case 'error':
      pushLog(`Error: ${progress.message}`, 'error')
      setResponse({ kind: 'error', message: progress.message })
      break
  }
}

function currencySymbol(currency: string): string {
  if (currency === 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v') return 'USDC'
  if (currency === 'sol' || currency === 'SOL') return 'SOL'
  return currency.length > 12 ? `${currency.slice(0, 4)}…${currency.slice(-4)}` : currency
}
