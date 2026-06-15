import { useState } from 'react'
import { CodeBlock } from './CodeBlock'
import { CopyButton } from './CopyButton'
import { fmtDuration } from '../lib/format'
import type { ResponsePayload } from '../types'

interface Props {
  payload: ResponsePayload | null
  running: boolean
}

const HEADER_DENYLIST = new Set(['date', 'connection', 'keep-alive', 'transfer-encoding', 'content-length'])

export function ResponsePane({ payload, running }: Props) {
  const [showHeaders, setShowHeaders] = useState(false)

  // Show the placeholder only until the first payload arrives — streamed
  // responses set a partial payload per chunk and must render live, not
  // wait for the flow (including settlement polling) to finish.
  if (!payload) {
    return (
      <div className="response-pane">
        <div className={running ? 'response-empty pulsing' : 'response-empty'}>
          {running ? 'Waiting on payment…' : 'No response yet. Hit Send to fire the request.'}
        </div>
      </div>
    )
  }

  if (payload.kind === 'error') {
    return (
      <div className="response-pane">
        <div className="response-status">
          <span className="code err">ERROR</span>
        </div>
        <div className="response-body">
          <pre style={{ color: 'var(--red)' }}>{payload.message}</pre>
        </div>
      </div>
    )
  }

  const { status, latencyMs, headers } = payload
  const codeClass = status < 300 ? 'ok' : status < 500 ? 'warn' : 'err'
  const bodyText = payload.kind === 'json' ? JSON.stringify(payload.data, null, 2) : payload.text

  const headerEntries = Object.entries(headers)
    .filter(([k]) => !HEADER_DENYLIST.has(k.toLowerCase()))
    .sort(([a], [b]) => a.localeCompare(b))

  return (
    <div className="response-pane">
      <div className="response-status">
        <span className={`code ${codeClass}`}>{status}</span>
        <span className="latency">{fmtDuration(latencyMs)}</span>
        <button
          className="btn-ghost"
          onClick={() => setShowHeaders((v) => !v)}
          style={{ marginLeft: 'auto' }}
        >
          {showHeaders ? 'Hide headers' : `Show ${headerEntries.length} headers`}
        </button>
      </div>

      {showHeaders && (
        <div className="response-headers">
          <h4>Response headers</h4>
          {headerEntries.map(([k, v]) => (
            <div className="header-row" key={k}>
              <span className="k">{k}</span>
              <span className="v">{v}</span>
            </div>
          ))}
        </div>
      )}

      <div className="response-body" style={{ position: 'relative', marginTop: 12 }}>
        {payload.kind === 'json' ? (
          <CodeBlock language="json" text={bodyText} />
        ) : (
          <pre>{bodyText}</pre>
        )}
        <CopyButton text={bodyText} />
      </div>
    </div>
  )
}
