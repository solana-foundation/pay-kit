import type { Endpoint } from '../types'

interface Props {
  endpoint: Endpoint
  paramValues: Record<string, string>
  onParamChange: (name: string, value: string) => void
  onSend: () => void
  onReset: () => void
  running: boolean
  disabled?: boolean
  disabledReason?: string
}

export function RequestBuilder({
  endpoint,
  paramValues,
  onParamChange,
  onSend,
  onReset,
  running,
  disabled,
  disabledReason,
}: Props) {
  const params = endpoint.params ?? []

  return (
    <div className="req-builder">
      {params.length === 0 && (
        <div style={{ color: 'var(--fg-muted)', fontSize: 12 }}>
          No parameters for this endpoint.
        </div>
      )}
      {params.map((p) => (
        <div className="param-row" key={p.name}>
          <label htmlFor={`param-${p.name}`}>{p.name}</label>
          <input
            id={`param-${p.name}`}
            value={paramValues[p.name] ?? p.default}
            onChange={(e) => onParamChange(p.name, e.target.value)}
            placeholder={p.default || '(empty)'}
            spellCheck={false}
          />
        </div>
      ))}
      <div className="req-actions">
        <button
          className="btn-primary"
          onClick={onSend}
          disabled={running || disabled}
          title={disabled ? disabledReason : undefined}
        >
          {running ? 'Sending…' : disabled ? 'Disabled' : 'Send request'}
        </button>
        <button className="btn-secondary" onClick={onReset} disabled={running}>
          Reset
        </button>
        {disabled && disabledReason && (
          <span style={{ color: 'var(--yellow)', fontSize: 12, alignSelf: 'center' }}>
            {disabledReason}
          </span>
        )}
      </div>
    </div>
  )
}
