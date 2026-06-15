import { useRef, useEffect } from 'react'
import type { LogLine } from '../types'
import { fmtTime } from '../lib/format'

interface Props {
  log: LogLine[]
  onClear?: () => void
}

export function EventLog({ log, onClear }: Props) {
  const scrollRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [log])

  return (
    <div ref={scrollRef} className="event-log" style={{ overflowY: 'auto', maxHeight: '100%' }}>
      <h3 style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span>Events</span>
        {log.length > 0 && onClear && (
          <button className="btn-ghost" onClick={onClear} style={{ padding: '2px 8px' }}>
            clear
          </button>
        )}
      </h3>
      {log.length === 0 && (
        <div style={{ color: 'var(--fg-muted)', fontSize: 12, padding: '4px 0' }}>
          Nothing yet — hit Send to start a flow.
        </div>
      )}
      {log.map((line) => (
        <div className="event-entry" key={line.id}>
          <span className="event-ts">{fmtTime(line.ts)}</span>
          <div className="event-content">
            <div className={`event-msg ${line.kind}`}>{line.message}</div>
            {line.link && (
              <a className="event-link" href={line.link.href} target="_blank" rel="noopener noreferrer">
                {line.link.label} ↗
              </a>
            )}
            {line.detail && (
              <div className="event-detail">
                <pre className="event-detail-pre">{line.detail}</pre>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}
