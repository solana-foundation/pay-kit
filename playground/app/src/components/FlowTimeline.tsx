import type { FlowStep } from '../types'
import { fmtTime } from '../lib/format'

interface Props {
  steps: FlowStep[]
  failed?: boolean
  success?: boolean
}

const ROW_H = 48
const R = 7
const CX = 10

export function FlowTimeline({ steps, failed, success }: Props) {
  if (steps.length === 0) {
    return (
      <div className="sequence-diagram">
        <h3>Flow</h3>
        <div style={{ color: 'var(--fg-muted)', fontSize: 12, padding: '8px 0' }}>
          Send a request to see the 402 handshake.
        </div>
      </div>
    )
  }

  const totalH = steps.length * ROW_H
  const failedIdx = failed ? steps.findIndex((s) => s.status !== 'completed') : -1

  return (
    <div className="sequence-diagram">
      <h3>Flow</h3>
      <div className="seq-container">
        <svg width={CX * 2} height={totalH}>
          {steps.map((step, i) => {
            const cy = i * ROW_H + R + 1
            const isLast = i === steps.length - 1
            const completed = step.status === 'completed'
            const isFailed = i === failedIdx

            const color = isFailed
              ? 'var(--red)'
              : !success && !failed
                ? completed
                  ? 'var(--fg-muted)'
                  : 'var(--border)'
                : completed
                  ? 'var(--green)'
                  : step.status === 'in-progress'
                    ? 'var(--yellow)'
                    : 'var(--fg-muted)'

            const lineColor = !success && !failed
              ? completed
                ? 'var(--fg-muted)'
                : 'var(--border)'
              : completed
                ? 'var(--green)'
                : 'var(--border)'

            const showCheck = isLast && completed && !failed

            return (
              <g key={step.key}>
                {!isLast && (
                  <line
                    x1={CX}
                    y1={cy + R}
                    x2={CX}
                    y2={(i + 1) * ROW_H + 1}
                    stroke={lineColor}
                    strokeWidth={3}
                  />
                )}
                <circle cx={CX} cy={cy} r={R} fill={color} />
                {showCheck && (
                  <path
                    d={`M${CX - 3.5} ${cy}L${CX - 1} ${cy + 2.5}L${CX + 3.5} ${cy - 2.5}`}
                    stroke="white"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    fill="none"
                  />
                )}
                {isFailed && (
                  <g>
                    <line x1={CX - 3} y1={cy - 3} x2={CX + 3} y2={cy + 3} stroke="white" strokeWidth="1.8" strokeLinecap="round" />
                    <line x1={CX + 3} y1={cy - 3} x2={CX - 3} y2={cy + 3} stroke="white" strokeWidth="1.8" strokeLinecap="round" />
                  </g>
                )}
              </g>
            )
          })}
        </svg>
        <div className="seq-labels">
          {steps.map((step, i) => (
            <div
              className="seq-row"
              key={step.key}
              style={{ height: ROW_H }}
            >
              <div
                className={`step-label${step.status === 'pending' ? ' pending' : ''}${
                  i === failedIdx ? ' failed' : ''
                }`}
              >
                {step.label}
              </div>
              {step.ts && <div className="step-ts">{fmtTime(step.ts)}</div>}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
