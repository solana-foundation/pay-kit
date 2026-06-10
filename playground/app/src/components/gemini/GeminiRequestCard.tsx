import { GEMINI_DEMO_PROMPT } from '../../lib/gemini/state'
import type { GeminiDemoResponse, PaymentEvent, RunState, VoucherState } from '../../lib/gemini/types'
import { AnimatedCost, AnimatedTokenCounter } from './AnimatedCost'
import { PaymentDetails } from './PaymentDetails'
import { ResponsePanel } from './ResponsePanel'

interface Props {
  canRun: boolean
  events: readonly PaymentEvent[]
  response: GeminiDemoResponse | null
  runState: RunState
  voucher: VoucherState | null
  onReset: () => void
  onRun: () => void
}

export function GeminiRequestCard({ canRun, events, onReset, onRun, response, runState, voucher }: Props) {
  const outputTokens = outputTokenCount(response)

  return (
    <div className="gemini-card">
      <div className="gemini-card-head">
        <div>
          <div className="gemini-eyebrow">Gemini session</div>
          <h2 className="gemini-prompt">{GEMINI_DEMO_PROMPT}</h2>
        </div>
        <div className="gemini-actions">
          <button className="btn-primary" onClick={onRun} disabled={!canRun}>
            {runState === 'running' ? '↻ Running' : '▶ Run'}
          </button>
          <button className="btn-secondary" onClick={onReset} title="Reset demo" aria-label="Reset demo">
            ⟲
          </button>
        </div>
      </div>

      <div className="gemini-body">
        <div className="gemini-counters">
          <AnimatedTokenCounter isRunning={runState === 'running'} label="Output tokens" value={outputTokens} />
          <AnimatedCost isRunning={runState === 'running'} receipt={response?.receipt} voucher={voucher} />
        </div>

        <div className="gemini-section-block">
          <ResponsePanel response={response} runState={runState} />
        </div>

        <div className="gemini-section-block">
          <PaymentDetails events={events} receipt={response?.receipt} response={response} voucher={voucher} />
        </div>
      </div>
    </div>
  )
}

function outputTokenCount(response: GeminiDemoResponse | null): number {
  const usage = response?.usage
  if (!usage) return estimateLiveOutputTokens(response?.text ?? '')
  if (usage.candidatesTokenCount !== undefined) return usage.candidatesTokenCount
  if (usage.totalTokenCount !== undefined || usage.promptTokenCount !== undefined) {
    return Math.max(0, (usage.totalTokenCount ?? 0) - (usage.promptTokenCount ?? 0))
  }
  return estimateLiveOutputTokens(response?.text ?? '')
}

function estimateLiveOutputTokens(text: string): number {
  if (!text) return 0
  return Math.floor(text.replace(/\s+/gu, '').length / 6)
}
