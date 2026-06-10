import {
  createGeminiMeteringBreakdown,
  getGeminiMeteringSpec,
  type GeminiMeteringBreakdown,
  type UnitPrice,
} from '../../lib/gemini/metering'
import type { GeminiDemoResponse, PaymentEvent, ReceiptState, VoucherState } from '../../lib/gemini/types'

interface Props {
  events: readonly PaymentEvent[]
  receipt?: ReceiptState
  response: GeminiDemoResponse | null
  voucher: VoucherState | null
}

export function PaymentDetails({ events, receipt, response, voucher }: Props) {
  const model = response?.modelVersion ?? response?.model ?? 'gemini-2.5-flash'
  const decimals = voucher?.decimals ?? 6
  const minVoucherDeltaAmount = voucher?.minVoucherDeltaAmount ?? '1'
  const spec = getGeminiMeteringSpec(model)
  const metering = createGeminiMeteringBreakdown({
    baselineCumulativeAmount: voucher?.baselineCumulativeAmount ?? '0',
    currentCumulativeAmount: voucher?.cumulativeAmount ?? '0',
    minVoucherDeltaAmount,
    model,
    targetCumulativeAmount: voucher?.cumulativeAmount,
    usage: response?.usage,
  })

  return (
    <details className="gemini-details">
      <summary className="gemini-details-summary">
        <span className="gemini-details-summary-label">
          <span className="gemini-details-caret">▾</span> Session details
        </span>
        {receipt ? (
          <a
            href={receipt.explorerUrl}
            target="_blank"
            rel="noreferrer"
            className="btn-primary gemini-receipt-btn"
            onClick={(e) => e.stopPropagation()}
          >
            View transaction receipt ↗
          </a>
        ) : (
          <span className="gemini-cumulative">{voucher?.cumulativeUsdc ?? '0.000000 USDC'}</span>
        )}
      </summary>

      <div className="gemini-details-grid">
        <section className="gemini-section">
          <h4>Metering specification</h4>
          <div className="gemini-row-list">
            <DetailRow label="input rate" value={meterRate(spec.input)} />
            <DetailRow label="output rate" value={meterRate(spec.output)} />
            <DetailRow label="precision" value={amountWithUsd(minVoucherDeltaAmount, decimals)} />
            <DetailRow label="rounding" value="ceil metered usage to precision" />
            <DetailRow label="basis" value="prompt tokens + output tokens" />
          </div>
        </section>

        <section className="gemini-section">
          <h4>Metering observed / billed</h4>
          {metering ? (
            <MeteringRows decimals={decimals} metering={metering} />
          ) : (
            <div className="gemini-detail-empty">Waiting for usage metadata</div>
          )}
        </section>
      </div>

      <section className="gemini-events">
        <div className="gemini-events-head">
          <h4>Events</h4>
          <span className="gemini-events-count">{events.length}</span>
        </div>
        {events.length > 0 ? (
          <div className="gemini-row-list">
            {events.map((event, i) => (
              <EventRow event={event} key={`${event.label}-${i}`} />
            ))}
          </div>
        ) : (
          <div className="gemini-detail-empty">Idle</div>
        )}
      </section>
    </details>
  )
}

function MeteringRows({ decimals, metering }: { decimals: number; metering: GeminiMeteringBreakdown }) {
  return (
    <div className="gemini-row-list">
      <DetailRow label="input" value={tokenMath(metering.input, decimals)} />
      <DetailRow label="output" value={tokenMath(metering.output, decimals)} />
      <DetailRow
        label="metered"
        value={`${formatAmount(metering.input.amount)} + ${formatAmount(metering.output.amount)} = ${amountWithUsd(metering.rawAmount, decimals)}`}
      />
      <DetailRow
        label="rounding"
        value={`ceil(${formatAmount(metering.rawAmount)} / ${formatAmount(metering.minVoucherDeltaAmount)}) × ${formatAmount(metering.minVoucherDeltaAmount)} = ${amountWithUsd(metering.roundedAmount, decimals)}`}
      />
      <DetailRow
        label="voucher total"
        value={`${formatAmount(metering.baselineCumulativeAmount)} + ${formatAmount(metering.roundedAmount)} = ${amountWithUsd(metering.cumulativeAmount, decimals)}`}
      />
    </div>
  )
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="gemini-detail-row">
      <span className="gemini-detail-label">{label}</span>
      <span className="gemini-detail-value">{value}</span>
    </div>
  )
}

function EventRow({ event }: { event: PaymentEvent }) {
  const icon = event.state === 'working' ? '◐' : event.state === 'error' ? '✕' : '✓'
  return (
    <div className="gemini-event-row">
      <span className={`gemini-event-icon ${event.state}`}>{icon}</span>
      <div className="gemini-event-body">
        <div className="gemini-event-label">{event.label}</div>
        <div className="gemini-event-detail">{event.detail}</div>
      </div>
    </div>
  )
}

// ── Format helpers ──

function formatCount(value: number | undefined): string {
  return value === undefined ? '—' : value.toLocaleString('en-US')
}

function tokenMath(line: GeminiMeteringBreakdown['input'], decimals: number): string {
  return `${formatCount(line.tokens)} tokens × ${formatRate(line)} / 1M → ${amountWithUsd(line.amount, decimals)}`
}

function meterRate(price: UnitPrice): string {
  return `${formatRate(price)} / 1M tokens (${formatAmount(price.microUsdPerUnit)} μUSD / ${formatCount(price.tokensPerUnit)} tokens)`
}

function formatAmount(value: number | string): string {
  const raw = typeof value === 'number' ? value.toString() : value
  try {
    return BigInt(raw).toLocaleString('en-US')
  } catch {
    return raw
  }
}

function amountWithUsd(amount: string, decimals: number): string {
  return `${formatAmount(amount)} μUSD (${formatUsdFromBaseUnits(amount, decimals)})`
}

function formatRate(line: UnitPrice): string {
  const cents = Math.round((line.microUsdPerUnit * 100) / line.tokensPerUnit)
  return `$${(cents / 100).toFixed(2)}`
}

function formatUsdFromBaseUnits(amount: string, decimals: number): string {
  try {
    const value = BigInt(amount)
    const scale = BigInt(10) ** BigInt(decimals)
    const whole = value / scale
    const fractional = (value % scale).toString().padStart(decimals, '0')
    return `$${whole.toString()}.${fractional}`
  } catch {
    return `$${amount}`
  }
}
