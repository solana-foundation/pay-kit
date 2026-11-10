import { useCallback, useEffect, useRef, useState } from 'react'
import { EventLog } from '../components/EventLog'
import { FlowTimeline } from '../components/FlowTimeline'
import {
  CREDITS_STEPS,
  creditsStatus,
  explorerTx,
  creditsRunActive,
  currentCreditsRun,
  runCreditsOnce,
  type CreditsState,
  type CreditsStatus,
} from '../lib/credits'
import { fmtUnits } from '../lib/format'
import type { FlowStep, LogLine } from '../types'

const usdc = (value: string | null | undefined): string => (value == null ? '—' : fmtUnits(value, 6, 'USDC'))

function freshSteps(): FlowStep[] {
  return CREDITS_STEPS.map((step) => ({ ...step, status: 'pending' }))
}

/**
 * A credit provider funds an MPP session (payment-channels V2 lifecycle
 * hooks): the merchant's 402 names the provider's callbacks, the channel
 * program calls `preFund` inside the open and `postDistribute` inside the
 * close. Every balance below is read on chain after each step.
 */
export function Credits({ onBalanceChange }: { onBalanceChange?: () => void }) {
  const [status, setStatus] = useState<CreditsStatus | null>(null)
  const [steps, setSteps] = useState<FlowStep[]>(freshSteps)
  const [log, setLog] = useState<LogLine[]>([])
  const [state, setState] = useState<CreditsState | null>(null)
  // The merchant's balance before this run, to show what the run paid it.
  const [merchantBefore, setMerchantBefore] = useState<string | null>(null)
  const [last, setLast] = useState<unknown>(null)
  // A run started before this page was (re)mounted is still in flight.
  const [running, setRunning] = useState(creditsRunActive)
  const [outcome, setOutcome] = useState<'success' | 'failed' | null>(null)
  const logId = useRef(0)

  // Reopened while an earlier run is in flight: wait for it, then re-enable.
  useEffect(() => {
    currentCreditsRun()?.finally(() => setRunning(false))
  }, [])

  useEffect(() => {
    creditsStatus()
      .then(setStatus)
      .catch((error: unknown) => setStatus({ enabled: false, reason: error instanceof Error ? error.message : String(error) }))
  }, [])

  const pushLog = useCallback((message: string, kind: LogLine['kind'], detail?: string, signature?: string) => {
    const entry: LogLine = {
      detail,
      id: logId.current++,
      kind,
      link: signature ? { href: explorerTx(signature), label: 'View transaction' } : undefined,
      message,
      ts: new Date().toISOString(),
    }
    setLog((prev) => [...prev, entry])
  }, [])

  const run = useCallback(async () => {
    setRunning(true)
    setOutcome(null)
    setSteps(freshSteps())
    setLog([])
    setState(null)
    setMerchantBefore(null)
    setLast(null)
    try {
      await runCreditsOnce((event) => {
        switch (event.type) {
          case 'step':
            setSteps((prev) =>
              prev.map((step) =>
                step.key === event.key ? { ...step, status: event.status, ts: new Date().toISOString() } : step,
              ),
            )
            break
          case 'log':
            pushLog(event.message, event.kind, event.detail, event.signature)
            break
          case 'state':
            setState(event.state)
            setMerchantBefore((before) => before ?? event.state.balances.merchant)
            break
          case 'response':
            setLast(event.body)
            break
        }
      })
      setOutcome('success')
    } catch (error) {
      pushLog(`Error: ${error instanceof Error ? error.message : String(error)}`, 'error')
      setSteps((prev) => {
        const at = prev.findIndex((step) => step.status !== 'completed')
        return prev.map((step, i) => (i === at ? { ...step, status: 'failed' } : step))
      })
      setOutcome('failed')
    } finally {
      setRunning(false)
      onBalanceChange?.()
    }
  }, [onBalanceChange, pushLog])

  const ledger = state?.ledger
  return (
    <>
      <div className="page-head">
        <span className="method">GET</span>
        <span className="path">/api/v1/credits/:customer/quote</span>
        <span className="desc">A credit provider funds the session through lifecycle hooks</span>
        <span className="cost">0.01 USDC / request</span>
      </div>
      {status && !status.enabled && (
        <div className="banner">
          Credit-funded sessions are off: {status.reason}. Start the API with <code>PAYMENT_CHANNELS_V2_SO</code> and{' '}
          <code>CREDIT_PROVIDER_SO</code> pointing at the payment-channels artifacts on the local sandbox.
        </div>
      )}
      <div className="credits-page">
        <section className="credits-intro">
          <p>
            The customer (this wallet) holds <strong>2 USDC of credits</strong> with a provider program. The merchant's
            402 names the provider's callbacks (<code>channelVersion: 2</code>). The provider co-signs an approval for
            exactly one channel; the channel program then calls <code>preFund</code> inside the open, which debits
            credits and supplies the backing, and <code>postDistribute</code> inside the close, which pulls the unspent
            refund back into custody and restores those credits. Your wallet's USDC is not spent.
          </p>
          {status?.enabled && (
            <dl className="credits-meta">
              <dt>Provider</dt>
              <dd>
                <code>{status.provider}</code>
              </dd>
              <dt>Issuer</dt>
              <dd>
                <code>{status.issuer}</code>
              </dd>
              <dt>Channel program</dt>
              <dd>
                <code>{status.channelProgram}</code> (hooks build)
              </dd>
            </dl>
          )}
          <div className="req-actions">
            <button className="btn-primary" disabled={running || !status?.enabled} onClick={run}>
              {running ? 'Running…' : outcome ? 'Run again' : 'Run the credit-funded session'}
            </button>
          </div>
        </section>
        <div className="credits-grid">
          <FlowTimeline steps={steps} failed={outcome === 'failed'} success={outcome === 'success'} />
          <section className="credits-balances">
            <h3>On chain</h3>
            <table>
              <tbody>
                <tr>
                  <th>Customer credits</th>
                  <td>{usdc(ledger?.credits)}</td>
                </tr>
                <tr>
                  <th>Provider vault (backing)</th>
                  <td>{usdc(state?.balances.vault)}</td>
                </tr>
                <tr>
                  <th>Channel escrow</th>
                  <td>
                    {state?.balances.escrow != null
                      ? usdc(state.balances.escrow)
                      : steps.find((step) => step.key === 'close')?.status === 'completed'
                        ? 'closed'
                        : '—'}
                  </td>
                </tr>
                <tr>
                  <th>Merchant earned</th>
                  <td>
                    {state?.balances.merchant != null && merchantBefore != null
                      ? `+${usdc((BigInt(state.balances.merchant) - BigInt(merchantBefore)).toString())}`
                      : '—'}
                  </td>
                </tr>
                <tr>
                  <th>Customer wallet USDC (not spent)</th>
                  <td>{usdc(state?.balances.customer)}</td>
                </tr>
                <tr>
                  <th>Ledger funded / refunded</th>
                  <td>
                    {ledger ? `${usdc(ledger.funded)} / ${usdc(ledger.refunded)}` : '—'}
                  </td>
                </tr>
                <tr>
                  <th>Requests served</th>
                  <td>{state ? state.served : '—'}</td>
                </tr>
              </tbody>
            </table>
            {last != null && (
              <>
                <h3>Last response</h3>
                <pre className="event-detail-pre">{JSON.stringify(last, null, 2)}</pre>
              </>
            )}
          </section>
          <EventLog log={log} onClear={() => setLog([])} />
        </div>
      </div>
    </>
  )
}
