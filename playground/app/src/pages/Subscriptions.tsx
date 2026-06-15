import { useConfig } from '../hooks/useConfig'
import { EndpointWorkbench } from '../components/EndpointWorkbench'

export function Subscriptions({ onBalanceChange }: { onBalanceChange?: () => void }) {
  const config = useConfig()
  const endpoints = (config?.endpoints ?? []).filter((e) => e.primitive === 'subscription')

  if (endpoints.length === 0) {
    return (
      <>
        <div className="page-head">
          <span className="path">Subscriptions</span>
          <span className="desc">Plan PDA not yet bootstrapped on the local sandbox.</span>
        </div>
        <div className="banner">
          The server boots a subscription plan against the surfnet. If you're seeing this message, the surfnet
          either isn't running or the subscriptions program isn't deployed on it.{' '}
          <code>surfpool start</code> and reload.
        </div>
      </>
    )
  }

  return (
    <EndpointWorkbench
      endpoints={endpoints}
      primitive="subscription"
      onBalanceChange={onBalanceChange}
      banner={
        <div className="banner">
          The first call activates the subscription on-chain via the kit's <code>solana.subscription</code> method.
          Subsequent calls within the period reuse the active subscription without re-paying.
        </div>
      }
    />
  )
}
