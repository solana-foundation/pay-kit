import { useConfig } from '../hooks/useConfig'
import { EndpointWorkbench } from '../components/EndpointWorkbench'

export function Sessions({ onBalanceChange }: { onBalanceChange?: () => void }) {
  const config = useConfig()
  const endpoints = (config?.endpoints ?? []).filter((e) => e.primitive === 'session')

  if (endpoints.length === 0) {
    return (
      <>
        <div className="page-head">
          <span className="path">Sessions</span>
          <span className="desc">No session endpoints registered.</span>
        </div>
        <div className="banner">
          The server is responsible for advertising session-billed endpoints. If you're seeing this, the
          playground API didn't register any — check that <code>@solana/mpp</code> is up-to-date in
          <code>typescript/examples/playground-api</code>.
        </div>
      </>
    )
  }

  return <EndpointWorkbench endpoints={endpoints} primitive="session" onBalanceChange={onBalanceChange} />
}
