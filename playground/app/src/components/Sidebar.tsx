import { NavLink } from 'react-router-dom'
import { useConfig, explorerAddrUrl } from '../hooks/useConfig'
import type { Endpoint, Primitive } from '../types'

const GROUPS: Array<{ title: string; primitive: Primitive | 'docs'; route: string; cls: string }> = [
  { title: 'Charges', primitive: 'charge', route: '/charges', cls: 'charges' },
  { title: 'x402', primitive: 'x402', route: '/x402', cls: 'x402' },
  { title: 'Subscriptions', primitive: 'subscription', route: '/subscriptions', cls: 'subscription' },
  { title: 'Sessions', primitive: 'session', route: '/sessions', cls: 'session' },
]

export function Sidebar({
  onEndpointClick,
  selectedEndpointId,
}: {
  onEndpointClick: (ep: Endpoint) => void
  selectedEndpointId: string | null
}) {
  const config = useConfig()

  const byPrimitive = (p: Primitive): Endpoint[] => {
    if (!config) return []
    return config.endpoints.filter((e) => e.primitive === p)
  }

  return (
    <>
      {GROUPS.map((g) => {
        if (g.primitive === 'docs') return null
        const eps = byPrimitive(g.primitive)
        return (
          <div className="side-group" key={g.title}>
            <NavLink
              to={g.route}
              className={({ isActive }) =>
                `side-group-header ${g.cls}` + (isActive ? ' active' : '')
              }
              style={{ textDecoration: 'none' }}
            >
              {g.title}
              <span style={{ marginLeft: 'auto', color: 'var(--fg-muted)', fontWeight: 400 }}>
                {eps.length || ''}
              </span>
            </NavLink>
            {eps.map((ep) => (
              <div
                key={ep.id}
                className={`side-link${selectedEndpointId === ep.id ? ' active' : ''}`}
                onClick={() => onEndpointClick(ep)}
              >
                <span className={`method ${ep.method}`}>{ep.method}</span>
                <span className="path" title={ep.path}>
                  {ep.title}
                </span>
                <span className="pr">{ep.cost}</span>
              </div>
            ))}
          </div>
        )
      })}

      <div className="side-group">
        <NavLink
          to="/docs"
          className={({ isActive }) => 'side-group-header docs' + (isActive ? ' active' : '')}
          style={{ textDecoration: 'none' }}
        >
          Documentation
        </NavLink>
        <NavLink
          to="/docs"
          className={({ isActive }) => 'side-link' + (isActive ? ' active' : '')}
        >
          <span className="method">DOC</span>
          <span className="path">Language quickstarts</span>
        </NavLink>
      </div>

      {config && (
        <div className="side-foot">
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>Network</span>
            <span style={{ color: 'var(--fg-secondary)' }}>
              {config.network === 'localnet' ? 'SANDBOX' : config.network.toUpperCase()}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>Recipient</span>
            <a href={explorerAddrUrl(config.recipient, config.network)} target="_blank" rel="noopener">
              {config.recipient.slice(0, 4)}…{config.recipient.slice(-4)}
            </a>
          </div>
          {config.feePayer && (
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span>Fee payer</span>
              <a href={explorerAddrUrl(config.feePayer, config.network)} target="_blank" rel="noopener">
                {config.feePayer.slice(0, 4)}…{config.feePayer.slice(-4)}
              </a>
            </div>
          )}
        </div>
      )}
    </>
  )
}
