import { useNavigate, useLocation } from 'react-router-dom'
import { useConfig } from '../hooks/useConfig'
import type { Endpoint, Primitive } from '../types'

const PRIMITIVE_ROUTE: Record<Primitive, string> = {
  charge: '/charges',
  subscription: '/subscriptions',
  session: '/sessions',
  x402: '/x402',
}

/** Group color family. charge + x402 `exact` share the "pay" tile color (both
 * are single-shot payments); session and subscription get their own. */
const PRIMITIVE_CLS: Record<Primitive, string> = {
  charge: 'pay',
  x402: 'pay',
  subscription: 'subscription',
  session: 'session',
}

/** Pill color class for an endpoint — by scheme where it matters: a metered
 * x402 `upto` route is pink (like sessions), not the blue `pay` tile. */
function pillClass(ep: Endpoint): string {
  if (ep.description?.includes('upto')) return 'upto'
  return PRIMITIVE_CLS[ep.primitive]
}

/** Color-group display order: blue (single-shot pay) → pink (metered: upto +
 * session) → yellow (subscription). Docs renders after, separately. */
const GROUP_RANK: Record<string, number> = { pay: 0, upto: 1, session: 1, subscription: 2 }
function groupRank(ep: Endpoint): number {
  return GROUP_RANK[pillClass(ep)] ?? 3
}

interface Props {
  selectedEndpointId: string | null
  onEndpointClick: (ep: Endpoint) => void
}

/**
 * Horizontal endpoint nav. One pill per registered endpoint, plus a Docs pill
 * at the end. Selecting one routes to the primitive's page with the ep query
 * param set — same handler the old sidebar used.
 */
export function TopNav({ selectedEndpointId, onEndpointClick }: Props) {
  const config = useConfig()
  const navigate = useNavigate()
  const location = useLocation()
  const endpoints = [...(config?.endpoints ?? [])].sort((a, b) => groupRank(a) - groupRank(b))

  return (
    <div className="topnav" role="navigation" aria-label="Endpoints">
      <div className="topnav-scroll">
        {endpoints.map((ep) => {
          const active =
            selectedEndpointId === ep.id && location.pathname === PRIMITIVE_ROUTE[ep.primitive]
          return (
            <button
              key={ep.id}
              type="button"
              className={`topnav-pill ${pillClass(ep)}${active ? ' active' : ''}`}
              onClick={() => onEndpointClick(ep)}
              title={`${ep.method} ${ep.path} — ${ep.cost}`}
            >
              <span className="row">
                <span className="method">{ep.method}</span>
                <span className="title">{ep.title}</span>
              </span>
              {ep.description && <span className="desc">{ep.description}</span>}
              <span className="cost">{ep.cost}</span>
            </button>
          )
        })}
        <button
          type="button"
          className={`topnav-pill docs${location.pathname.startsWith('/docs') ? ' active' : ''}`}
          onClick={() => navigate('/docs')}
        >
          <span className="row">
            <span className="method">DOC</span>
            <span className="title">Docs</span>
          </span>
          <span className="desc">Pick a language and read the quickstart.</span>
          <span className="cost">Reference</span>
        </button>
      </div>
    </div>
  )
}
