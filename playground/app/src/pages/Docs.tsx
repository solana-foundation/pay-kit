import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { CodeBlock } from '../components/CodeBlock'
import { LANG_DOCS, type LangDoc } from '../lib/docs.gen'
import { CopyButton } from '../components/CopyButton'

interface AvailabilityResponse {
  root: string
  available: Record<string, boolean>
}

type Capability = 'full' | 'server' | 'client'

function capabilityOf(d: LangDoc): Capability {
  if (d.server === '✅' && d.client === '✅') return 'full'
  if (d.server === '✅') return 'server'
  return 'client'
}

const GROUPS: Array<{ id: Capability; title: string; lede: string }> = [
  {
    id: 'full',
    title: 'Server + Client',
    lede: 'Both sides of the 402 handshake. Gate routes and consume them.',
  },
  {
    id: 'server',
    title: 'Server only',
    lede: 'Gate HTTP routes; use the CLI or another language for the client.',
  },
  {
    id: 'client',
    title: 'Client only',
    lede: 'Consume 402-gated APIs from a wallet on the device.',
  },
]

export function Docs() {
  const [availability, setAvailability] = useState<Record<string, boolean>>({})

  useEffect(() => {
    fetch('/api/v1/docs')
      .then((r) => (r.ok ? (r.json() as Promise<AvailabilityResponse>) : null))
      .then((data) => data && setAvailability(data.available))
      .catch(() => {})
  }, [])

  return (
    <div className="docs-page">
      <h2>Language quickstarts</h2>
      <p className="lede">
        Pay-kit ships in nine languages. Pick yours below — each card shows the install command + a ten-line
        snippet. When the API reference has been generated (<code>just docs-&lt;lang&gt;</code>), the{' '}
        <strong>API reference →</strong> link opens the full markdown reference inside the playground.
      </p>

      {GROUPS.map((g) => {
        const langs = LANG_DOCS.filter((d) => capabilityOf(d) === g.id)
        return (
          <section key={g.id} className="docs-group">
            <div className="docs-group-head">
              <h3>{g.title}</h3>
              <span className="docs-group-count">{langs.length}</span>
            </div>
            <p className="docs-group-lede">{g.lede}</p>
            <div className="docs-group-grid">
              {langs.map((d) => (
                <DocCard key={d.id} doc={d} hasApiDocs={!!availability[d.id]} />
              ))}
            </div>
          </section>
        )
      })}

      <div style={{ marginTop: 32, paddingTop: 24, borderTop: '1px solid var(--border)' }}>
        <h3 style={{ fontSize: 14, fontWeight: 600, marginBottom: 8 }}>Use the `pay` CLI as a client</h3>
        <p className="lede" style={{ marginBottom: 12 }}>
          The simplest way to test any of these endpoints is the <code>pay</code> CLI. It handles wallet,
          signing, and the 402 replay transparently.
        </p>
        <div className="code-block">
          <CodeBlock
            language="bash"
            text={`brew install pay     # or: npm install -g @solana/pay
pay --sandbox curl http://localhost:3000/api/v1/stocks/quote/AAPL`}
          />
          <CopyButton text={`brew install pay
pay --sandbox curl http://localhost:3000/api/v1/stocks/quote/AAPL`} />
        </div>
      </div>
    </div>
  )
}

function DocCard({ doc, hasApiDocs }: { doc: LangDoc; hasApiDocs: boolean }) {
  return (
    <div className="docs-card">
      <div className="docs-card-head">
        <h4>{doc.name}</h4>
        <span className="install">{doc.install}</span>
      </div>
      <div className="docs-card-body">
        <div className="framework">{doc.framework}</div>
        {doc.snippet ? (
          <div className="code-block">
            <CodeBlock language={doc.id} text={doc.snippet} />
            <CopyButton text={doc.snippet} />
          </div>
        ) : (
          <div className="docs-card-pending-snippet">
            Quickstart coming soon —{' '}
            <a href={doc.href} target="_blank" rel="noopener">
              see README ↗
            </a>
          </div>
        )}
        <div className="docs-card-foot">
          {hasApiDocs ? (
            <Link to={`/docs/ref/${doc.id}`} className="docs-card-ref">
              API reference →
            </Link>
          ) : (
            <span className="docs-card-pending">
              Run <code>just docs-{recipeSlug(doc.id)}</code> for API reference
            </span>
          )}
          <a href={doc.href} target="_blank" rel="noopener" className="docs-card-readme">
            README ↗
          </a>
        </div>
      </div>
    </div>
  )
}

function recipeSlug(id: string): string {
  switch (id) {
    case 'typescript':
      return 'ts'
    case 'rust':
      return 'rs'
    case 'python':
      return 'py'
    case 'ruby':
      return 'rb'
    case 'kotlin':
      return 'kt'
    default:
      return id
  }
}
