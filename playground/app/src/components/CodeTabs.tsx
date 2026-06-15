import { useState } from 'react'
import { CopyButton } from './CopyButton'
import { CodeBlock } from './CodeBlock'
import { buildSnippets, type Language, LANGUAGES } from '../lib/snippets'
import type { Endpoint } from '../types'

interface Props {
  endpoint: Endpoint
  paramValues: Record<string, string>
  baseUrl: string
}

export function CodeTabs({ endpoint, paramValues, baseUrl }: Props) {
  const [lang, setLang] = useState<Language>('curl')
  const snippets = buildSnippets(endpoint, paramValues, baseUrl)
  const { client, server } = snippets[lang]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: 0 }}>
      <div className="lang-tabs">
        {LANGUAGES.map((l) => (
          <button
            key={l}
            className={`lang-tab${lang === l ? ' active' : ''}`}
            onClick={() => setLang(l)}
          >
            {l}
          </button>
        ))}
      </div>
      <div className="code-wrap">
        {client && (
          <section className="code-section">
            <h2 className="code-section-title">Client</h2>
            <div className="code-block">
              <CodeBlock language={lang} text={client} />
              <CopyButton text={client} />
            </div>
          </section>
        )}
        {server && (
          <section className="code-section">
            <h2 className="code-section-title">Server</h2>
            <div className="code-block">
              <CodeBlock language={lang} text={server} />
              <CopyButton text={server} />
            </div>
          </section>
        )}
      </div>
    </div>
  )
}
