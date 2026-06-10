import { useState } from 'react'
import { CopyButton } from './CopyButton'
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
        <div className="code-block">
          <pre>{snippets[lang]}</pre>
          <CopyButton text={snippets[lang]} />
        </div>
      </div>
    </div>
  )
}
