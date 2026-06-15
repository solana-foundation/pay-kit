import { useMemo } from 'react'
import hljs from 'highlight.js/lib/core'
import bash from 'highlight.js/lib/languages/bash'
import typescript from 'highlight.js/lib/languages/typescript'
import rust from 'highlight.js/lib/languages/rust'
import go from 'highlight.js/lib/languages/go'
import python from 'highlight.js/lib/languages/python'
import ruby from 'highlight.js/lib/languages/ruby'
import php from 'highlight.js/lib/languages/php'
import lua from 'highlight.js/lib/languages/lua'
import kotlin from 'highlight.js/lib/languages/kotlin'
import swift from 'highlight.js/lib/languages/swift'
import json from 'highlight.js/lib/languages/json'

let registered = false
function ensureRegistered() {
  if (registered) return
  hljs.registerLanguage('bash', bash)
  hljs.registerLanguage('typescript', typescript)
  hljs.registerLanguage('rust', rust)
  hljs.registerLanguage('go', go)
  hljs.registerLanguage('python', python)
  hljs.registerLanguage('ruby', ruby)
  hljs.registerLanguage('php', php)
  hljs.registerLanguage('lua', lua)
  hljs.registerLanguage('kotlin', kotlin)
  hljs.registerLanguage('swift', swift)
  hljs.registerLanguage('json', json)
  registered = true
}

/** Map playground language ids to hljs grammar ids. */
const LANG_MAP: Record<string, string> = {
  curl: 'bash',
  pay: 'bash',
  bash: 'bash',
  shell: 'bash',
  typescript: 'typescript',
  ts: 'typescript',
  rust: 'rust',
  rs: 'rust',
  go: 'go',
  python: 'python',
  py: 'python',
  ruby: 'ruby',
  rb: 'ruby',
  php: 'php',
  lua: 'lua',
  kotlin: 'kotlin',
  kt: 'kotlin',
  swift: 'swift',
  json: 'json',
}

interface Props {
  language: string
  text: string
  className?: string
}

export function CodeBlock({ language, text, className }: Props) {
  ensureRegistered()
  const html = useMemo(() => {
    const lang = LANG_MAP[language] ?? language
    if (hljs.getLanguage(lang)) {
      try {
        return hljs.highlight(text, { language: lang, ignoreIllegals: true }).value
      } catch {
        /* fall through to plain */
      }
    }
    return escapeHtml(text)
  }, [language, text])

  return (
    <pre className={className}>
      <code className={`hljs language-${LANG_MAP[language] ?? language}`} dangerouslySetInnerHTML={{ __html: html }} />
    </pre>
  )
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => {
    switch (c) {
      case '&':
        return '&amp;'
      case '<':
        return '&lt;'
      case '>':
        return '&gt;'
      case '"':
        return '&quot;'
      default:
        return '&#39;'
    }
  })
}
