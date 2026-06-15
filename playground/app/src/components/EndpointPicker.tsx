import { useState, useEffect, useMemo, useRef } from 'react'
import type { Endpoint } from '../types'
import { isMac } from '../hooks/useKeyboard'

interface Props {
  endpoints: Endpoint[]
  onSelect: (ep: Endpoint) => void
  onClose: () => void
}

function score(ep: Endpoint, query: string): number {
  if (!query) return 1
  const q = query.toLowerCase()
  const haystacks = [ep.title, ep.path, ep.description, ep.primitive, ep.method].map((s) => s.toLowerCase())
  let s = 0
  for (const h of haystacks) {
    if (h === q) s += 10
    else if (h.startsWith(q)) s += 5
    else if (h.includes(q)) s += 2
  }
  return s
}

export function EndpointPicker({ endpoints, onSelect, onClose }: Props) {
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  const filtered = useMemo(() => {
    return endpoints
      .map((ep) => ({ ep, s: score(ep, query) }))
      .filter((r) => r.s > 0)
      .sort((a, b) => b.s - a.s)
      .slice(0, 20)
      .map((r) => r.ep)
  }, [endpoints, query])

  useEffect(() => {
    if (active >= filtered.length) setActive(Math.max(0, filtered.length - 1))
  }, [filtered, active])

  const onKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive((i) => Math.min(filtered.length - 1, i + 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((i) => Math.max(0, i - 1))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      const choice = filtered[active]
      if (choice) onSelect(choice)
    } else if (e.key === 'Escape') {
      onClose()
    }
  }

  const mod = isMac() ? '⌘' : 'Ctrl'

  return (
    <div className="picker-overlay" onClick={onClose}>
      <div className="picker" onClick={(e) => e.stopPropagation()}>
        <input
          ref={inputRef}
          value={query}
          placeholder="Search endpoints…"
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onKey}
        />
        <div className="picker-results">
          {filtered.length === 0 && (
            <div style={{ padding: '20px 18px', color: 'var(--fg-muted)', fontSize: 13 }}>
              No endpoints match “{query}”.
            </div>
          )}
          {filtered.map((ep, i) => (
            <div
              key={ep.id}
              className={`picker-row${i === active ? ' active' : ''}`}
              onMouseEnter={() => setActive(i)}
              onClick={() => onSelect(ep)}
            >
              <span className={`method ${ep.method}`}>{ep.method}</span>
              <span className="path">{ep.path}</span>
              <span className="pr">{ep.cost}</span>
            </div>
          ))}
        </div>
        <div className="picker-foot">
          <span>
            <kbd>↑</kbd> <kbd>↓</kbd> navigate
          </span>
          <span>
            <kbd>↵</kbd> open
          </span>
          <span>
            <kbd>esc</kbd> close
          </span>
          <span style={{ marginLeft: 'auto' }}>
            <kbd>{mod}K</kbd> toggle
          </span>
        </div>
      </div>
    </div>
  )
}
