import { useEffect, useRef, useState } from 'react'
import type { GeminiDemoResponse, RunState } from '../../lib/gemini/types'

const WORD_REVEAL_MS = 25

interface Props {
  response: GeminiDemoResponse | null
  runState: RunState
}

export function ResponsePanel({ response, runState }: Props) {
  const scrollRef = useRef<HTMLDivElement>(null)
  const text = response?.text ?? ''
  const [displayedText, setDisplayedText] = useState('')

  useEffect(() => {
    if (!text) {
      setDisplayedText('')
      return
    }
    if (!text.startsWith(displayedText)) {
      setDisplayedText(text)
      return
    }
    if (displayedText === text) return
    const remaining = text.slice(displayedText.length)
    const match = remaining.match(/^\s*\S+/u)
    if (!match) {
      setDisplayedText(text)
      return
    }
    const id = setTimeout(() => {
      setDisplayedText(displayedText + match[0])
    }, WORD_REVEAL_MS)
    return () => clearTimeout(id)
  }, [text, displayedText])

  useEffect(() => {
    if (runState !== 'running' && text && displayedText !== text) {
      setDisplayedText(text)
    }
  }, [runState, text, displayedText])

  useEffect(() => {
    const element = scrollRef.current
    if (!element) return
    element.scrollTop = element.scrollHeight
  }, [response?.error, runState, displayedText])

  return (
    <div className="gemini-response">
      <div ref={scrollRef} aria-live="polite" className="gemini-response-scroll">
        {response?.error ? (
          <pre className="gemini-response-error">{response.error}</pre>
        ) : displayedText || runState === 'running' ? (
          <p className="gemini-response-text">
            {displayedText ? displayedText : <span className="gemini-response-placeholder">Opening paid stream</span>}
            {runState === 'running' ? <span className="gemini-response-caret" /> : null}
          </p>
        ) : (
          <div className="gemini-response-placeholder">Awaiting stream</div>
        )}
      </div>
    </div>
  )
}
