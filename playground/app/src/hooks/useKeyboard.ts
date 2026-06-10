import { useEffect } from 'react'

type Handler = (e: KeyboardEvent) => void

export interface KeyBinding {
  key: string
  meta?: boolean
  shift?: boolean
  preventDefault?: boolean
  handler: Handler
}

export function useKeyboard(bindings: KeyBinding[]) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      for (const b of bindings) {
        if (e.key !== b.key) continue
        if (b.meta && !(e.metaKey || e.ctrlKey)) continue
        if (b.shift !== undefined && e.shiftKey !== b.shift) continue
        if (b.preventDefault !== false) e.preventDefault()
        b.handler(e)
        return
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [bindings])
}

export function isMac(): boolean {
  if (typeof navigator === 'undefined') return false
  return /Mac|iPhone|iPod|iPad/.test(navigator.platform)
}
