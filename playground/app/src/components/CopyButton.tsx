import { useState } from 'react'

interface Props {
  text: string
  className?: string
}

export function CopyButton({ text, className }: Props) {
  const [copied, setCopied] = useState(false)

  const onCopy = (e: React.MouseEvent) => {
    e.stopPropagation()
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }

  return (
    <button className={`copy-btn${copied ? ' copied' : ''}${className ? ' ' + className : ''}`} onClick={onCopy}>
      {copied ? 'copied' : 'copy'}
    </button>
  )
}
