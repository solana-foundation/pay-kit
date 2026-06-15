import { useState, useEffect, useMemo } from 'react'
import { useParams, useSearchParams, Link } from 'react-router-dom'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { LANG_DOCS } from '../lib/docs.gen'

interface TreeNode {
  name: string
  path: string
  type: 'file' | 'dir'
  children?: TreeNode[]
}

interface TreeResponse {
  lang: string
  tree: TreeNode[]
}

export function ApiReference() {
  const { lang } = useParams<{ lang: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const filePath = searchParams.get('file') ?? 'README.md'
  const [tree, setTree] = useState<TreeNode[] | null>(null)
  const [content, setContent] = useState<string>('')
  const [error, setError] = useState<string | null>(null)
  const [loadingTree, setLoadingTree] = useState(true)
  const [loadingFile, setLoadingFile] = useState(false)

  const langMeta = useMemo(() => LANG_DOCS.find((d) => d.id === lang), [lang])

  useEffect(() => {
    if (!lang) return
    setLoadingTree(true)
    setError(null)
    fetch(`/api/v1/docs/${lang}/tree`)
      .then(async (r) => {
        if (!r.ok) {
          const data = (await r.json().catch(() => ({}))) as { hint?: string; error?: string }
          throw new Error(data.hint || data.error || `tree ${r.status}`)
        }
        return r.json() as Promise<TreeResponse>
      })
      .then((data) => setTree(data.tree))
      .catch((e) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoadingTree(false))
  }, [lang])

  useEffect(() => {
    if (!lang) return
    setLoadingFile(true)
    fetch(`/api/v1/docs/${lang}/file?path=${encodeURIComponent(filePath)}`)
      .then(async (r) => {
        if (!r.ok) throw new Error(`file ${r.status}`)
        return r.text()
      })
      .then(setContent)
      .catch((e) => setContent(`# Error\n\n${e instanceof Error ? e.message : String(e)}`))
      .finally(() => setLoadingFile(false))
  }, [lang, filePath])

  if (!langMeta) {
    return (
      <div className="docs-page">
        <h2>Unknown language</h2>
        <p className="lede">
          <Link to="/docs">← Back to language list</Link>
        </p>
      </div>
    )
  }

  return (
    <>
      <div className="page-head">
        <Link to="/docs" className="apidoc-back">
          ← Docs
        </Link>
        <span className="path">
          {langMeta.name} <span style={{ color: 'var(--fg-muted)' }}>· API reference</span>
        </span>
        <span className="desc">{langMeta.framework}</span>
        <a href={langMeta.href} target="_blank" rel="noopener" className="meta-pill">
          README ↗
        </a>
      </div>

      <div className="apidoc-layout">
        <aside className="apidoc-tree">
          {loadingTree && <div className="apidoc-empty">Loading file tree…</div>}
          {error && !loadingTree && (
            <div className="apidoc-empty" style={{ color: 'var(--yellow)' }}>
              {error}
            </div>
          )}
          {tree && (
            <Tree
              nodes={tree}
              activePath={filePath}
              onSelect={(p) => setSearchParams({ file: p }, { replace: true })}
            />
          )}
        </aside>
        <main className="apidoc-content">
          {loadingFile ? (
            <div className="apidoc-empty pulsing">Loading…</div>
          ) : (
            <div className="markdown-body">
              <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                  a: ({ href, children, ...props }) => {
                    if (!href) return <a {...props}>{children}</a>
                    // Internal .md links inside the same lang dir
                    if (href.endsWith('.md') || href.endsWith('.md/') || href.includes('.md#')) {
                      const resolved = resolvePath(filePath, href)
                      return (
                        <Link to={`/docs/ref/${lang}?file=${encodeURIComponent(resolved)}`}>
                          {children}
                        </Link>
                      )
                    }
                    return (
                      <a href={href} target="_blank" rel="noopener" {...props}>
                        {children}
                      </a>
                    )
                  },
                }}
              >
                {content}
              </ReactMarkdown>
            </div>
          )}
        </main>
      </div>
    </>
  )
}

function Tree({
  nodes,
  activePath,
  onSelect,
  depth = 0,
}: {
  nodes: TreeNode[]
  activePath: string
  onSelect: (path: string) => void
  depth?: number
}) {
  return (
    <ul className="apidoc-tree-list" style={{ paddingLeft: depth === 0 ? 0 : 12 }}>
      {nodes.map((n) => (
        <TreeNode key={n.path} node={n} activePath={activePath} onSelect={onSelect} depth={depth} />
      ))}
    </ul>
  )
}

function TreeNode({
  node,
  activePath,
  onSelect,
  depth,
}: {
  node: TreeNode
  activePath: string
  onSelect: (path: string) => void
  depth: number
}) {
  const [open, setOpen] = useState(depth < 2)
  if (node.type === 'dir') {
    return (
      <li>
        <button
          className="apidoc-tree-dir"
          onClick={() => setOpen((v) => !v)}
          aria-expanded={open}
        >
          <span className="apidoc-tree-caret">{open ? '▾' : '▸'}</span>
          {node.name}
        </button>
        {open && node.children && (
          <Tree nodes={node.children} activePath={activePath} onSelect={onSelect} depth={depth + 1} />
        )}
      </li>
    )
  }
  const isActive = node.path === activePath
  return (
    <li>
      <button
        className={`apidoc-tree-file${isActive ? ' active' : ''}`}
        onClick={() => onSelect(node.path)}
      >
        {node.name}
      </button>
    </li>
  )
}

function resolvePath(from: string, to: string): string {
  // Trim trailing slashes / hash refs.
  const cleanedTo = to.replace(/#.*$/, '').replace(/\/$/, '')
  if (cleanedTo.startsWith('/')) return cleanedTo.slice(1)
  const parts = from.split('/').slice(0, -1)
  for (const seg of cleanedTo.split('/')) {
    if (seg === '..') parts.pop()
    else if (seg !== '.') parts.push(seg)
  }
  return parts.join('/')
}
