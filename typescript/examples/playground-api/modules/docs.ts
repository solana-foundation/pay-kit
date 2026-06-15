import type { Express, Request, Response as ExpressResponse } from 'express'
import { readdir, readFile, stat } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
// docs/api lives at the repo root, two levels above server/modules/.
const DOCS_ROOT = path.resolve(__dirname, '..', '..', '..', 'docs', 'api')

const LANGS = ['typescript', 'rust', 'go', 'python', 'ruby', 'php', 'lua', 'kotlin', 'swift'] as const
type Lang = (typeof LANGS)[number]

interface TreeNode {
  name: string
  path: string
  type: 'file' | 'dir'
  children?: TreeNode[]
}

async function buildTree(absDir: string, relDir = ''): Promise<TreeNode[]> {
  const entries = await readdir(absDir, { withFileTypes: true })
  const nodes: TreeNode[] = []
  for (const entry of entries) {
    if (entry.name.startsWith('.') || entry.name === 'node_modules') continue
    const relPath = relDir ? `${relDir}/${entry.name}` : entry.name
    const absPath = path.join(absDir, entry.name)
    if (entry.isDirectory()) {
      nodes.push({
        name: entry.name,
        path: relPath,
        type: 'dir',
        children: await buildTree(absPath, relPath),
      })
    } else if (entry.isFile() && entry.name.endsWith('.md')) {
      nodes.push({ name: entry.name, path: relPath, type: 'file' })
    }
  }
  // Folders first, then files; both alpha.
  nodes.sort((a, b) => {
    if (a.type !== b.type) return a.type === 'dir' ? -1 : 1
    return a.name.localeCompare(b.name)
  })
  return nodes
}

/** Reject any path that escapes the language root. */
function safeJoin(root: string, rel: string): string | null {
  const joined = path.resolve(root, rel)
  const rel2 = path.relative(root, joined)
  if (rel2.startsWith('..') || path.isAbsolute(rel2)) return null
  return joined
}

export function registerDocs(app: Express): void {
  // GET /api/v1/docs — which languages have generated docs?
  app.get('/api/v1/docs', async (_req: Request, res: ExpressResponse) => {
    const available: Record<Lang, boolean> = Object.fromEntries(LANGS.map((l) => [l, false])) as Record<Lang, boolean>
    for (const lang of LANGS) {
      const readme = path.join(DOCS_ROOT, lang, 'README.md')
      try {
        await stat(readme)
        available[lang] = true
      } catch {
        /* not generated yet */
      }
    }
    res.json({ root: DOCS_ROOT, available })
  })

  // GET /api/v1/docs/:lang/tree — file tree under docs/api/:lang/
  app.get('/api/v1/docs/:lang/tree', async (req: Request, res: ExpressResponse) => {
    const lang = String(req.params.lang)
    if (!(LANGS as readonly string[]).includes(lang)) {
      res.status(404).json({ error: 'unknown_lang' })
      return
    }
    const root = path.join(DOCS_ROOT, lang)
    try {
      await stat(root)
    } catch {
      res.status(404).json({ error: 'not_generated', hint: `Run: just docs-${recipeSlug(lang)}` })
      return
    }
    try {
      const tree = await buildTree(root)
      res.json({ lang, tree })
    } catch (err) {
      res.status(500).json({ error: 'tree_failed', detail: errMessage(err) })
    }
  })

  // GET /api/v1/docs/:lang/file?path=foo/bar.md — raw markdown content
  app.get('/api/v1/docs/:lang/file', async (req: Request, res: ExpressResponse) => {
    const lang = String(req.params.lang)
    if (!(LANGS as readonly string[]).includes(lang)) {
      res.status(404).json({ error: 'unknown_lang' })
      return
    }
    const rel = String(req.query.path ?? 'README.md')
    const root = path.join(DOCS_ROOT, lang)
    const abs = safeJoin(root, rel)
    if (!abs) {
      res.status(400).json({ error: 'unsafe_path' })
      return
    }
    if (!abs.endsWith('.md')) {
      res.status(400).json({ error: 'not_markdown' })
      return
    }
    try {
      const content = await readFile(abs, 'utf-8')
      res.type('text/markdown').send(content)
    } catch (err) {
      res.status(404).json({ error: 'not_found', detail: errMessage(err) })
    }
  })
}

function recipeSlug(lang: string): string {
  switch (lang) {
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
      return lang
  }
}

function errMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}
