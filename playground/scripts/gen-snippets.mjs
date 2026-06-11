#!/usr/bin/env node
// Extract per-language playground snippets from each language's
// docs/snippets/ directory (the ROOTS table below) into a single JSON
// manifest the playground's snippets.ts imports at build time.
//
// Convention (see docs/snippets-convention.md):
//   <lang root>/<primitive>.<side>.<ext>
//   File contains a region bracketed by `snippet:start` … `snippet:end`
//   (any comment syntax) that's extracted verbatim.

import { readdir, readFile, writeFile, mkdir } from 'node:fs/promises'
import { existsSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = resolve(__dirname, '..', '..')

/** Where each language's snippet examples live, relative to repo root. */
const ROOTS = {
  typescript: 'typescript/docs/snippets',
  rust: 'rust/docs/snippets',
  go: 'go/docs/snippets',
  python: 'python/docs/snippets',
  ruby: 'ruby/docs/snippets',
  php: 'php/docs/snippets',
  lua: 'lua/docs/snippets',
  kotlin: 'kotlin/docs/snippets',
  swift: 'swift/docs/snippets',
}

const PRIMITIVES = ['charge', 'subscription', 'session', 'x402']
const SIDES = ['client', 'server']

const FILENAME_RE = /^(charge|subscription|session|x402)\.(client|server)\.[^.]+$/
// Marker must be the last meaningful token on its line — only horizontal
// whitespace allowed after it. That keeps in-file prose references like
// `snippet:start/end` from matching by accident.
const MARKER_RE = /(?:^|\n)[^\n]*\bsnippet:start[ \t]*\n([\s\S]*?)\n[^\n]*\bsnippet:end[ \t]*(?:\n|$)/

const OUTPUT = resolve(__dirname, '..', 'app', 'src', 'lib', 'snippets.gen.json')

/**
 * @param {string} text
 * @returns {string | null}
 */
function extractRegion(text) {
  const m = text.match(MARKER_RE)
  if (!m) return null
  // Normalize: strip common leading whitespace so the snippet renders flush.
  const region = m[1]
  const lines = region.split('\n')
  let minIndent = Infinity
  for (const line of lines) {
    if (line.trim().length === 0) continue
    const indent = line.match(/^(\s*)/)?.[1].length ?? 0
    if (indent < minIndent) minIndent = indent
  }
  if (minIndent === Infinity || minIndent === 0) return region
  return lines.map((l) => l.slice(minIndent)).join('\n')
}

/**
 * @param {string} langRoot absolute
 * @returns {Promise<Record<string, Partial<Record<'client' | 'server', string>>>>}
 */
async function readLangSnippets(langRoot) {
  /** @type {Record<string, Partial<Record<'client' | 'server', string>>>} */
  const out = {}
  if (!existsSync(langRoot)) return out
  const entries = await readdir(langRoot, { withFileTypes: true })
  for (const entry of entries) {
    if (!entry.isFile()) continue
    const match = entry.name.match(FILENAME_RE)
    if (!match) continue
    const [, primitive, side] = match
    const full = join(langRoot, entry.name)
    const text = await readFile(full, 'utf8')
    const region = extractRegion(text)
    if (region === null) {
      console.warn(`[gen-snippets] ${relative(ROOT, full)}: no snippet:start/end markers found — skipping`)
      continue
    }
    if (!out[primitive]) out[primitive] = {}
    out[primitive][side] = region
  }
  return out
}

async function main() {
  /** @type {Record<string, Record<string, Partial<Record<'client' | 'server', string>>>>} */
  const manifest = {}
  for (const [lang, rel] of Object.entries(ROOTS)) {
    const abs = resolve(ROOT, rel)
    const snippets = await readLangSnippets(abs)
    if (Object.keys(snippets).length > 0) {
      manifest[lang] = snippets
    }
  }

  await mkdir(dirname(OUTPUT), { recursive: true })
  await writeFile(OUTPUT, JSON.stringify(manifest, null, 2) + '\n', 'utf8')

  const counts = Object.entries(manifest)
    .map(([lang, prims]) => {
      const n = Object.values(prims).reduce(
        (sum, sides) => sum + Object.keys(sides).length,
        0,
      )
      return `${lang}:${n}`
    })
    .join(' ')
  console.log(`[gen-snippets] wrote ${relative(ROOT, OUTPUT)} — ${counts || '(empty)'}`)

  // Surface obvious gaps so contributors see what's missing.
  for (const lang of Object.keys(ROOTS)) {
    const prims = manifest[lang] ?? {}
    for (const primitive of PRIMITIVES) {
      for (const side of SIDES) {
        if (!prims[primitive]?.[side]) {
          // Not all (lang, primitive, side) combos make sense — silent by default.
        }
      }
    }
  }
}

main().catch((err) => {
  console.error('[gen-snippets] failed:', err)
  process.exit(1)
})
