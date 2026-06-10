#!/usr/bin/env node
// rustdoc-to-md — render rustdoc JSON output into a navigable markdown tree.
//
// The Rust ecosystem doesn't ship a maintained markdown doc generator. The
// closest thing is `cargo +nightly rustdoc -Z unstable-options --output-format json`,
// which emits a single JSON blob per crate describing every public item.
//
// This script walks one or more such JSON files and renders an index +
// per-module markdown into `docs/api/rust/`.
//
// Usage:
//   node scripts/rustdoc-to-md.mjs <out-dir> <crate.json> [<crate2.json> ...]
//
// Invoked from `just docs-rs` after `cargo +nightly rustdoc --output-format json`.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { resolve, dirname } from 'node:path'

const [outDir, ...jsonFiles] = process.argv.slice(2)
if (!outDir || jsonFiles.length === 0) {
  console.error('usage: rustdoc-to-md.mjs <out-dir> <crate.json> [more.json ...]')
  process.exit(2)
}

const crates = []
for (const file of jsonFiles) {
  const json = JSON.parse(readFileSync(file, 'utf-8'))
  const crateName = json.index?.[json.root]?.name ?? 'unknown'
  crates.push({ file, name: crateName, json })
}

mkdirSync(outDir, { recursive: true })

// Top-level index across all crates.
const indexLines = ['# Rust API reference', '']
indexLines.push('Generated from rustdoc JSON. One file per crate.', '')
indexLines.push('| Crate | Items | Source |', '|-------|------:|--------|')

for (const { name, json } of crates) {
  const items = Object.values(json.index ?? {})
  const publicItems = items.filter((i) => i.visibility === 'public' && i.crate_id === 0)
  const path = `${name}.md`
  indexLines.push(`| [\`${name}\`](./${path}) | ${publicItems.length} | rustdoc JSON |`)
  writeFileSync(resolve(outDir, path), renderCrate(name, json))
}

indexLines.push('')
indexLines.push(`_Regenerate with_ \`just docs-rs\`.`)
writeFileSync(resolve(outDir, 'README.md'), indexLines.join('\n'))
console.log(`Wrote ${crates.length} crate doc(s) + index to ${outDir}`)

function renderCrate(name, json) {
  const out = [`# Crate \`${name}\``, '']
  const index = json.index ?? {}
  const root = index[json.root]
  if (root?.docs) out.push(root.docs.trim(), '')

  const items = Object.values(index).filter(
    (i) => i.crate_id === 0 && i.visibility === 'public',
  )

  const groups = {
    Module: [],
    Struct: [],
    Enum: [],
    Trait: [],
    Function: [],
    TypeAlias: [],
    Constant: [],
    Macro: [],
  }

  for (const item of items) {
    const kind = kindOf(item)
    if (groups[kind]) groups[kind].push(item)
  }

  for (const [group, list] of Object.entries(groups)) {
    if (list.length === 0) continue
    out.push(`## ${group}s`, '')
    list.sort((a, b) => (a.name ?? '').localeCompare(b.name ?? ''))
    out.push('| Name | Summary |', '|------|---------|')
    for (const item of list) {
      const sig = item.name ?? '_anon_'
      const summary = (item.docs ?? '').split('\n')[0].trim() || '—'
      out.push(`| \`${sig}\` | ${escapeMd(summary)} |`)
    }
    out.push('')
  }

  if (items.length === 0) {
    out.push('_No public items._', '')
  }
  return out.join('\n')
}

function kindOf(item) {
  const inner = item.inner ?? {}
  if ('module' in inner) return 'Module'
  if ('struct' in inner) return 'Struct'
  if ('enum' in inner) return 'Enum'
  if ('trait' in inner) return 'Trait'
  if ('function' in inner) return 'Function'
  if ('type_alias' in inner) return 'TypeAlias'
  if ('constant' in inner) return 'Constant'
  if ('macro' in inner) return 'Macro'
  return 'Other'
}

function escapeMd(s) {
  return s.replace(/\|/g, '\\|').replace(/\n/g, ' ')
}
