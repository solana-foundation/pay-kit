#!/usr/bin/env bash
# Emit docs/api/README.md — a markdown aggregator that links to each
# language's generated docs. A row's "open" link is live only when the
# language's docs/api/<lang>/README.md exists; missing ones fall back
# to the "run `just docs-<lang>`" hint. Invoked by `just docs-index`.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

emit_row() {
  local slug="$1" recipe_slug="$2" name="$3" generator="$4"
  local entry="docs/api/${slug}/README.md"
  if [[ -f "$entry" ]]; then
    printf '| %s | [open](./%s/) | %s |\n' "$name" "$slug" "$generator"
  else
    printf '| %s | _not yet generated — `just docs-%s`_ | %s |\n' "$name" "$recipe_slug" "$generator"
  fi
}

cat <<'HEAD'
# pay-kit API reference

Generated markdown reference for every language pay-kit ships. Each row links to the language's own `README.md` index inside this tree; that index links onward to per-module pages.

Re-run with `just docs` (all) or `just docs-<lang>` (one).

| Language | Docs | Generator |
|----------|------|-----------|
HEAD

emit_row typescript ts    "TypeScript" "typedoc + typedoc-plugin-markdown"
emit_row rust       rs    "Rust"       "cargo +nightly rustdoc JSON → scripts/rustdoc-to-md.mjs"
emit_row go         go    "Go"         "gomarkdoc"
emit_row python     py    "Python"     "pydoc-markdown"
emit_row ruby       rb    "Ruby"       "YARD::Registry → scripts/yard_to_md.rb"
emit_row php        php   "PHP"        "tokenizer + Reflection → scripts/php-doc-to-md.php"
emit_row lua        lua   "Lua"        "comment extraction → scripts/lua-doc-to-md.lua"
emit_row kotlin     kt    "Kotlin"     "Dokka GFM (\`dokkaGfm\` task)"
emit_row swift      swift "Swift"      "sourcedocs"

cat <<'FOOT'

_Regenerate this index with `just docs-index`._
FOOT
