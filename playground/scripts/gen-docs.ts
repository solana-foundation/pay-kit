/**
 * Diagnostic for `app/src/lib/docs.gen.ts` — scans the per-language READMEs
 * and reports which ones expose a usable quickstart code block.
 *
 * Today this script is a placeholder and does NOT write docs.gen.ts. The
 * in-tree docs.gen.ts derives language cards from the generated snippets
 * manifest (snippets.gen.json, produced by scripts/gen-snippets.mjs) and
 * falls back to curated per-language entries for languages whose snippets
 * haven't been migrated to `<lang>/docs/snippets/` yet. To automate the
 * curated half, point each entry at a specific markdown anchor and use a
 * markdown AST walker (e.g. unified/remark) to extract the snippet block.
 *
 * Run with: pnpm docs:gen
 */
import { readFile, writeFile } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const ROOT = path.resolve(__dirname, '..', '..')

const LANGS = ['typescript', 'rust', 'go', 'python', 'ruby', 'php', 'lua', 'kotlin', 'swift']

async function extractFirstCodeBlock(file: string): Promise<string | null> {
  const text = await readFile(file, 'utf-8')
  const re = /```[\w]*\n([\s\S]*?)```/g
  let match
  while ((match = re.exec(text)) !== null) {
    const code = match[1]?.trim() ?? ''
    if (code.length > 50) return code
  }
  return null
}

async function main() {
  console.log('Scanning per-language READMEs…')
  for (const lang of LANGS) {
    const file = path.join(ROOT, lang, 'README.md')
    try {
      const code = await extractFirstCodeBlock(file)
      console.log(`  ${lang.padEnd(12)} ${code ? `${code.split('\n').length} lines` : '(no block)'}`)
    } catch {
      console.log(`  ${lang.padEnd(12)} (README missing)`)
    }
  }
  console.log()
  console.log(
    'docs.gen.ts derives cards from snippets.gen.json (run `pnpm gen-snippets`), with curated',
  )
  console.log('fallbacks for unmigrated languages — see the header comment for the automation plan.')
  void writeFile
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
