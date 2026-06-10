/**
 * Regenerate `app/src/lib/docs.gen.ts` from the per-language READMEs.
 *
 * Reads each {lang}/README.md, extracts the first fenced code block under
 * the "Quick start" heading, and emits a typed module.
 *
 * Today this script is a placeholder — the in-tree docs.gen.ts is hand
 * curated so it can include the framework name and install command. To
 * automate, point each entry at a specific markdown anchor and use
 * `gray-matter` or a markdown AST walker (e.g. unified/remark) to
 * extract the snippet block.
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
    'docs.gen.ts is currently hand curated for layout reasons (framework + install per language).',
  )
  console.log('Wire this script up if you want full automation — see header comment for the plan.')
  void writeFile
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
