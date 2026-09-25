import { createFromJson } from 'codama';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';

const CODAMA_RUBY_REPO = 'https://github.com/lgalabru/codama-renderers-ruby.git';
const CODAMA_RUBY_COMMIT = '875672cd2e92007f5973dc335234c7e654153827';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..', '..');

const idlPath = path.join(repoRoot, 'idl', 'payment-channels.json');
const rubyClientDir = path.join(repoRoot, 'ruby', 'lib', 'pay_core', 'solana', 'generated');
const cacheDir = path.join(__dirname, '.codama-renderers-ruby');

if (!fs.existsSync(idlPath)) {
    console.error(`[codegen] IDL not found at ${idlPath}`);
    console.error(`[codegen] Run \`just payment-channels-pull-idl\` first to fetch it from upstream.`);
    process.exit(1);
}

const run = (cmd: string, args: string[], cwd: string) => execFileSync(cmd, args, { cwd, stdio: 'inherit' });

if (!fs.existsSync(path.join(cacheDir, 'package.json'))) {
    console.log(`[codegen] Cloning codama-renderers-ruby @ ${CODAMA_RUBY_COMMIT.slice(0, 8)}`);
    fs.rmSync(cacheDir, { force: true, recursive: true });
    run('git', ['clone', '--quiet', CODAMA_RUBY_REPO, cacheDir], __dirname);
}
run('git', ['checkout', '--quiet', CODAMA_RUBY_COMMIT], cacheDir);
run('pnpm', ['install', '--frozen-lockfile', '--ignore-scripts', '--silent'], cacheDir);
run('pnpm', ['build'], cacheDir);

const rendererPath = path.join(cacheDir, 'dist', 'index.node.mjs');
const { renderVisitor } = await import(pathToFileURL(rendererPath).href);
const codama = createFromJson(fs.readFileSync(idlPath, 'utf-8'));

console.log(`[codegen] Rendering Ruby client from ${path.relative(repoRoot, idlPath)}`);
console.log(`[codegen]   → ${path.relative(repoRoot, rubyClientDir)}/`);

await codama.accept(renderVisitor(rubyClientDir, { deleteFolderBeforeRendering: true, formatCode: true }));

const rubyFiles = collectRubyFiles(rubyClientDir);
for (const filePath of rubyFiles) {
    const original = fs.readFileSync(filePath, 'utf8');
    const patched = original
        .replaceAll('module PaymentChannels', 'module PayCore::Solana::Generated::PaymentChannels')
        .replaceAll('PaymentChannels::Error', 'PayCore::Solana::Generated::PaymentChannels::Error');
    fs.writeFileSync(filePath, patched);
}

const entry = path.join(rubyClientDir, 'payment_channels.rb');
const entryContent = fs.readFileSync(entry, 'utf8');
const namespace = `module PayCore\n  module Solana\n    module Generated\n    end\n  end\nend\n\n`;
if (!entryContent.includes('module Generated')) {
    fs.writeFileSync(entry, entryContent.replace("require_relative 'payment_channels/shared/errors'", namespace + "require_relative 'payment_channels/shared/errors'"));
}

for (const filePath of rubyFiles) {
    run('ruby', ['-c', filePath], repoRoot);
}

console.log(`[codegen] Done.`);

function collectRubyFiles(dir: string): string[] {
    const out: string[] = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const filePath = path.join(dir, entry.name);
        if (entry.isDirectory()) out.push(...collectRubyFiles(filePath));
        if (entry.isFile() && entry.name.endsWith('.rb')) out.push(filePath);
    }
    return out;
}
