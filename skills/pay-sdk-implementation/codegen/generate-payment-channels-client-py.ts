/**
 * Generate the pay-kit Python payment-channels client from the upstream
 * `Moonsong-Labs/solana-payment-channels` Codama IDL.
 *
 * Mirrors generate-payment-channels-client.ts (Rust) — both scripts read the
 * vendored IDL at `<repo-root>/idl/payment-channels.json`. This one renders a
 * Python client into `python/src/pay_kit/protocols/programs/paymentchannels/`
 * using the community `codama-py` renderer (Solana-ZH/codama-py).
 *
 * codama-py cannot be consumed as an npm/git dependency yet: its package.json
 * ships only `dist` (not committed, and its build is currently broken
 * upstream), so a git install packs an empty module. Until a fixed release
 * exists this script instead clones the repo at a pinned commit — the merge
 * of Solana-ZH/codama-py#10, which fixed PDA seed rendering — and drives its
 * own `genpy` CLI, exactly as the upstream README documents.
 *
 * Output:
 *   python/src/pay_kit/protocols/programs/paymentchannels/   (rendered by codama-py)
 */
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const CODAMA_PY_REPO = 'https://github.com/Solana-ZH/codama-py.git';
// Merge commit of Solana-ZH/codama-py#10 (PDA seed rendering fixes).
const CODAMA_PY_COMMIT = 'fcc75fc8abdf18cf4e0b3e4ae9338ddb60deb2e1';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Script lives at skills/pay-sdk-implementation/codegen/ — climb three
// levels to land at the repository root.
const repoRoot = path.resolve(__dirname, '..', '..', '..');

const idlPath = path.join(repoRoot, 'idl', 'payment-channels.json');
const pyClientDir = path.join(
    repoRoot,
    'python',
    'src',
    'pay_kit',
    'protocols',
    'programs',
    'paymentchannels',
);
const cacheDir = path.join(__dirname, '.codama-py');

if (!fs.existsSync(idlPath)) {
    console.error(`[codegen] IDL not found at ${idlPath}`);
    console.error(`[codegen] Run \`just payment-channels-pull-idl\` first to fetch it from upstream.`);
    process.exit(1);
}

const run = (cmd: string, args: string[], cwd: string) =>
    execFileSync(cmd, args, { cwd, stdio: 'inherit' });

if (!fs.existsSync(path.join(cacheDir, 'package.json'))) {
    console.log(`[codegen] Cloning codama-py @ ${CODAMA_PY_COMMIT.slice(0, 8)}`);
    fs.rmSync(cacheDir, { force: true, recursive: true });
    run('git', ['clone', '--quiet', CODAMA_PY_REPO, cacheDir], __dirname);
}
run('git', ['checkout', '--quiet', CODAMA_PY_COMMIT], cacheDir);
run('pnpm', ['install', '--frozen-lockfile', '--ignore-scripts', '--silent'], cacheDir);

console.log(`[codegen] Rendering Python client from ${path.relative(repoRoot, idlPath)}`);
console.log(`[codegen]   → ${path.relative(repoRoot, pyClientDir)}/`);

fs.rmSync(pyClientDir, { force: true, recursive: true });
run('pnpm', ['run', 'genpy', '-i', idlPath, '-d', pyClientDir], cacheDir);

// genpy swallows render errors (logs and exits 0), so verify the output.
const sentinel = path.join(pyClientDir, 'program_id.py');
if (!fs.existsSync(sentinel)) {
    console.error(`[codegen] Render produced no output at ${path.relative(repoRoot, pyClientDir)}`);
    process.exit(1);
}

console.log(`[codegen] Done.`);
