/**
 * Generate the pay-kit subscriptions client crate from the upstream
 * `solana-foundation/subscriptions` Codama IDL.
 *
 * The IDL is expected to already be vendored at `<repo-root>/idl/subscriptions.json` —
 * the `just subscriptions-pull-idl` recipe fetches it from a pinned upstream
 * commit. Running this script standalone re-renders the Rust client without
 * re-fetching, so consumers can iterate on the generator config without an
 * extra network round-trip.
 *
 * Output:
 *   rust/crates/programs/subscriptions/src/generated/   (rendered by Codama)
 *
 * Mirrors the upstream `solana-foundation/subscriptions/scripts/generate-clients.ts`
 * stripped to the Rust-only path, so the layout of the generated tree is byte-for-byte
 * what a consumer who reads the upstream client would expect.
 */
import type { AnchorIdl } from '@codama/nodes-from-anchor';
import { renderVisitor as renderRustVisitor } from '@codama/renderers-rust';
import { createFromJson } from 'codama';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Script lives at skills/pay-sdk-implementation/codegen/ — climb three
// levels to land at the repository root.
const repoRoot = path.resolve(__dirname, '..', '..', '..');

const idlPath = path.join(repoRoot, 'idl', 'subscriptions.json');
const rustClientDir = path.join(repoRoot, 'rust', 'crates', 'programs', 'subscriptions');

if (!fs.existsSync(idlPath)) {
    console.error(`[codegen] IDL not found at ${idlPath}`);
    console.error(`[codegen] Run \`just subscriptions-pull-idl\` first to fetch it from upstream.`);
    process.exit(1);
}

const idl = JSON.parse(fs.readFileSync(idlPath, 'utf-8')) as AnchorIdl;
const codama = createFromJson(JSON.stringify(idl));

console.log(`[codegen] Rendering Rust client from ${path.relative(repoRoot, idlPath)}`);
console.log(`[codegen]   → ${path.relative(repoRoot, rustClientDir)}/src/generated/`);

void codama.accept(
    renderRustVisitor(rustClientDir, {
        // Pay-kit does not depend on Anchor at runtime. Generating bare Borsh
        // structs keeps the client free of `anchor-lang` transitively.
        anchorTraits: false,
        // Codama re-renders into `src/generated/` on every run; pre-clearing
        // means a removed instruction in the upstream IDL also disappears
        // here on regeneration.
        deleteFolderBeforeRendering: true,
        formatCode: true,
        generatedFolder: 'src/generated',
    }),
);

console.log(`[codegen] Done.`);
