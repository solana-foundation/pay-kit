/**
 * Generate the pay-kit payment-channels client crate from the upstream
 * `Moonsong-Labs/solana-payment-channels` Codama IDL.
 *
 * Mirrors generate-subscriptions-client.ts — both scripts vendor the IDL
 * at `<repo-root>/idl/<program>.json` and render a Rust client into
 * `rust/crates/kit/src/generated/<program>/generated/`. See
 * `../references/codegen.md` for the broader rationale and for how to
 * add a third language renderer.
 *
 * Output:
 *   rust/crates/kit/src/generated/payment_channels/generated/   (rendered by Codama)
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

const idlPath = path.join(repoRoot, 'idl', 'payment-channels.json');
// The payment-channels client is inlined into the single publishable crate at
// rust/crates/kit/src/generated/payment_channels/generated/.
const rustClientDir = path.join(repoRoot, 'rust', 'crates', 'kit', 'src', 'generated', 'payment_channels');

if (!fs.existsSync(idlPath)) {
    console.error(`[codegen] IDL not found at ${idlPath}`);
    console.error(`[codegen] Run \`just payment-channels-pull-idl\` first to fetch it from upstream.`);
    process.exit(1);
}

const idl = JSON.parse(fs.readFileSync(idlPath, 'utf-8')) as AnchorIdl;
const codama = createFromJson(JSON.stringify(idl));

console.log(`[codegen] Rendering Rust client from ${path.relative(repoRoot, idlPath)}`);
console.log(`[codegen]   → ${path.relative(repoRoot, rustClientDir)}/generated/`);

void codama.accept(
    renderRustVisitor(rustClientDir, {
        anchorTraits: false,
        deleteFolderBeforeRendering: true,
        formatCode: true,
        generatedFolder: 'generated',
    }),
);

console.log(`[codegen] Done.`);
