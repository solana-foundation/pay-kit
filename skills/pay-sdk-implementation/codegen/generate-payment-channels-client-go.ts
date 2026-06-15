/**
 * Generate the pay-kit payment-channels Go client from the upstream
 * `Moonsong-Labs/solana-payment-channels` Codama IDL.
 *
 * Mirrors generate-payment-channels-client.ts (the Rust path) — both scripts
 * vendor the IDL at `<repo-root>/idl/payment-channels.json` and render a client
 * into the matching SDK tree. This one targets the Go SDK via
 * `@codama/renderers-go`, which emits a flat Go package using
 * github.com/gagliardetto/{solana-go,binary} (already pay-kit Go deps).
 *
 * The renderer derives the Go package name from the IDL program name
 * (`paymentChannels` → `payment_channels`). We render into a directory named
 * `paymentchannels/` to keep a clean, import-friendly path that mirrors the
 * rust `crates/programs/payment-channels/generated` layout.
 *
 * Output:
 *   go/protocols/programs/paymentchannels/   (rendered by Codama)
 */
import type { AnchorIdl } from '@codama/nodes-from-anchor';
import { renderVisitor as renderGoVisitor } from '@codama/renderers-go';
import { createFromJson } from 'codama';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Script lives at skills/pay-sdk-implementation/codegen/ — climb three
// levels to land at the repository root.
const repoRoot = path.resolve(__dirname, '..', '..', '..');

const idlPath = path.join(repoRoot, 'idl', 'payment-channels.json');
const goClientDir = path.join(repoRoot, 'go', 'protocols', 'programs', 'paymentchannels');

if (!fs.existsSync(idlPath)) {
    console.error(`[codegen] IDL not found at ${idlPath}`);
    console.error(`[codegen] Run \`just payment-channels-pull-idl\` first to fetch it from upstream.`);
    process.exit(1);
}

const idl = JSON.parse(fs.readFileSync(idlPath, 'utf-8')) as AnchorIdl;
const codama = createFromJson(JSON.stringify(idl));

console.log(`[codegen] Rendering Go client from ${path.relative(repoRoot, idlPath)}`);
console.log(`[codegen]   → ${path.relative(repoRoot, goClientDir)}/`);

void codama.accept(
    renderGoVisitor(goClientDir, {
        // Codama re-renders into the target folder on every run; pre-clearing
        // means a removed instruction in the upstream IDL also disappears here
        // on regeneration.
        deleteFolderBeforeRendering: true,
        // gofmt the emitted Go so `gofmt -l` stays clean on the generated tree.
        formatCode: true,
    }),
);

console.log(`[codegen] Done.`);
