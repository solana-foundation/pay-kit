/**
 * Generate the pay-kit payment-channels TypeScript client from the upstream
 * `Moonsong-Labs/solana-payment-channels` Codama IDL.
 *
 * Mirrors generate-payment-channels-client-rs.ts (Rust) and
 * generate-payment-channels-client-go.ts (Go) — all three read the vendored IDL
 * at `<repo-root>/idl/payment-channels.json` and render a client into the
 * matching SDK tree. This one targets the `@solana/kit`-based JS/TS SDK via
 * `@codama/renderers-js`, replacing the previously hand-vendored subset under
 * `typescript/packages/mpp/src/generated/payment-channels/`.
 *
 * Output:
 *   typescript/packages/mpp/src/generated/payment-channels/   (rendered by Codama)
 */
import type { AnchorIdl } from "@codama/nodes-from-anchor";
import { renderVisitor as renderJsVisitor } from "@codama/renderers-js";
import { createFromJson } from "codama";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
// Script lives at skills/pay-sdk-implementation/codegen/ — climb three
// levels to land at the repository root.
const repoRoot = path.resolve(__dirname, "..", "..", "..");

const idlPath = path.join(repoRoot, "idl", "payment-channels.json");
const tsClientDir = path.join(
  repoRoot,
  "typescript",
  "packages",
  "mpp",
  "src",
  "generated",
  "payment-channels",
);

if (!fs.existsSync(idlPath)) {
  console.error(`[codegen] IDL not found at ${idlPath}`);
  console.error(
    `[codegen] Run \`just payment-channels-pull-idl\` first to fetch it from upstream.`,
  );
  process.exit(1);
}

const idl = JSON.parse(fs.readFileSync(idlPath, "utf-8")) as AnchorIdl;
const codama = createFromJson(JSON.stringify(idl));

console.log(
  `[codegen] Rendering TypeScript client from ${path.relative(repoRoot, idlPath)}`,
);
console.log(`[codegen]   → ${path.relative(repoRoot, tsClientDir)}/`);

// `@codama/renderers-js` writes a full package scaffold (package.json +
// `src/generated/`), unlike the flat Rust/Go renderers. We only want the flat
// client modules in the SDK tree, so render into a temp package, then lift its
// `src/generated/` contents into `tsClientDir`.
const tmpPkg = fs.mkdtempSync(path.join(os.tmpdir(), "paychan-ts-"));

void (async () => {
  await codama.accept(renderJsVisitor(tmpPkg, { formatCode: true }));

  const rendered = path.join(tmpPkg, "src", "generated");
  if (!fs.existsSync(rendered)) {
    console.error(`[codegen] expected rendered client at ${rendered}`);
    process.exit(1);
  }
  // Replace the target wholesale so an instruction/type removed upstream also
  // disappears here on regeneration.
  fs.rmSync(tsClientDir, { recursive: true, force: true });
  fs.cpSync(rendered, tsClientDir, { recursive: true });
  fs.rmSync(tmpPkg, { recursive: true, force: true });

  // The renderer emits extensionless relative specifiers; the mpp package
  // uses `node16` module resolution, which requires explicit `.js` on
  // relative imports. Append it to every relative import/export.
  const addJsExtensions = (dir: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        addJsExtensions(full);
      } else if (entry.name.endsWith(".ts")) {
        const fileDir = path.dirname(full);
        const patched = fs
          .readFileSync(full, "utf-8")
          .replace(
            /(from\s*['"])(\.\.?(?:\/[^'"]+)?)(['"])/g,
            (m, pre, spec, post) => {
              if (spec.endsWith(".js")) return m;
              // A specifier that points at a directory (barrel, incl.
              // bare "." / "..") resolves to its index under node16; a
              // file gets a plain `.js`.
              const resolved = path.resolve(fileDir, spec);
              const suffix =
                fs.existsSync(resolved) && fs.statSync(resolved).isDirectory()
                  ? "/index.js"
                  : ".js";
              return `${pre}${spec}${suffix}${post}`;
            },
          );
        fs.writeFileSync(full, patched);
      }
    }
  };
  addJsExtensions(tsClientDir);

  console.log(`[codegen] Done.`);
})();
