import type { AnchorIdl } from '@codama/nodes-from-anchor';
import { renderVisitor as renderJsVisitor } from '@codama/renderers-js';
import { createFromJson } from 'codama';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, '..', '..', '..');
const idlPath = path.join(repoRoot, 'idl', 'subscriptions.json');
const tsClientDir = path.join(repoRoot, 'typescript', 'packages', 'mpp', 'src', 'generated', 'subscriptions');

if (!fs.existsSync(idlPath)) {
    console.error(`[codegen] IDL not found at ${idlPath}`);
    process.exit(1);
}

const idl = JSON.parse(fs.readFileSync(idlPath, 'utf-8')) as AnchorIdl;
const codama = createFromJson(JSON.stringify(idl));
const tmpPkg = fs.mkdtempSync(path.join(os.tmpdir(), 'subscriptions-ts-'));

void (async () => {
    await codama.accept(renderJsVisitor(tmpPkg, { formatCode: true }));

    const rendered = path.join(tmpPkg, 'src', 'generated');
    if (!fs.existsSync(rendered)) {
        throw new Error(`Expected rendered client at ${rendered}`);
    }
    fs.rmSync(tsClientDir, { force: true, recursive: true });
    fs.cpSync(rendered, tsClientDir, { recursive: true });
    fs.rmSync(tmpPkg, { force: true, recursive: true });

    const addJsExtensions = (dir: string): void => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, entry.name);
            if (entry.isDirectory()) {
                addJsExtensions(full);
                continue;
            }
            if (!entry.name.endsWith('.ts')) continue;
            const fileDir = path.dirname(full);
            const patched = fs.readFileSync(full, 'utf8').replace(
                /(from\s*['"])(\.\.?(?:\/[^'"]+)?)(['"])/g,
                (match, prefix: string, specifier: string, suffix: string) => {
                    if (specifier.endsWith('.js')) return match;
                    const resolved = path.resolve(fileDir, specifier);
                    const extension =
                        fs.existsSync(resolved) && fs.statSync(resolved).isDirectory() ? '/index.js' : '.js';
                    return `${prefix}${specifier}${extension}${suffix}`;
                },
            );
            fs.writeFileSync(full, patched);
        }
    };
    addJsExtensions(tsClientDir);
})();
