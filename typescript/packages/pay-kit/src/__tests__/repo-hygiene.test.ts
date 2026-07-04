import { execFileSync } from 'node:child_process';
import { readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// Repository-hygiene guards. These are not about product behaviour; they
// permanently pin two dependency-supply-chain invariants so a stale or
// re-vendored tarball cannot silently re-enter the tree:
//
//   1. No committed `.tgz` tarballs anywhere under typescript/packages/**.
//      The live @solana/mpp dep is resolved via `workspace:^`, and the live
//      x402 vendored tarballs live under typescript/.x402-vendor (outside
//      packages/). A tarball under packages/ is therefore always stale.
//   2. The ignore rule that keeps future *.tgz out of packages/mpp is present,
//      so an accidental re-vendor is untracked by default.

// Resolve the repo root from this file's location so the checks are independent
// of the process cwd (vitest is invoked from typescript/).
const thisFile = fileURLToPath(import.meta.url);
// .../typescript/packages/pay-kit/src/__tests__/repo-hygiene.test.ts
const repoRoot = path.resolve(path.dirname(thisFile), '..', '..', '..', '..', '..');
const packagesDir = path.join(repoRoot, 'typescript', 'packages');

// Recursively collect every *.tgz under a directory, skipping node_modules.
function findTarballs(dir: string): string[] {
    const found: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.name === 'node_modules') continue;
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            found.push(...findTarballs(full));
        } else if (entry.isFile() && entry.name.endsWith('.tgz')) {
            found.push(path.relative(repoRoot, full));
        }
    }
    return found;
}

describe('repo hygiene: vendored tarballs', () => {
    it('has no committed .tgz tarballs under typescript/packages', () => {
        const tarballs = findTarballs(packagesDir);
        expect(tarballs).toEqual([]);
    });

    it('gitignores future *.tgz under typescript/packages/mpp', () => {
        // A path that does not exist on disk; git check-ignore evaluates it
        // against the ignore rules purely by pattern. Exit code 0 => ignored.
        const candidate = 'typescript/packages/mpp/solana-mpp-9.9.9.tgz';
        let ignored = false;
        try {
            execFileSync('git', ['check-ignore', '--quiet', candidate], {
                cwd: repoRoot,
                stdio: 'ignore',
            });
            ignored = true;
        } catch {
            ignored = false;
        }
        expect(ignored).toBe(true);
    });
});
