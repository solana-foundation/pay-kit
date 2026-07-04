import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

// Repository-hygiene guards. These are not about product behaviour; they
// permanently pin two dependency-supply-chain invariants so a stale or
// re-vendored tarball cannot silently re-enter the tree:
//
//   1. No *committed* `.tgz` tarballs anywhere under typescript/packages/**.
//      The live @solana/mpp dep is resolved via `workspace:^`, and the live
//      x402 vendored tarballs live under typescript/.x402-vendor (outside
//      packages/). A tracked tarball under packages/ is therefore always
//      stale. This is keyed on the git index rather than the working tree so
//      a local, gitignored `pnpm pack` artifact does not fail the suite.
//   2. The ignore rule that keeps future *.tgz out of packages/mpp is present,
//      so an accidental re-vendor is untracked by default.

// Resolve the repo root from this file's location so the checks are independent
// of the process cwd (vitest is invoked from typescript/).
const thisFile = fileURLToPath(import.meta.url);
// .../typescript/packages/pay-kit/src/__tests__/repo-hygiene.test.ts
const repoRoot = path.resolve(path.dirname(thisFile), '..', '..', '..', '..', '..');

// Both guards depend on a real git checkout. Source tarballs and some CI
// mirrors have no `.git`; there the invariants cannot be evaluated and the
// tests skip with an explanatory message rather than erroring.
function isInsideGitWorkTree(): boolean {
    try {
        const out = execFileSync('git', ['rev-parse', '--is-inside-work-tree'], {
            cwd: repoRoot,
            stdio: ['ignore', 'pipe', 'ignore'],
            encoding: 'utf8',
        });
        return out.trim() === 'true';
    } catch {
        return false;
    }
}

const insideGit = isInsideGitWorkTree();
const skipReason = 'not a git checkout (no .git); tarball-hygiene guards require git';

describe('repo hygiene: vendored tarballs', () => {
    it('has no committed .tgz tarballs under typescript/packages', ctx => {
        if (!insideGit) {
            ctx.skip(skipReason);
            return;
        }
        // Key on the git index, not the working tree: a locally built,
        // gitignored `pnpm pack` artifact must not fail this guard, while a
        // committed tarball still does. The pathspecs are resolved by git
        // relative to `repoRoot`, independent of the vitest cwd. Two patterns
        // are needed because git's `**` glob only spans nested directories:
        // `packages/*.tgz` catches a tarball dropped directly under packages/,
        // and `packages/**/*.tgz` catches any tarball nested below it.
        const out = execFileSync(
            'git',
            ['ls-files', '-z', '--', 'typescript/packages/*.tgz', 'typescript/packages/**/*.tgz'],
            {
                cwd: repoRoot,
                encoding: 'utf8',
            },
        );
        const tracked = out.split('\0').filter(entry => entry.length > 0);
        expect(tracked).toEqual([]);
    });

    it('gitignores future *.tgz under typescript/packages/mpp', ctx => {
        if (!insideGit) {
            ctx.skip(skipReason);
            return;
        }
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
