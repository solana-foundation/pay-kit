#!/usr/bin/env node
import { readFileSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const ledgerPath = resolve(root, '.github/delivery/pr216-ledger.json');
const ledger = JSON.parse(readFileSync(ledgerPath, 'utf8'));
const currentHead = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: root, encoding: 'utf8' }).trim();

const deliveries = {
    214: ['fix/go-idiomatic-cleanup', '92bdcbf'],
    227: ['fix/rust-security-hardening', '205b3d8'],
    228: ['fix/python-security-hardening', '8ac54e8'],
    229: ['fix/php-security-hardening', '0bd30c1'],
    230: ['fix/kotlin-canonical-json-hardening', 'd286dd9'],
    231: ['fix/swift-conformance-hardening', '63ca1c3'],
    232: ['fix/typescript-security-hardening', '74d4d99'],
    233: ['fix/harness-adversarial-hardening', 'd9815dc'],
    236: ['fix/x402-replay-hardening', '10708ce'],
    237: ['fix/mpp-replay-store-hardening', '9bfd9e1'],
    238: ['fix/mpp-subscription-hardening', '1865dfb'],
    239: ['fix/mpp-session-state-hardening', '34e7456'],
};

const commitOwners = new Map([
    ['3bb8202', [214, 231]],
    ['272190c', [229]],
    ['cd9d245', [227]],
    ['e51727e', [227]],
    ['a707983', [227]],
    ['f1830dc', [230]],
    ['a99a571', [227]],
    ['7faeb0d', [232, 237]],
    ['0ca5ef5', [239]],
    ['2cca2ce', [214]],
    ['51d1c4a', [214]],
    ['8fd892b', [228]],
    ['09b7e5f', [228]],
    ['232bf91', [238]],
    ['fa8ce84', [228]],
    ['1ed6204', [227]],
    ['fc6aabb', [214]],
    ['ca15d94', [232]],
    ['4efd4bb', [233]],
    ['ef6e977', [232]],
    ['36d493f', [238]],
    ['45ad8c9', [238]],
]);

function ownersForPath(path, bucket) {
    if (bucket === 'go') return [214];
    if (bucket === 'kotlin') return [230];
    if (bucket === 'php') return [229];
    if (bucket === 'rust') return [227];
    if (bucket === 'swift') return [231];
    if (bucket === 'python') {
        if (path.includes('/x402/')) return [236];
        if (path.includes('session_topup') || path.includes('session_voucher')) return [239];
        return [228];
    }
    if (bucket === 'typescript') {
        if (path.endsWith('.tgz') || path.includes('repo-hygiene')) return [233];
        if (path.includes('subscription')) return [238];
        if (path.includes('session-') || path.includes('/session')) return [239];
        if (path.includes('replay')) return [237];
        return [232];
    }
    return [233];
}

function markOpen(record, prs, label) {
    const named = prs.map((pr) => {
        const [branch, commit] = deliveries[pr];
        return { pr, branch, deliveryCommit: commit };
    });
    record.status = 'open_pr';
    record.evidence = named.map(({ pr, branch, deliveryCommit }) => ({
        kind: 'open-delivery-head',
        pr,
        branch,
        deliveryCommit,
        detail: `${label} is assigned to PR #${pr} at or beyond ${deliveryCommit}; merge-time validation must replace this open evidence with exact integrated tree evidence.`,
    }));
    record.owner = named.map(({ pr, branch }) => `PR #${pr} / ${branch}`).join('; ');
    record.followUp = `Land ${named.map(({ pr }) => `PR #${pr}`).join(' and ')}, then revalidate semantic and exact tree-state delivery on #219.`;
}

for (const record of ledger.commits) {
    if (record.status !== 'missing' && record.status !== 'open_pr') continue;
    const owners = commitOwners.get(record.sha.slice(0, 7));
    if (!owners) throw new Error(`missing commit owner: ${record.sha}`);
    markOpen(record, owners, `Source commit ${record.sha}`);
}

for (const record of ledger.paths) {
    if (record.status === 'missing' || record.status === 'open_pr') {
        markOpen(record, ownersForPath(record.path, record.bucket), `Source path ${record.path}`);
        continue;
    }
    if (record.status !== 'integrated') continue;
    const identity = record.evidence.find((item) => item.kind === 'identical-tree-entry');
    if (!identity) throw new Error(`integrated path lacks identity evidence: ${record.path}`);
    let currentBlob;
    try {
        currentBlob = execFileSync('git', ['rev-parse', `${currentHead}:${record.path}`], {
            cwd: root,
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore'],
        }).trim();
    } catch {
        currentBlob = undefined;
    }
    if (currentBlob === identity.sourceBlob) {
        identity.deliveryBlob = currentBlob;
        identity.deliveryRef = `${currentHead}:${record.path}`;
        continue;
    }
    markOpen(record, ownersForPath(record.path, record.bucket), `Source path ${record.path}`);
}

const count = (records) =>
    Object.fromEntries(
        ledger.allowedStatuses
            .map((status) => [status, records.filter((record) => record.status === status).length])
            .filter(([, total]) => total > 0),
    );
ledger.summary = { commits: count(ledger.commits), paths: count(ledger.paths) };
ledger.deliveryBaseline = currentHead;

writeFileSync(ledgerPath, `${JSON.stringify(ledger, null, 2)}\n`);
