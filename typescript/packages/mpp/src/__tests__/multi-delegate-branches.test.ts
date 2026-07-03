// Branch-coverage tests for client/MultiDelegate.ts.
//
// Targets the integer-parsing guards (u64 / i64 range, safe-integer, digit
// string) reached through buildCreateFixedDelegationInstruction, plus the
// `nonce ?? 0n` defaulting in the transaction builders and the derive-ATA
// arm of resolveUserAta (builder invoked without an explicit userAta).
// No production code is touched.

import { createKeyPairSignerFromPrivateKeyBytes } from '@solana/kit';
import { describe, expect, test } from 'vitest';

import {
    buildCreateFixedDelegationInstruction,
    buildInitMultiDelegateTx,
    buildUpdateDelegationTx,
} from '../client/MultiDelegate.js';
import { TOKEN_PROGRAM } from '../constants.js';

const USER = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const OPERATOR = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY';
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';

const U64_MAX = (1n << 64n) - 1n;
const I64_MAX = (1n << 63n) - 1n;

async function makeSigner() {
    const seed = new Uint8Array(32);
    seed.fill(0x2a);
    return await createKeyPairSignerFromPrivateKeyBytes(seed);
}

// ── Integer-parsing guards via buildCreateFixedDelegationInstruction ──

describe('buildCreateFixedDelegationInstruction integer guards', () => {
    const base = { delegatee: OPERATOR, delegator: USER, mint: MINT, nonce: 0n } as const;

    test('rejects a negative amount (u64 lower bound)', async () => {
        await expect(buildCreateFixedDelegationInstruction({ ...base, amount: -1n, expiryTs: 0n })).rejects.toThrow(
            /amount must be non-negative/,
        );
    });

    test('rejects an amount above u64 max (u64 upper bound)', async () => {
        await expect(
            buildCreateFixedDelegationInstruction({ ...base, amount: U64_MAX + 1n, expiryTs: 0n }),
        ).rejects.toThrow(/amount exceeds u64 max/);
    });

    test('rejects a negative expiryTs (i64 lower bound)', async () => {
        await expect(buildCreateFixedDelegationInstruction({ ...base, amount: 1n, expiryTs: -1n })).rejects.toThrow(
            /expiryTs must be non-negative/,
        );
    });

    test('rejects an expiryTs above i64 max (i64 upper bound)', async () => {
        await expect(
            buildCreateFixedDelegationInstruction({ ...base, amount: 1n, expiryTs: I64_MAX + 1n }),
        ).rejects.toThrow(/expiryTs exceeds i64 max/);
    });

    test('rejects an unsafe-integer numeric amount', async () => {
        await expect(
            buildCreateFixedDelegationInstruction({
                ...base,
                amount: Number.MAX_SAFE_INTEGER + 2,
                expiryTs: 0n,
            }),
        ).rejects.toThrow(/must be a safe integer/);
    });

    test('rejects a non-digit string amount', async () => {
        await expect(buildCreateFixedDelegationInstruction({ ...base, amount: '10x', expiryTs: 0n })).rejects.toThrow(
            /must be an integer string/,
        );
    });
});

// ── nonce defaulting + resolveUserAta derive path ──

describe('multi-delegate tx builders defaulting', () => {
    test('buildInitMultiDelegateTx defaults nonce to 0 and derives the ATA when userAta is omitted', async () => {
        const signer = await makeSigner();
        const wire = await buildInitMultiDelegateTx({
            amount: 5_000_000n,
            expiryTs: 1_893_456_000n,
            mint: MINT,
            operator: OPERATOR,
            recentBlockhash: BLOCKHASH,
            signer,
            tokenProgram: TOKEN_PROGRAM,
            // no nonce → defaults to 0n; no userAta → derived via findAssociatedTokenPda
        });
        expect(typeof wire).toBe('string');
        expect(wire.length).toBeGreaterThan(0);
    });

    test('buildUpdateDelegationTx defaults nonce to 0 when omitted', async () => {
        const signer = await makeSigner();
        const wire = await buildUpdateDelegationTx({
            amount: 5_000_000n,
            expiryTs: 1_893_456_000n,
            mint: MINT,
            operator: OPERATOR,
            recentBlockhash: BLOCKHASH,
            signer,
            tokenProgram: TOKEN_PROGRAM,
            // no nonce → defaults to 0n
        });
        expect(wire.length).toBeGreaterThan(0);
    });
});
