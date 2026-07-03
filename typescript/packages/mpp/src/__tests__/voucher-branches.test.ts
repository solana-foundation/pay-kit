// Branch-coverage tests for shared/voucher.ts.
//
// Targets the validation and defaulting branches the existing suites leave
// uncovered: the legacy `cumulative` alias fallback and its missing-value
// throw, the unsafe-integer `expiresAt` guard, the optional `nonce`
// passthrough, the 32/64-byte decode guards in the message encoder and the
// signature verifier, and the i64-range / integer-parse guards.
// No production code is touched.

import { getBase58Decoder } from '@solana/kit';
import { describe, expect, it } from 'vitest';

import {
    encodeVoucherMessageLoose,
    normalizeSignedVoucher,
    verifyVoucherSignature,
    type WireSignedVoucher,
} from '../shared/voucher.js';

const CHANNEL_ID = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';

// ── normalizeSignedVoucher ────────────────────────────────────────────────

describe('normalizeSignedVoucher', () => {
    it('maps the legacy `cumulative` alias onto `cumulativeAmount`', () => {
        const wire: WireSignedVoucher = {
            data: { channelId: CHANNEL_ID, cumulative: '500', expiresAt: 1_893_456_000 },
            signature: 'sig',
        };
        const normalized = normalizeSignedVoucher(wire);
        expect(normalized.data.cumulativeAmount).toBe('500');
        expect(normalized.data.nonce).toBeUndefined();
    });

    it('preserves an explicit nonce when present', () => {
        const wire: WireSignedVoucher = {
            data: { channelId: CHANNEL_ID, cumulativeAmount: '10', expiresAt: 100, nonce: 7 },
            signature: 'sig',
        };
        expect(normalizeSignedVoucher(wire).data.nonce).toBe(7);
    });

    it('throws when neither cumulativeAmount nor the legacy cumulative alias is present', () => {
        const wire = {
            data: { channelId: CHANNEL_ID, expiresAt: 100 },
            signature: 'sig',
        } as unknown as WireSignedVoucher;
        expect(() => normalizeSignedVoucher(wire)).toThrow(/cumulativeAmount is required/);
    });

    it('throws when expiresAt is not a safe JavaScript integer', () => {
        const wire: WireSignedVoucher = {
            data: { channelId: CHANNEL_ID, cumulativeAmount: '1', expiresAt: Number.MAX_SAFE_INTEGER + 2 },
            signature: 'sig',
        };
        expect(() => normalizeSignedVoucher(wire)).toThrow(/not a safe JavaScript integer/);
    });
});

// ── encodeVoucherMessageLoose ─────────────────────────────────────────────

describe('encodeVoucherMessageLoose', () => {
    it('encodes a 48-byte payload for a valid voucher', () => {
        const bytes = encodeVoucherMessageLoose({
            channelId: CHANNEL_ID,
            cumulativeAmount: '1000',
            expiresAt: 1_893_456_000,
        });
        expect(bytes).toHaveLength(48);
    });

    it('throws when the channelId does not decode to 32 bytes', () => {
        expect(() =>
            encodeVoucherMessageLoose({
                channelId: 'abc', // decodes to far fewer than 32 bytes
                cumulativeAmount: '1',
                expiresAt: 1,
            }),
        ).toThrow(/channelId must decode to 32 bytes/);
    });

    it('throws when expiresAt is outside the i64 range', () => {
        expect(() =>
            encodeVoucherMessageLoose({
                channelId: CHANNEL_ID,
                cumulativeAmount: '1',
                expiresAt: 1n << 64n, // > i64 max
            }),
        ).toThrow(/expiresAt is outside i64 range/);
    });

    it('throws when a numeric amount is not a safe integer', () => {
        expect(() =>
            encodeVoucherMessageLoose({
                channelId: CHANNEL_ID,
                cumulativeAmount: Number.MAX_SAFE_INTEGER + 2,
                expiresAt: 1,
            }),
        ).toThrow(/must be a safe integer/);
    });

    it('throws when a string amount is not all digits', () => {
        expect(() =>
            encodeVoucherMessageLoose({
                channelId: CHANNEL_ID,
                cumulativeAmount: '12x',
                expiresAt: 1,
            }),
        ).toThrow(/must be an integer string/);
    });
});

// ── verifyVoucherSignature ────────────────────────────────────────────────

describe('verifyVoucherSignature', () => {
    const voucher = { channelId: CHANNEL_ID, cumulativeAmount: '1', expiresAt: 1 };

    it('throws when the signature does not decode to 64 bytes', async () => {
        // A valid 32-byte base58 value is a valid signer but only 32 bytes,
        // so passing it as the signature trips the 64-byte guard.
        const thirtyTwoBytes = getBase58Decoder().decode(new Uint8Array(32).fill(1));
        await expect(
            verifyVoucherSignature({
                signatureBase58: thirtyTwoBytes,
                signerBase58: CHANNEL_ID,
                voucher,
            }),
        ).rejects.toThrow(/signature must decode to 64 bytes/);
    });

    it('throws when the signer does not decode to 32 bytes', async () => {
        const sixtyFourBytes = getBase58Decoder().decode(new Uint8Array(64).fill(2));
        await expect(
            verifyVoucherSignature({
                signatureBase58: sixtyFourBytes,
                signerBase58: 'abc', // too short
                voucher,
            }),
        ).rejects.toThrow(/signer must decode to 32 bytes/);
    });
});
