// Canonical voucher message encoder and Ed25519 verifier.
//
// The 50-byte voucher payload is the exact byte layout the on-chain
// payment-channels program signs over:
//   magic (2 bytes, constant [0x56, 0x01])
//   channel_id (32 bytes, base58-decoded pubkey)
//   cumulative_amount (u64 little-endian)
//   expires_at (i64 little-endian)
//
// The magic prefix exists only in the signed bytes — it is never carried in
// the wire JSON. This module is the single source of truth for that layout
// so client and server agree on the bytes they sign / verify. The Rust
// mirror lives in
// `mpp/src/protocol/intents/session.rs::VoucherData::message_bytes`.

import { getBase58Encoder, getI64Encoder, getU64Encoder } from '@solana/kit';

import type { AmountLike, SignedVoucher, VoucherData, VoucherDataInput } from './session-types.js';

const U64_MAX = (1n << 64n) - 1n;
const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;

/**
 * Constant 2-byte magic prefix of the signed voucher payload. The on-chain
 * program rejects vouchers without it (`voucherBadMagic`).
 */
export const VOUCHER_MAGIC: Readonly<Uint8Array> = new Uint8Array([0x56, 0x01]);

/**
 * Signed voucher as it arrives on the wire.
 */
export interface WireSignedVoucher {
    readonly signature: string;
    readonly signatureType: 'ed25519';
    readonly signer: string;
    readonly voucher: {
        readonly channelId: string;
        readonly cumulativeAmount: string;
        readonly expiresAt?: number | undefined;
    };
}

/**
 * Normalize an inbound signed voucher and validate that an optional
 * `expiresAt` survived JSON parsing intact.
 */
export function normalizeSignedVoucher(signed: WireSignedVoucher): SignedVoucher {
    const { voucher: data } = signed;
    if (data.expiresAt !== undefined && !Number.isSafeInteger(data.expiresAt)) {
        throw new Error(
            `invalid-voucher: expiresAt ${data.expiresAt} is not a safe JavaScript integer — ` +
                'the wire type is an i64, and JSON numbers above 2^53 - 1 lose precision, so such values cannot be accepted',
        );
    }
    return {
        signature: signed.signature,
        signatureType: signed.signatureType,
        signer: signed.signer,
        voucher: {
            channelId: data.channelId,
            cumulativeAmount: data.cumulativeAmount,
            ...(data.expiresAt !== undefined ? { expiresAt: data.expiresAt } : {}),
        },
    };
}

/**
 * Canonical 50-byte payment-channel voucher payload signed by the session
 * key. Accepts the strict `VoucherData` shape used in the protocol types.
 */
export function encodeVoucherMessage(voucher: VoucherData): Uint8Array {
    return encodeVoucherMessageLoose({ ...voucher, expiresAt: voucher.expiresAt ?? 0 });
}

/**
 * Variant of {@link encodeVoucherMessage} that accepts the looser input
 * shape used by client helpers.
 */
export function encodeVoucherMessageLoose(data: VoucherDataInput): Uint8Array {
    const channelIdBytes = getBase58Encoder().encode(data.channelId);
    if (channelIdBytes.byteLength !== 32) {
        throw new Error(`channelId must decode to 32 bytes; got ${channelIdBytes.byteLength}`);
    }

    const cumulative = parseAmount(data.cumulativeAmount, 'cumulativeAmount');
    const expiresAt = parseI64(data.expiresAt, 'expiresAt');

    const bytes = new Uint8Array(50);
    bytes.set(VOUCHER_MAGIC, 0);
    bytes.set(channelIdBytes, 2);
    bytes.set(getU64Encoder().encode(cumulative), 34);
    bytes.set(getI64Encoder().encode(expiresAt), 42);
    return bytes;
}

/**
 * Verify an Ed25519 voucher signature against the authorized signer.
 * Both the signature and signer are base58-encoded (Solana wire format).
 */
export async function verifyVoucherSignature(args: {
    readonly signatureBase58: string;
    readonly signerBase58: string;
    readonly voucher: VoucherData;
}): Promise<boolean> {
    const base58 = getBase58Encoder();
    const signatureBytes = toArrayBufferBacked(base58.encode(args.signatureBase58));
    if (signatureBytes.byteLength !== 64) {
        throw new Error(`signature must decode to 64 bytes; got ${signatureBytes.byteLength}`);
    }
    const pubkeyBytes = toArrayBufferBacked(base58.encode(args.signerBase58));
    if (pubkeyBytes.byteLength !== 32) {
        throw new Error(`signer must decode to 32 bytes; got ${pubkeyBytes.byteLength}`);
    }

    const message = toArrayBufferBacked(encodeVoucherMessage(args.voucher));
    const key = await crypto.subtle.importKey('raw', pubkeyBytes, 'Ed25519', false, ['verify']);
    return await crypto.subtle.verify('Ed25519', key, signatureBytes, message);
}

/**
 * Copy a Uint8Array-like into a fresh `ArrayBuffer`-backed view. The base58
 * codec returns `ReadonlyUint8Array<ArrayBufferLike>`, which `crypto.subtle.*`
 * rejects under DOM lib types because `SharedArrayBuffer` is not assignable
 * to `ArrayBuffer`.
 */
function toArrayBufferBacked(bytes: { [index: number]: number; byteLength: number }): Uint8Array<ArrayBuffer> {
    const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
    for (let i = 0; i < bytes.byteLength; i++) copy[i] = bytes[i] ?? 0;
    return copy;
}

function parseAmount(value: AmountLike, name: string): bigint {
    const parsed = parseInteger(value, name);
    if (parsed < 0n) throw new Error(`${name} must be non-negative`);
    if (parsed > U64_MAX) throw new Error(`${name} exceeds u64 max`);
    return parsed;
}

function parseI64(value: AmountLike, name: string): bigint {
    const parsed = parseInteger(value, name);
    if (parsed < I64_MIN || parsed > I64_MAX) throw new Error(`${name} is outside i64 range`);
    return parsed;
}

function parseInteger(value: AmountLike, name: string): bigint {
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value)) throw new Error(`${name} must be a safe integer`);
        return BigInt(value);
    }
    if (!/^\d+$/.test(value)) throw new Error(`${name} must be an integer string`);
    return BigInt(value);
}
