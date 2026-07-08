// Canonical voucher message encoder and Ed25519 verifier.
//
// The 48-byte voucher payload is the exact byte layout the on-chain
// payment-channels program signs over:
//   channel_id (32 bytes, base58-decoded pubkey)
//   cumulative_amount (u64 little-endian)
//   expires_at (i64 little-endian)
//
// This module is the single source of truth for that layout so client and
// server agree on the bytes they sign / verify. The Rust mirror lives in
// `mpp/src/protocol/intents/session.rs::VoucherData::message_bytes`.

import { getBase58Encoder, getI64Encoder, getU64Encoder } from '@solana/kit';

import type { AmountLike, VoucherData, VoucherDataInput } from './session-types.js';

const U64_MAX = (1n << 64n) - 1n;
const I64_MIN = -(1n << 63n);
const I64_MAX = (1n << 63n) - 1n;

/**
 * Signed voucher as it may arrive on the wire. `cumulative` is the legacy
 * alias for `cumulativeAmount` — the Rust mirror deserializes both (see
 * `VoucherData` in `rust/crates/mpp/src/protocol/intents/session.rs`).
 */
export interface WireSignedVoucher {
    readonly data: {
        readonly channelId: string;
        readonly cumulative?: string | undefined;
        readonly cumulativeAmount?: string | undefined;
        readonly expiresAt: number;
        readonly nonce?: number | undefined;
    };
    readonly signature: string;
}

/**
 * Normalize an inbound signed voucher to the canonical shape: maps the
 * legacy `cumulative` alias onto `cumulativeAmount` and validates that
 * `expiresAt` survived JSON parsing intact. Outbound serialization always
 * uses `cumulativeAmount`.
 */
export function normalizeSignedVoucher(signed: WireSignedVoucher): { data: VoucherData; signature: string } {
    const { data } = signed;
    const cumulativeAmount = data.cumulativeAmount ?? data.cumulative;
    if (cumulativeAmount === undefined) {
        throw new Error('invalid-voucher: cumulativeAmount is required (legacy wire alias: cumulative)');
    }
    if (!Number.isSafeInteger(data.expiresAt)) {
        throw new Error(
            `invalid-voucher: expiresAt ${data.expiresAt} is not a safe JavaScript integer — ` +
                'the wire type is an i64, and JSON numbers above 2^53 - 1 lose precision, so such values cannot be accepted',
        );
    }
    return {
        data: {
            channelId: data.channelId,
            cumulativeAmount,
            expiresAt: data.expiresAt,
            ...(data.nonce !== undefined ? { nonce: data.nonce } : {}),
        },
        signature: signed.signature,
    };
}

/**
 * Canonical 48-byte payment-channel voucher payload signed by the session
 * key. Accepts the strict `VoucherData` shape used in the protocol types.
 */
export function encodeVoucherMessage(voucher: VoucherData): Uint8Array {
    return encodeVoucherMessageLoose(voucher);
}

/**
 * Variant of {@link encodeVoucherMessage} that accepts the looser input
 * shape used by client helpers (allows `cumulative` alias and string/number
 * amounts).
 */
export function encodeVoucherMessageLoose(data: VoucherDataInput): Uint8Array {
    const channelIdBytes = getBase58Encoder().encode(data.channelId);
    if (channelIdBytes.byteLength !== 32) {
        throw new Error(`channelId must decode to 32 bytes; got ${channelIdBytes.byteLength}`);
    }

    const cumulative = parseAmount(requiredCumulative(data), 'cumulativeAmount');
    const expiresAt = parseI64(data.expiresAt, 'expiresAt');

    const bytes = new Uint8Array(48);
    bytes.set(channelIdBytes, 0);
    bytes.set(getU64Encoder().encode(cumulative), 32);
    bytes.set(getI64Encoder().encode(expiresAt), 40);
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

function requiredCumulative(data: VoucherDataInput): AmountLike {
    if (data.cumulativeAmount !== undefined) return data.cumulativeAmount;
    if (data.cumulative !== undefined) return data.cumulative;
    throw new Error('cumulativeAmount required');
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
