// Voucher verifier for the MPP session server.
//
// Pure function — given a current channel snapshot and a signed voucher,
// decide whether to accept (and what the new watermark would be), reject,
// or treat as an idempotent replay. The caller persists any accepted
// delta through `store.updateChannel` (typically inside its own
// re-read-and-recheck closure to be safe under concurrency).
//
// Mirrors the 9-step verifier in
// `rust/crates/mpp/src/server/session.rs::SessionServer::verify_voucher`
// (lines ~427–543). Step numbering below matches the Rust source.

import type { SignedVoucher } from '../../shared/session-types.js';
import { verifyVoucherSignature } from '../../shared/voucher.js';
import type { ChannelState } from './store.js';

/**
 * Reasons a voucher can be rejected. Stable string tags so the caller
 * can map to HTTP statuses / log levels without parsing free text.
 */
export type VoucherRejectReason =
    | 'below-min-delta'
    | 'channel-close-pending'
    | 'channel-sealed'
    | 'cumulative-not-monotonic'
    | 'exceeds-deposit'
    | 'expired'
    | 'expires-within-settlement-window'
    | 'invalid-cumulative'
    | 'invalid-signature';

/** Verification outcome: the voucher advanced the channel watermark. */
export interface VoucherVerifyAccepted {
    /** New cumulative watermark to persist. */
    readonly newCumulative: bigint;
    /** Expiry of the now-highest voucher (i64 seconds). */
    readonly newExpiresAt: bigint;
    /** Signature to persist as `highestVoucherSignature`. */
    readonly newSignature: string;
    readonly status: 'accepted';
}

/** Verification outcome: an already-accepted voucher was re-submitted (idempotent). */
export interface VoucherVerifyReplayed {
    /** Existing watermark, returned for caller convenience. */
    readonly newCumulative: bigint;
    readonly status: 'replayed';
}

/** Verification outcome: the voucher was rejected. See {@link VoucherRejectReason}. */
export interface VoucherVerifyRejected {
    /** Human-readable detail. Safe to log; not stable. */
    readonly detail: string;
    readonly reason: VoucherRejectReason;
    readonly status: 'rejected';
}

/** Union of the three voucher verification outcomes. */
export type VoucherVerifyResult = VoucherVerifyAccepted | VoucherVerifyRejected | VoucherVerifyReplayed;

/** Arguments to {@link verifyVoucherForChannel}. */
export interface VerifyVoucherArgs {
    /**
     * Authoritative deposit cap. Passed in (rather than read off `state`)
     * because some callers carry an updated cap after a recent top-up
     * that hasn't yet been written back into the store.
     */
    readonly deposit: bigint;
    /** Optional minimum delta from the previous cumulative. */
    readonly minVoucherDelta?: bigint | undefined;
    /**
     * Unix seconds, defaults to `Math.floor(Date.now() / 1000)`. Exposed
     * for tests and for callers that already have a clock.
     */
    readonly nowSeconds?: bigint | undefined;
    /**
     * Forced-close grace period of the channel, in seconds (the on-chain
     * `gracePeriod` captured at open). When set, a *non-zero* voucher
     * `expiresAt` must outlast the settlement window — i.e. it must still
     * be valid `settlementWindow` seconds from now, so the merchant can
     * land an async settle_and_seal before the voucher expires.
     * A voucher with `expiresAt == 0` never expires and is unaffected.
     * Defaults to 0 (window check disabled — only `expiresAt <= now` is
     * rejected for non-zero expiries).
     */
    readonly settlementWindow?: bigint | undefined;
    /** Voucher being submitted. */
    readonly signed: SignedVoucher;
    /** Channel snapshot — typically read just before calling. */
    readonly state: ChannelState;
}

/**
 * Verify a voucher against a channel snapshot.
 *
 * Returns a verdict; the caller is responsible for persisting any
 * accepted delta via `store.updateChannel`. The verifier is pure —
 * no store, network, or clock side effects (clock is injectable).
 *
 * Mirrors `SessionServer::verify_voucher` in Rust. Expiry is checked
 * here rather than inside the signature helper (Rust intermixes the
 * two; we keep them separate so callers can override `nowSeconds`).
 */
export async function verifyVoucherForChannel(args: VerifyVoucherArgs): Promise<VoucherVerifyResult> {
    const { state, signed, deposit } = args;
    const { data } = signed;

    // 1. Parse new_cumulative from payload
    let newCumulative: bigint;
    try {
        newCumulative = parseU64(data.cumulativeAmount);
    } catch (error) {
        return reject('invalid-cumulative', errorMessage(error));
    }

    // 2. Channel must not be sealed
    if (state.sealed) {
        return reject('channel-sealed', `Channel ${state.channelId} is already sealed`);
    }

    // 3. Channel must not be in close-pending
    if (state.closeRequestedAt !== undefined) {
        return reject(
            'channel-close-pending',
            `Channel ${state.channelId} close is pending — no further vouchers accepted`,
        );
    }

    // 4. Idempotent replay: same cumulative AND same signature
    if (newCumulative === state.cumulative && state.highestVoucherSignature === signed.signature) {
        // Rust still re-verifies the signature on the replay path. We do
        // the same so a replay of a forged voucher can't slip through.
        const ok = await safeVerifySignature(signed, state.authorizedSigner);
        if (!ok.ok) return ok.reject;
        const expiryReject = checkExpiry(toBigInt(data.expiresAt), currentTime(args.nowSeconds), args.settlementWindow);
        if (expiryReject) return expiryReject;
        return { newCumulative, status: 'replayed' };
    }

    // 5. Must strictly exceed watermark (non-replay case)
    if (newCumulative <= state.cumulative) {
        return reject(
            'cumulative-not-monotonic',
            `Voucher cumulative ${newCumulative} must exceed watermark ${state.cumulative}`,
        );
    }

    // 6. Must not exceed deposit
    if (newCumulative > deposit) {
        return reject('exceeds-deposit', `Voucher cumulative ${newCumulative} exceeds deposit ${deposit}`);
    }

    // 7. Min delta check
    const delta = newCumulative - state.cumulative;
    const minDelta = args.minVoucherDelta ?? 0n;
    if (minDelta > 0n && delta < minDelta) {
        return reject('below-min-delta', `Voucher delta ${delta} is below minimum ${minDelta}`);
    }

    // 8. Verify signature (Ed25519 over the 50-byte canonical payload)
    const sigCheck = await safeVerifySignature(signed, state.authorizedSigner);
    if (!sigCheck.ok) return sigCheck.reject;

    // 9. Expiry — caller may override `nowSeconds` for deterministic tests.
    const expiresAt = toBigInt(data.expiresAt);
    const expiryReject = checkExpiry(expiresAt, currentTime(args.nowSeconds), args.settlementWindow);
    if (expiryReject) return expiryReject;

    return {
        newCumulative,
        newExpiresAt: expiresAt,
        newSignature: signed.signature,
        status: 'accepted',
    };
}

// ── helpers ──

function reject(reason: VoucherRejectReason, detail: string): VoucherVerifyRejected {
    return { detail, reason, status: 'rejected' };
}

/**
 * Voucher expiry rule, mirroring the on-chain settle check
 * (`expires_at != 0 && now >= expires_at` ⇒ rejected) so the off-chain
 * acceptance never advances a watermark the program would later refuse.
 *
 * - `expiresAt == 0` ⇒ never expires; always accepted regardless of `now`.
 * - non-zero `expiresAt <= now` ⇒ already expired.
 * - non-zero `expiresAt` within `settlementWindow` of `now` ⇒ rejected: it
 *   would not outlast the forced-close grace period, so a merchant settle
 *   could miss the window. Skipped when `settlementWindow` is unset/zero.
 *
 * Returns a {@link VoucherVerifyRejected} to short-circuit on, or
 * `undefined` when the voucher's expiry is acceptable.
 */
function checkExpiry(
    expiresAt: bigint,
    now: bigint,
    settlementWindow: bigint | undefined,
): VoucherVerifyRejected | undefined {
    // 0 means never-expires on-chain — accept unconditionally.
    if (expiresAt === 0n) return undefined;
    if (expiresAt <= now) {
        return reject('expired', `Voucher expired at ${expiresAt} (now ${now})`);
    }
    const window = settlementWindow ?? 0n;
    if (window > 0n && expiresAt < now + window) {
        return reject(
            'expires-within-settlement-window',
            `Voucher expiresAt ${expiresAt} is within the settlement window (now ${now} + window ${window} = ${now + window}); ` +
                'it may expire before settlement lands',
        );
    }
    return undefined;
}

async function safeVerifySignature(
    signed: SignedVoucher,
    authorizedSigner: string,
): Promise<{ ok: false; reject: VoucherVerifyRejected } | { ok: true }> {
    try {
        const valid = await verifyVoucherSignature({
            signatureBase58: signed.signature,
            signerBase58: authorizedSigner,
            voucher: signed.data,
        });
        if (!valid) {
            return { ok: false, reject: reject('invalid-signature', 'Voucher signature verification failed') };
        }
        return { ok: true };
    } catch (error) {
        return {
            ok: false,
            reject: reject('invalid-signature', errorMessage(error)),
        };
    }
}

function parseU64(value: string): bigint {
    if (!/^\d+$/.test(value)) {
        throw new Error(`Invalid cumulative in voucher: ${value}`);
    }
    const parsed = BigInt(value);
    if (parsed < 0n || parsed > (1n << 64n) - 1n) {
        throw new Error(`Cumulative ${value} outside u64 range`);
    }
    return parsed;
}

function toBigInt(value: bigint | number | string): bigint {
    if (typeof value === 'bigint') return value;
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value)) throw new Error(`expiresAt is not a safe integer: ${value}`);
        return BigInt(value);
    }
    return BigInt(value);
}

function currentTime(override: bigint | undefined): bigint {
    if (override !== undefined) return override;
    return BigInt(Math.floor(Date.now() / 1000));
}

function errorMessage(error: unknown): string {
    if (error instanceof Error) return error.message;
    return String(error);
}
