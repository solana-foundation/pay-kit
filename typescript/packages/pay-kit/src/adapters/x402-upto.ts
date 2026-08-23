import { createSolanaRpc, getBase58Decoder } from '@solana/kit';
import { encodeVoucherMessageBytes, OPEN_SLOT_WINDOW } from '@solana/mpp/server';
import { x402Facilitator } from '@x402/core/facilitator';
import {
    decodePaymentSignatureHeader,
    encodePaymentRequiredHeader,
    encodePaymentResponseHeader,
} from '@x402/core/http';
import type { Network, PaymentPayload, PaymentRequired, PaymentRequirements } from '@x402/core/types';
import { getStablecoinTokenProgram, resolveStablecoinMint, toFacilitatorSvmSigner } from '@x402/svm';
import { UptoSvmScheme as UptoSvmFacilitator } from '@x402/svm/upto/facilitator';

import { requireMint, resolveCoin } from '../coin.js';
import type { PayKitConfig } from '../config.js';
import { InvalidProofError } from '../errors.js';
import type { Price } from '../price.js';
import { caip2 } from '../protocol.js';
import { errorMessage, x402PaymentHeader } from './x402-shared.js';

/** Settlement-response header mirrored by the x402 SDK family. */
const PAYMENT_RESPONSE_HEADER = 'x-payment-response';
/** 402 challenge header read by x402 clients (alongside the JSON body). */
const PAYMENT_REQUIRED_HEADER = 'payment-required';
const X402_VERSION = 2;
const MAX_TIMEOUT_SECONDS = 300;
const DEFAULT_WITHDRAW_DELAY_SECONDS = 900;

/**
 * Usage meter handed to a usage-gated handler. The handler reports the actual
 * amount consumed (token base units) via {@link Charge.charge}; the gate settles
 * that amount - never above the authorized ceiling - after the handler returns,
 * refunding the remainder. If the handler never calls `charge`, the settled
 * amount is `0`. Mirrors the Rust `Charge` extractor on `paid_upto_*` routes.
 */
export class Charge {
    #amount: bigint | undefined;

    /** The authorized maximum for this request, in base units. */
    readonly maxBaseUnits: bigint;

    constructor(maxBaseUnits: bigint) {
        this.maxBaseUnits = maxBaseUnits;
    }

    /** Record the actual amount consumed (base units). Values above the ceiling are clamped; negatives floor to 0. */
    charge(baseUnits: bigint | number): void {
        const value = typeof baseUnits === 'bigint' ? baseUnits : BigInt(Math.trunc(baseUnits));
        this.#amount = value < 0n ? 0n : value > this.maxBaseUnits ? this.maxBaseUnits : value;
    }

    /** The amount to settle (base units): the clamped charge, or `0` if never set. */
    settledBaseUnits(): bigint {
        return this.#amount ?? 0n;
    }
}

/** A verified `upto` authorization carried from {@link X402Upto.verifyOpen} to {@link X402Upto.settle}. */
export type UptoVerified = {
    readonly maxBaseUnits: bigint;
    readonly payer: string;
    readonly payload: PaymentPayload;
    readonly requirements: PaymentRequirements;
};

/** Result of settling a `upto` authorization. */
export type UptoSettlement = {
    readonly amount: string;
    readonly settlementHeaders: Readonly<Record<string, string>>;
    readonly transaction: string;
};

/**
 * Usage-based (`upto`) x402 engine: the metered counterpart to the `exact`
 * adapter. The client opens a payment channel depositing the authorized ceiling;
 * the in-process `@x402/svm` upto facilitator broadcasts the open (deposit
 * settle) before the handler runs, then settles the metered amount with a
 * single voucher (claim settle), refunding the remainder.
 *
 * `upto` does not fit the protocol-uniform {@link import('../adapter.js').ProtocolAdapter}
 * contract (which settles before the handler runs), so it is exposed as a
 * dedicated engine the framework wrappers drive - exactly as Rust ships
 * `paid_upto_*` separately from the unified gate.
 */
export class X402Upto {
    readonly #facilitator: x402Facilitator;
    readonly #network: Network;
    readonly #feePayer: string;
    readonly #receiverAuthorizer: string;
    readonly #signer: PayKitConfig['operator']['signer'];
    readonly #recipient: string;
    readonly #rpcUrl: string;
    readonly #stablecoins: readonly string[];

    constructor(config: PayKitConfig) {
        this.#network = caip2(config.network) as Network;
        // The operator key holds both seats: fee payer (transaction sponsor,
        // rent payer, and zero-share channel payee) and receiver authorizer
        // (voucher signer).
        this.#feePayer = config.operator.signer.pubkey;
        this.#receiverAuthorizer = config.operator.signer.pubkey;
        this.#signer = config.operator.signer;
        this.#recipient = config.operator.recipient;
        this.#rpcUrl = config.rpcUrl;
        this.#stablecoins = config.stablecoins;
        this.#facilitator = new x402Facilitator().register(
            this.#network,
            new UptoSvmFacilitator(
                toFacilitatorSvmSigner(config.operator.signer.signer, { defaultRpcUrl: config.rpcUrl }),
                { rpcUrl: config.rpcUrl },
            ),
        );
    }

    /** Whether `request` carries an x402 payment credential. */
    detect(request: Request): boolean {
        return x402PaymentHeader(request) !== undefined;
    }

    /**
     * The 402 challenge headers for a route capped at `maxPrice`. Pass the
     * entries from {@link accepts} to reuse one server-enriched requirement
     * (one `getLatestBlockhash` round-trip) for both the header and the body.
     */
    async challengeHeaders(
        maxPrice: Price,
        request: Request,
        accepts?: readonly PaymentRequirements[],
    ): Promise<Readonly<Record<string, string>>> {
        const paymentRequired: PaymentRequired = {
            accepts: [...(accepts ?? (await this.accepts(maxPrice)))],
            resource: { url: new URL(request.url).pathname },
            x402Version: X402_VERSION,
        };
        return { [PAYMENT_REQUIRED_HEADER]: encodePaymentRequiredHeader(paymentRequired) };
    }

    /**
     * The `accepts[]` entries for the 402 JSON body — the same server-enriched
     * requirement (`extra.recentBlockhash` + `extra.recentSlot`) the header
     * carries, so body-based `upto` clients can build the channel open too.
     */
    async accepts(maxPrice: Price): Promise<readonly PaymentRequirements[]> {
        return [await this.#challengeRequirements(maxPrice)];
    }

    /**
     * Verify the authorization and broadcast the channel open (escrowing the
     * ceiling before the resource is served).
     *
     * In `@x402/svm` >= 2.23 the facilitator's `verify()` is a read-only
     * preflight — the open broadcast moved to `settle()`'s deposit path
     * (no `voucherSignature`, `requirements.amount === payload.maxAmount`).
     * `settle()` runs the same authorization checks `verify()` does before
     * touching the network, so calling it directly here does not skip any
     * validation — it is the only path that actually escrows the ceiling.
     *
     * @throws {InvalidProofError} when the authorization or the deposit
     *   broadcast fails.
     */
    async verifyOpen(request: Request, maxPrice: Price): Promise<UptoVerified> {
        const header = x402PaymentHeader(request);
        if (!header) throw new InvalidProofError('missing_x402_payment_header');

        let payload: PaymentPayload;
        try {
            payload = decodePaymentSignatureHeader(header);
        } catch (error) {
            throw new InvalidProofError('invalid_x402_payment_header', errorMessage(error));
        }

        // Bind the authorization's openSlot to the challenged recentSlot
        // BEFORE the facilitator broadcasts the open: the facilitator already
        // pins the open transaction's `openArgs.openSlot` to
        // `payload.openSlot`, so window-checking the payload value here binds
        // the openArgs transitively. Mirrors the Rust
        // `X402Upto::validate_open_transaction` recentSlot check.
        //
        // x402 is stateless, so the challenged slot is re-observed here exactly
        // how the challenge minted it (one `getLatestBlockhash`, context slot)
        // and then handed to the facilitator, which runs the same window check
        // inside `verifyOpenTransaction`. Without the hint the facilitator
        // falls back to `getSlot({commitment: 'finalized'})`, which lags the
        // challenge's own read by tens of slots and rejects a fresh open.
        const recentSlot = await this.#observeRecentSlot();
        this.#assertOpenSlotBoundToChallenge(payload, recentSlot);

        const requirements = this.#requirements(maxPrice, recentSlot);
        const settled = await this.#facilitator.settle(payload, requirements);
        if (!settled.success) {
            throw new InvalidProofError(settled.errorReason ?? 'invalid_proof', settled.errorMessage);
        }
        return { maxBaseUnits: BigInt(requirements.amount), payer: settled.payer ?? '', payload, requirements };
    }

    /**
     * Re-observe the current slot the way {@link X402Upto.accepts} mints it for
     * the challenge: one `getLatestBlockhash`, whose response context carries
     * the slot the blockhash was produced at. `undefined` when the RPC read
     * fails — callers then skip the window check (the facilitator's channel-PDA
     * bind still holds and the program enforces the window at broadcast).
     */
    async #observeRecentSlot(): Promise<bigint | undefined> {
        try {
            const { context } = await createSolanaRpc(this.#rpcUrl).getLatestBlockhash().send();
            return BigInt(context.slot);
        } catch {
            return undefined;
        }
    }

    /**
     * Enforce `openSlot <= recentSlot` and `recentSlot - openSlot <=
     * OPEN_SLOT_WINDOW` against the re-observed challenged recentSlot.
     *
     * @throws {InvalidProofError} when the openSlot was not built against a
     *   fresh challenge.
     */
    #assertOpenSlotBoundToChallenge(payload: PaymentPayload, recentSlot: bigint | undefined): void {
        const raw = payload.payload as { openSlot?: unknown } | undefined;
        if (!raw || typeof raw.openSlot !== 'string' || !/^\d+$/.test(raw.openSlot)) {
            throw new InvalidProofError(
                'invalid_upto_svm_payload_channel_seed',
                'payload.openSlot must be a u64 decimal string',
            );
        }
        const openSlot = BigInt(raw.openSlot);
        if (recentSlot === undefined) return;
        if (openSlot > recentSlot) {
            throw new InvalidProofError(
                'invalid_upto_svm_payload_open_slot',
                `open openSlot ${openSlot} is ahead of the challenged recentSlot ${recentSlot}`,
            );
        }
        if (recentSlot - openSlot > OPEN_SLOT_WINDOW) {
            throw new InvalidProofError(
                'invalid_upto_svm_payload_open_slot',
                `open openSlot ${openSlot} is outside the ${OPEN_SLOT_WINDOW}-slot freshness window of the challenged recentSlot ${recentSlot}`,
            );
        }
    }

    /**
     * Settle the metered amount (`actualBaseUnits`, clamped to the ceiling) against
     * a verified open: receiver-authorizer voucher, fee-payer-signed settle-and-seal,
     * refund the remainder.
     *
     * @throws {InvalidProofError} when settlement fails.
     */
    async settle(verified: UptoVerified, actualBaseUnits: bigint): Promise<UptoSettlement> {
        const actual = actualBaseUnits > verified.maxBaseUnits ? verified.maxBaseUnits : actualBaseUnits;
        const payload = parseUptoPayload(verified.payload);

        // `voucherSignature` is the wire discriminator `UptoSvmScheme.settle`
        // uses to route to the claim path (vs. the deposit path `verifyOpen`
        // already ran) — always sign, even for a zero-amount refund: the
        // facilitator's claim validation requires a non-empty signature
        // regardless of the settled amount.
        const voucherSignature = await this.#signVoucher(payload.channelId, actual, BigInt(payload.expiresAt));
        const claimPayload: PaymentPayload = {
            ...verified.payload,
            payload: { ...verified.payload.payload, voucherSignature },
        };
        const claimRequirements: PaymentRequirements = { ...verified.requirements, amount: actual.toString() };

        const settled = await this.#facilitator.settle(claimPayload, claimRequirements);
        if (!settled.success) {
            throw new InvalidProofError(settled.errorReason ?? 'transaction_failed', settled.errorMessage);
        }
        const settlement = {
            amount: settled.amount ?? actual.toString(),
            network: verified.requirements.network,
            payer: settled.payer ?? payload.from,
            success: true,
            transaction: settled.transaction,
        } as const;
        return {
            amount: settlement.amount,
            settlementHeaders: { [PAYMENT_RESPONSE_HEADER]: encodePaymentResponseHeader(settlement) },
            transaction: settlement.transaction,
        };
    }

    async #signVoucher(channelId: string, cumulativeAmount: bigint, expiresAt: bigint): Promise<string> {
        const message = encodeVoucherMessageBytes({ channelId, cumulativeAmount, expiresAt });
        const signature = await this.#signer.sign(message);
        return getBase58Decoder().decode(signature);
    }

    /**
     * The route's pinned requirements. `recentSlot`, when passed, is the
     * challenged slot the facilitator window-checks `payload.openSlot` against;
     * omitting it makes the facilitator read its own `finalized` slot, which
     * lags the challenge and rejects a fresh open.
     */
    #requirements(maxPrice: Price, recentSlot?: bigint): PaymentRequirements {
        const coin = resolveCoin(maxPrice, this.#stablecoins);
        const mint = requireMint(coin, resolveStablecoinMint(coin, this.#network), this.#network);
        return {
            amount: maxPrice.baseUnits().toString(),
            asset: mint,
            extra: {
                feePayer: this.#feePayer,
                receiverAuthorizer: this.#receiverAuthorizer,
                ...(recentSlot !== undefined && { recentSlot: recentSlot.toString() }),
                tokenProgram: getStablecoinTokenProgram(mint, this.#network),
                withdrawDelay: DEFAULT_WITHDRAW_DELAY_SECONDS,
            },
            maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
            network: this.#network,
            payTo: this.#recipient,
            scheme: 'upto',
        };
    }

    /**
     * The challenge requirements with a server-fetched recent blockhash and
     * current slot (`recentSlot`) in `extra` - so the client can sign the
     * channel-open without its own RPC round-trip (mirroring MPP). The slot
     * comes from the same blockhash response's context and becomes the
     * channel `openSlot` PDA seed, which clients must take from the
     * challenge — so a bare offer without it is unusable. A failed fetch
     * therefore throws (the caller fails the challenge or omits the `upto`
     * offer) instead of advertising requirements no client can act on.
     */
    async #challengeRequirements(maxPrice: Price): Promise<PaymentRequirements> {
        const base = this.#requirements(maxPrice);
        let context, value;
        try {
            ({ context, value } = await createSolanaRpc(this.#rpcUrl).getLatestBlockhash().send());
        } catch (error) {
            throw new Error(
                `x402 upto challenge requires extra.recentBlockhash/recentSlot; getLatestBlockhash failed: ${errorMessage(error)}`,
            );
        }
        return {
            ...base,
            extra: {
                ...base.extra,
                lastValidBlockHeight: value.lastValidBlockHeight.toString(),
                recentBlockhash: value.blockhash,
                recentSlot: context.slot.toString(),
            },
        };
    }
}

type UptoPaymentChannelPayload = {
    readonly channelId: string;
    readonly expiresAt: number;
    readonly from: string;
};

function parseUptoPayload(payload: PaymentPayload): UptoPaymentChannelPayload {
    const raw = payload.payload as Partial<UptoPaymentChannelPayload> | undefined;
    if (
        !raw ||
        typeof raw.channelId !== 'string' ||
        typeof raw.from !== 'string' ||
        typeof raw.expiresAt !== 'number'
    ) {
        throw new InvalidProofError('invalid_upto_payload');
    }
    return { channelId: raw.channelId, expiresAt: raw.expiresAt, from: raw.from };
}
