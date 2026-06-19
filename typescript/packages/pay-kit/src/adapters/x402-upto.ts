import { createSolanaRpc } from '@solana/kit';
import { x402Facilitator } from '@x402/core/facilitator';
import {
    decodePaymentSignatureHeader,
    encodePaymentRequiredHeader,
    encodePaymentResponseHeader,
} from '@x402/core/http';
import type { Network, PaymentPayload, PaymentRequired, PaymentRequirements } from '@x402/core/types';
import { resolveStablecoinMint } from '@x402/svm';
import { UptoSvmScheme as UptoSvmFacilitator } from '@x402/svm/upto/facilitator';

import type { PayKitConfig } from '../config.js';
import { ConfigurationError, InvalidProofError } from '../errors.js';
import type { Price } from '../price.js';
import { caip2 } from '../protocol.js';

/** Settlement-response header mirrored by the x402 SDK family. */
const PAYMENT_RESPONSE_HEADER = 'x-payment-response';
/** 402 challenge header read by x402 clients (alongside the JSON body). */
const PAYMENT_REQUIRED_HEADER = 'payment-required';
const X402_VERSION = 2;
const MAX_TIMEOUT_SECONDS = 300;

/**
 * Usage meter handed to a usage-gated handler. The handler reports the actual
 * amount consumed (token base units) via {@link Charge.charge}; the gate settles
 * that amount — never above the authorized ceiling — after the handler returns,
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
 * the in-process `@x402/svm` upto facilitator (signed + fee-paid by the operator)
 * verifies and broadcasts the open, then settles the metered amount with a single
 * voucher, refunding the remainder.
 *
 * `upto` does not fit the protocol-uniform {@link import('../adapter.js').ProtocolAdapter}
 * contract (which settles before the handler runs), so it is exposed as a
 * dedicated engine the framework wrappers drive — exactly as Rust ships
 * `paid_upto_*` separately from the unified gate.
 */
export class X402Upto {
    readonly #facilitator: x402Facilitator;
    readonly #network: Network;
    readonly #operator: string;
    readonly #recipient: string;
    readonly #rpcUrl: string;
    readonly #stablecoins: readonly string[];

    constructor(config: PayKitConfig) {
        this.#network = caip2(config.network) as Network;
        this.#operator = config.operator.signer.pubkey;
        this.#recipient = config.operator.recipient;
        this.#rpcUrl = config.rpcUrl;
        this.#stablecoins = config.stablecoins;
        this.#facilitator = new x402Facilitator().register(
            this.#network,
            new UptoSvmFacilitator(config.operator.signer.signer, { rpcUrl: config.rpcUrl }),
        );
    }

    /** Whether `request` carries an x402 payment credential. */
    detect(request: Request): boolean {
        return this.#paymentHeader(request) !== undefined;
    }

    /** The 402 challenge headers for a route capped at `maxPrice`. */
    async challengeHeaders(maxPrice: Price, request: Request): Promise<Readonly<Record<string, string>>> {
        const paymentRequired: PaymentRequired = {
            accepts: [await this.#challengeRequirements(maxPrice)],
            resource: { url: new URL(request.url).pathname },
            x402Version: X402_VERSION,
        };
        return { [PAYMENT_REQUIRED_HEADER]: encodePaymentRequiredHeader(paymentRequired) };
    }

    /** The `accepts[]` entries for the 402 JSON body. */
    accepts(maxPrice: Price): readonly PaymentRequirements[] {
        return [this.#requirements(maxPrice)];
    }

    /**
     * Verify the authorization and broadcast the channel open (escrowing the
     * ceiling before the resource is served).
     *
     * @throws {InvalidProofError} when the authorization fails verification.
     */
    async verifyOpen(request: Request, maxPrice: Price): Promise<UptoVerified> {
        const header = this.#paymentHeader(request);
        if (!header) throw new InvalidProofError('missing_x402_payment_header');

        let payload: PaymentPayload;
        try {
            payload = decodePaymentSignatureHeader(header);
        } catch (error) {
            throw new InvalidProofError('invalid_x402_payment_header', errorMessage(error));
        }

        const requirements = this.#requirements(maxPrice);
        const verification = await this.#facilitator.verify(payload, requirements);
        if (!verification.isValid) {
            throw new InvalidProofError(verification.invalidReason ?? 'invalid_proof', verification.invalidMessage);
        }
        return { maxBaseUnits: BigInt(requirements.amount), payer: verification.payer ?? '', payload, requirements };
    }

    /**
     * Settle the metered amount (`actualBaseUnits`, clamped to the ceiling) against
     * a verified open: operator voucher, settle-and-finalize, refund the remainder.
     *
     * @throws {InvalidProofError} when settlement fails.
     */
    async settle(verified: UptoVerified, actualBaseUnits: bigint): Promise<UptoSettlement> {
        const actual = actualBaseUnits > verified.maxBaseUnits ? verified.maxBaseUnits : actualBaseUnits;
        const settleRequirements: PaymentRequirements = { ...verified.requirements, amount: actual.toString() };
        const settlement = await this.#facilitator.settle(verified.payload, settleRequirements);
        if (!settlement.success) {
            throw new InvalidProofError(settlement.errorReason ?? 'settlement_failed', settlement.errorMessage);
        }
        return {
            amount: settlement.amount ?? actual.toString(),
            settlementHeaders: { [PAYMENT_RESPONSE_HEADER]: encodePaymentResponseHeader(settlement) },
            transaction: settlement.transaction,
        };
    }

    #requirements(maxPrice: Price): PaymentRequirements {
        const coin = maxPrice.primaryCoin() ?? this.#stablecoins[0] ?? 'USDC';
        const mint = resolveStablecoinMint(coin, this.#network);
        if (!mint) throw new ConfigurationError(`No ${coin} mint known for ${this.#network}.`);
        return {
            amount: maxPrice.baseUnits().toString(),
            asset: mint,
            // Spec field names (scheme_upto_svm.md §4.1): `facilitator` (not the
            // old non-spec `facilitatorAddress`) + the required `profiles`, so a
            // Rust/other-SDK upto client can act on this challenge.
            extra: { facilitator: this.#operator, feePayer: this.#operator, profiles: ['payment-channel'] },
            maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
            network: this.#network,
            payTo: this.#recipient,
            scheme: 'upto',
        };
    }

    /**
     * The challenge requirements with a server-fetched recent blockhash in
     * `extra` — so the client can sign the channel-open without its own RPC
     * round-trip (mirroring MPP). Falls back to the bare requirements on error.
     */
    async #challengeRequirements(maxPrice: Price): Promise<PaymentRequirements> {
        const base = this.#requirements(maxPrice);
        try {
            const { value } = await createSolanaRpc(this.#rpcUrl).getLatestBlockhash().send();
            return {
                ...base,
                extra: {
                    ...base.extra,
                    lastValidBlockHeight: value.lastValidBlockHeight.toString(),
                    recentBlockhash: value.blockhash,
                },
            };
        } catch {
            return base;
        }
    }

    #paymentHeader(request: Request): string | undefined {
        return request.headers.get('x-payment') ?? request.headers.get('payment-signature') ?? undefined;
    }
}

function errorMessage(error: unknown): string | undefined {
    return error instanceof Error ? error.message : undefined;
}
