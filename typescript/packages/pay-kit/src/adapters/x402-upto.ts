import { createSolanaRpc, getBase58Decoder } from '@solana/kit';
import {
    buildAndSignWireTransaction,
    encodeVoucherMessageBytes,
    submitSettleAndDistribute,
    waitForSignatureConfirmation,
} from '@solana/mpp/server';
import { x402Facilitator } from '@x402/core/facilitator';
import {
    decodePaymentSignatureHeader,
    encodePaymentRequiredHeader,
    encodePaymentResponseHeader,
} from '@x402/core/http';
import type { Network, PaymentPayload, PaymentRequired, PaymentRequirements } from '@x402/core/types';
import { getStablecoinTokenProgram, resolveStablecoinMint } from '@x402/svm';
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
const UPTO_ASSET_TRANSFER_METHOD = 'payment-channel';
const BASIS_POINTS_DENOMINATOR = 10_000;

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

type SettlementSubmitRpc = Parameters<typeof submitSettleAndDistribute>[0]['rpc'];
type SettlementConfirmRpc = Parameters<typeof waitForSignatureConfirmation>[0]['rpc'];
type SettlementWireRpc = Parameters<typeof buildAndSignWireTransaction>[0];

/**
 * Usage-based (`upto`) x402 engine: the metered counterpart to the `exact`
 * adapter. The client opens a payment channel depositing the authorized ceiling;
 * the in-process `@x402/svm` upto facilitator (signed + fee-paid by the operator)
 * verifies and broadcasts the open, then settles the metered amount with a single
 * voucher, refunding the remainder.
 *
 * `upto` does not fit the protocol-uniform {@link import('../adapter.js').ProtocolAdapter}
 * contract (which settles before the handler runs), so it is exposed as a
 * dedicated engine the framework wrappers drive - exactly as Rust ships
 * `paid_upto_*` separately from the unified gate.
 */
export class X402Upto {
    readonly #facilitator: x402Facilitator;
    readonly #network: Network;
    readonly #operator: string;
    readonly #operatorSigner: PayKitConfig['operator']['signer'];
    readonly #recipient: string;
    readonly #facilitatorFee: number;
    readonly #rpcUrl: string;
    readonly #stablecoins: readonly string[];

    constructor(config: PayKitConfig) {
        this.#network = caip2(config.network) as Network;
        this.#operator = config.operator.signer.pubkey;
        this.#operatorSigner = config.operator.signer;
        this.#recipient = config.operator.recipient;
        this.#facilitatorFee = config.x402.facilitatorFee;
        this.#rpcUrl = config.rpcUrl;
        this.#stablecoins = config.stablecoins;
        this.#facilitator = new x402Facilitator().register(
            this.#network,
            new UptoSvmFacilitator(config.operator.signer.signer, { rpcUrl: config.rpcUrl }),
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
     * @throws {InvalidProofError} when the authorization fails verification.
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

        const requirements = this.#requirements(maxPrice);
        const verification = await this.#facilitator.verify(payload, requirements);
        if (!verification.isValid) {
            throw new InvalidProofError(verification.invalidReason ?? 'invalid_proof', verification.invalidMessage);
        }
        return { maxBaseUnits: BigInt(requirements.amount), payer: verification.payer ?? '', payload, requirements };
    }

    /**
     * Settle the metered amount (`actualBaseUnits`, clamped to the ceiling) against
     * a verified open: operator voucher, settle-and-seal, refund the remainder.
     *
     * @throws {InvalidProofError} when settlement fails.
     */
    async settle(verified: UptoVerified, actualBaseUnits: bigint): Promise<UptoSettlement> {
        const actual = actualBaseUnits > verified.maxBaseUnits ? verified.maxBaseUnits : actualBaseUnits;
        const payload = parseUptoPayload(verified.payload);
        const rpc = createSolanaRpc(this.#rpcUrl);
        const confirmRpc = rpc as unknown as SettlementConfirmRpc;
        const submitRpc = rpc as unknown as SettlementSubmitRpc;
        const wireRpc = rpc as unknown as SettlementWireRpc;
        let signature: string;
        try {
            const signed =
                actual > 0n
                    ? {
                          data: {
                              channelId: payload.channelId,
                              cumulativeAmount: actual.toString(),
                              expiresAt: payload.expiresAt,
                          },
                          signature: await this.#signVoucher(payload.channelId, actual, BigInt(payload.expiresAt)),
                      }
                    : undefined;
            const result = await submitSettleAndDistribute({
                buildAndSignWireTransaction: instructions =>
                    buildAndSignWireTransaction(wireRpc, this.#operatorSigner.signer, instructions),
                channelId: payload.channelId,
                mint: verified.requirements.asset,
                network: verified.requirements.network,
                payee: this.#operator,
                payer: payload.from,
                rentPayer: this.#operator,
                rpc: submitRpc,
                signer: this.#operatorSigner.signer,
                splits: this.#recipientSplits(verified.requirements.payTo),
                tokenProgram: tokenProgramFor(verified.requirements),
                voucher: signed ? { authorizedSigner: this.#operator, signed } : undefined,
            });
            signature = result.signature;
            await waitForSignatureConfirmation({
                context: 'x402 upto settle',
                rpc: confirmRpc,
                signature: result.signature,
            });
        } catch (error) {
            throw new InvalidProofError('transaction_failed', errorMessage(error));
        }
        const settlement = {
            amount: actual.toString(),
            network: verified.payload.accepted.network,
            payer: payload.from,
            success: true,
            transaction: signature,
        } as const;
        return {
            amount: settlement.amount,
            settlementHeaders: { [PAYMENT_RESPONSE_HEADER]: encodePaymentResponseHeader(settlement) },
            transaction: settlement.transaction,
        };
    }

    async #signVoucher(channelId: string, cumulativeAmount: bigint, expiresAt: bigint): Promise<string> {
        const message = encodeVoucherMessageBytes({ channelId, cumulativeAmount, expiresAt });
        const signature = await this.#operatorSigner.sign(message);
        return getBase58Decoder().decode(signature);
    }

    #requirements(maxPrice: Price): PaymentRequirements {
        const coin = resolveCoin(maxPrice, this.#stablecoins);
        const mint = requireMint(coin, resolveStablecoinMint(coin, this.#network), this.#network);
        return {
            amount: maxPrice.baseUnits().toString(),
            asset: mint,
            extra: {
                assetTransferMethod: UPTO_ASSET_TRANSFER_METHOD,
                facilitatorAddress: this.#operator,
                facilitatorFee: this.#facilitatorFee,
                feePayer: this.#operator,
            },
            maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
            network: this.#network,
            payTo: this.#recipient,
            scheme: 'upto',
        };
    }

    #recipientSplits(recipient: string): readonly { readonly bps: number; readonly recipient: string }[] {
        return this.#operator === recipient
            ? []
            : [{ bps: BASIS_POINTS_DENOMINATOR - this.#facilitatorFee, recipient }];
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

function tokenProgramFor(requirements: PaymentRequirements): string {
    const fromExtra = requirements.extra?.tokenProgram;
    if (typeof fromExtra === 'string') return fromExtra;
    return getStablecoinTokenProgram(requirements.asset, requirements.network);
}
