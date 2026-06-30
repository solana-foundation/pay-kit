import { createSolanaRpc } from '@solana/kit';
import { x402Facilitator } from '@x402/core/facilitator';
import {
    decodePaymentSignatureHeader,
    encodePaymentRequiredHeader,
    encodePaymentResponseHeader,
} from '@x402/core/http';
import type { Network, PaymentPayload, PaymentRequired, PaymentRequirements } from '@x402/core/types';
import { resolveStablecoinMint, toFacilitatorSvmSigner } from '@x402/svm';
import { ExactSvmScheme as ExactSvmFacilitator } from '@x402/svm/exact/facilitator';

import type { ProtocolAdapter } from '../adapter.js';
import type { AcceptsEntry } from '../challenge.js';
import type { PayKitConfig } from '../config.js';
import { ConfigurationError, InvalidProofError } from '../errors.js';
import type { Gate } from '../gate.js';
import type { Payment } from '../payment.js';
import { caip2 } from '../protocol.js';

/** x402 v2 protocol version advertised in the challenge envelope. */
const X402_VERSION = 2;
/** Default completion window advertised in `maxTimeoutSeconds`. */
const MAX_TIMEOUT_SECONDS = 300;
/** Settlement-response header mirrored by the x402 SDK family. */
const PAYMENT_RESPONSE_HEADER = 'x-payment-response';
/** 402 challenge header read by x402 clients (alongside the JSON body). */
const PAYMENT_REQUIRED_HEADER = 'payment-required';

/**
 * The x402 `exact` protocol adapter: wraps `@x402/svm`'s exact scheme behind
 * the PayKit {@link ProtocolAdapter} contract, settling SPL transfers through
 * an in-process `@x402/core` facilitator that the configured operator signs
 * and fee-pays. The 402 challenge is delivered both as the `PAYMENT-REQUIRED`
 * header and in the JSON body's `accepts[]`, and the paid retry is read from
 * `X-PAYMENT` (or `PAYMENT-SIGNATURE`), matching the x402 HTTP convention.
 */
export function createX402ExactAdapter(config: PayKitConfig): ProtocolAdapter {
    const network = caip2(config.network) as Network;
    const operator = config.operator.signer.pubkey;

    // In-process facilitator: the operator both fee-pays and signs settlement.
    const facilitator = new x402Facilitator().register(
        network,
        new ExactSvmFacilitator(
            toFacilitatorSvmSigner(config.operator.signer.signer, { defaultRpcUrl: config.rpcUrl }),
        ),
    );

    function mintFor(gate: Gate): string {
        const coin = gate.amount.primaryCoin() ?? config.stablecoins[0] ?? 'USDC';
        const mint = resolveStablecoinMint(coin, network);
        if (!mint) throw new ConfigurationError(`No ${coin} mint known for ${config.network}.`);
        return mint;
    }

    /** The route's pinned requirements — the credential is bound to this exact amount. */
    function requirementsFor(gate: Gate): PaymentRequirements {
        return {
            amount: gate.total().baseUnits().toString(),
            asset: mintFor(gate),
            extra: { feePayer: operator },
            maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
            network,
            payTo: gate.payTo,
            scheme: 'exact',
        };
    }

    function paymentHeader(request: Request): string | undefined {
        return request.headers.get('x-payment') ?? request.headers.get('payment-signature') ?? undefined;
    }

    /**
     * The challenge requirements with a server-fetched recent blockhash in
     * `extra` — so the client can build + sign the transfer without its own RPC
     * round-trip (mirroring MPP's `recentBlockhash`). Falls back to the bare
     * requirements if the fetch fails (the client then fetches its own).
     */
    async function challengeRequirements(gate: Gate): Promise<PaymentRequirements> {
        const base = requirementsFor(gate);
        try {
            const { value } = await createSolanaRpc(config.rpcUrl).getLatestBlockhash().send();
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

    return {
        acceptsEntry(gate: Gate): Promise<AcceptsEntry> {
            const requirements = requirementsFor(gate);
            return Promise.resolve({ ...requirements, protocol: 'x402' });
        },

        async challengeHeaders(gate: Gate, request: Request): Promise<Readonly<Record<string, string>>> {
            const paymentRequired: PaymentRequired = {
                accepts: [await challengeRequirements(gate)],
                resource: { url: new URL(request.url).pathname },
                x402Version: X402_VERSION,
            };
            return { [PAYMENT_REQUIRED_HEADER]: encodePaymentRequiredHeader(paymentRequired) };
        },

        detect(request: Request): boolean {
            return paymentHeader(request) !== undefined;
        },

        protocol: 'x402',
        scheme: 'exact',

        async verifyAndSettle(gate: Gate, request: Request): Promise<Payment> {
            const header = paymentHeader(request);
            if (!header) throw new InvalidProofError('missing_x402_payment_header');

            let payload: PaymentPayload;
            try {
                payload = decodePaymentSignatureHeader(header);
            } catch (error) {
                throw new InvalidProofError('invalid_x402_payment_header', errorMessage(error));
            }

            const requirements = requirementsFor(gate);
            const verification = await facilitator.verify(payload, requirements);
            if (!verification.isValid) {
                throw new InvalidProofError(verification.invalidReason ?? 'invalid_proof', verification.invalidMessage);
            }

            const settlement = await facilitator.settle(payload, requirements);
            if (!settlement.success) {
                throw new InvalidProofError(settlement.errorReason ?? 'settlement_failed', settlement.errorMessage);
            }

            return {
                gateName: gate.name,
                payer: settlement.payer ?? verification.payer,
                protocol: 'x402',
                raw: header,
                scheme: 'exact',
                settlementHeaders: { [PAYMENT_RESPONSE_HEADER]: encodePaymentResponseHeader(settlement) },
                transaction: settlement.transaction,
            };
        },
    };
}

function errorMessage(error: unknown): string | undefined {
    return error instanceof Error ? error.message : undefined;
}
