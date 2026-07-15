import { createHash } from 'node:crypto';

import { getBase64Codec, getTransactionDecoder } from '@solana/kit';
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
import { requireMint, resolveCoin } from '../coin.js';
import { assertReplayStorePolicy, type PayKitConfig } from '../config.js';
import { InvalidProofError } from '../errors.js';
import type { Gate } from '../gate.js';
import type { Payment } from '../payment.js';
import { caip2 } from '../protocol.js';
import {
    assertPaymentHeaderWithinCap,
    ChallengeBlockhashCache,
    errorMessage,
    resolveX402ReplayStore,
    x402PaymentHeader,
} from './x402-shared.js';

/** x402 v2 protocol version advertised in the challenge envelope. */
const X402_VERSION = 2;
/** Default completion window advertised in `maxTimeoutSeconds`. */
const MAX_TIMEOUT_SECONDS = 300;
/** Settlement-response header mirrored by the x402 SDK family. */
const PAYMENT_RESPONSE_HEADER = 'x-payment-response';
/** 402 challenge header read by x402 clients (alongside the JSON body). */
const PAYMENT_REQUIRED_HEADER = 'payment-required';
const CONSUMED_PREFIX = 'x402-svm-exact:consumed:';

const RELEASE_SAFE_SETTLE_REASONS: ReadonlySet<string> = new Set([
    'verification_failed',
    'unsupported_scheme',
    'network_mismatch',
    'fee_payer_not_managed_by_facilitator',
    'invalid_exact_svm_payload_missing_fee_payer',
    'invalid_exact_svm_payload_transaction_could_not_be_decoded',
    'invalid_exact_svm_payload_transaction_instructions_length',
    'invalid_exact_svm_payload_no_transfer_instruction',
    'invalid_exact_svm_payload_mint_mismatch',
    'invalid_exact_svm_payload_recipient_mismatch',
    'invalid_exact_svm_payload_amount_mismatch',
    'invalid_exact_svm_payload_memo_count',
    'invalid_exact_svm_payload_memo_mismatch',
    'invalid_exact_svm_payload_transaction_fee_payer_transferring_funds',
]);

/**
 * The x402 `exact` protocol adapter: wraps `@x402/svm`'s exact scheme behind
 * the PayKit {@link ProtocolAdapter} contract, settling SPL transfers through
 * an in-process `@x402/core` facilitator that the configured operator signs
 * and fee-pays. The 402 challenge is delivered both as the `PAYMENT-REQUIRED`
 * header and in the JSON body's `accepts[]`, and the paid retry is read from
 * `X-PAYMENT` (or `PAYMENT-SIGNATURE`), matching the x402 HTTP convention.
 */
export function createX402ExactAdapter(config: PayKitConfig): ProtocolAdapter {
    assertReplayStorePolicy(config);
    const network = caip2(config.network) as Network;
    const operator = config.operator.signer.pubkey;
    const blockhashCache = new ChallengeBlockhashCache();

    // In-process facilitator: the operator both fee-pays and signs settlement.
    const facilitator = new x402Facilitator().register(
        network,
        new ExactSvmFacilitator(
            toFacilitatorSvmSigner(config.operator.signer.signer, { defaultRpcUrl: config.rpcUrl }),
        ),
    );
    const reserveStore = resolveX402ReplayStore(config, 'exact');

    async function claimPayload(key: string): Promise<boolean> {
        return await reserveStore.reserve(`${CONSUMED_PREFIX}${key}`, true, MAX_TIMEOUT_SECONDS);
    }

    async function releasePayload(key: string): Promise<void> {
        await reserveStore.delete(`${CONSUMED_PREFIX}${key}`);
    }

    function payloadKey(header: string, payload: PaymentPayload, requirements: PaymentRequirements): string {
        const transaction = (payload.payload as { transaction?: unknown } | undefined)?.transaction;
        if (typeof transaction !== 'string' || transaction === '') return `header:${header}`;
        try {
            const decoded = getTransactionDecoder().decode(getBase64Codec().encode(transaction));
            const identity = JSON.stringify({
                amount: requirements.amount,
                asset: requirements.asset,
                extra: requirements.extra,
                maxTimeoutSeconds: requirements.maxTimeoutSeconds,
                message: getBase64Codec().decode(decoded.messageBytes),
                network: requirements.network,
                payTo: requirements.payTo,
                scheme: requirements.scheme,
            });
            return `msg:${createHash('sha256').update(identity).digest('hex')}`;
        } catch {
            // Verification remains authoritative; malformed transactions fall back to raw bytes.
        }
        return `tx:${transaction}`;
    }

    function mintFor(gate: Gate): string {
        const coin = resolveCoin(gate.amount, config.stablecoins);
        return requireMint(coin, resolveStablecoinMint(coin, network), config.network);
    }

    /** The route's pinned requirements — the credential is bound to this exact amount. */
    function requirementsFor(gate: Gate, request: Request): PaymentRequirements {
        return {
            amount: gate.total().baseUnits().toString(),
            asset: mintFor(gate),
            extra: { feePayer: operator, memo: new URL(request.url).pathname },
            maxTimeoutSeconds: MAX_TIMEOUT_SECONDS,
            network,
            payTo: gate.payTo,
            scheme: 'exact',
        };
    }

    /**
     * The challenge requirements with a server-fetched recent blockhash in
     * `extra` — so the client can build + sign the transfer without its own RPC
     * round-trip (mirroring MPP's `recentBlockhash`). Falls back to the bare
     * requirements if the fetch fails (the client then fetches its own).
     */
    async function challengeRequirements(gate: Gate, request: Request): Promise<PaymentRequirements> {
        const base = requirementsFor(gate, request);
        const cached = await blockhashCache.recentBlockhash(config.rpcUrl);
        if (cached === undefined) return base;
        return {
            ...base,
            extra: {
                ...base.extra,
                lastValidBlockHeight: cached.lastValidBlockHeight,
                recentBlockhash: cached.blockhash,
            },
        };
    }

    return {
        acceptsEntry(gate: Gate, request: Request): Promise<AcceptsEntry> {
            const requirements = requirementsFor(gate, request);
            return Promise.resolve({ ...requirements, protocol: 'x402' });
        },

        async challengeHeaders(gate: Gate, request: Request): Promise<Readonly<Record<string, string>>> {
            const paymentRequired: PaymentRequired = {
                accepts: [await challengeRequirements(gate, request)],
                resource: { url: new URL(request.url).pathname },
                x402Version: X402_VERSION,
            };
            return { [PAYMENT_REQUIRED_HEADER]: encodePaymentRequiredHeader(paymentRequired) };
        },

        detect(request: Request): boolean {
            return x402PaymentHeader(request) !== undefined;
        },

        protocol: 'x402',
        scheme: 'exact',

        async verifyAndSettle(gate: Gate, request: Request): Promise<Payment> {
            const header = x402PaymentHeader(request);
            if (!header) throw new InvalidProofError('missing_x402_payment_header');
            assertPaymentHeaderWithinCap(header);

            let payload: PaymentPayload;
            try {
                payload = decodePaymentSignatureHeader(header);
            } catch (error) {
                throw new InvalidProofError('invalid_x402_payment_header', errorMessage(error));
            }

            const requirements = requirementsFor(gate, request);
            const verification = await facilitator.verify(payload, requirements);
            if (!verification.isValid) {
                throw new InvalidProofError(verification.invalidReason ?? 'invalid_proof', verification.invalidMessage);
            }

            const key = payloadKey(header, payload, requirements);
            if (!(await claimPayload(key))) {
                throw new InvalidProofError('x402_payment_replayed', 'payment payload already used or in flight');
            }

            let settlement: Awaited<ReturnType<typeof facilitator.settle>>;
            try {
                settlement = await facilitator.settle(payload, requirements);
            } catch (error) {
                // A facilitator can throw after broadcast (for example while
                // awaiting confirmation), so its side-effect boundary is
                // ambiguous. Preserve the reservation and fail closed.
                throw new InvalidProofError('settlement_failed', errorMessage(error));
            }
            if (!settlement.success) {
                const reason = settlement.errorReason ?? 'settlement_failed';
                if (RELEASE_SAFE_SETTLE_REASONS.has(reason)) await releasePayload(key);
                throw new InvalidProofError(reason, settlement.errorMessage);
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
