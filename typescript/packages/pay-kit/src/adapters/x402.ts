import { createSolanaRpc, getBase58Decoder, getBase64Codec, getTransactionDecoder } from '@solana/kit';
import { isReservingStore } from '@solana/mpp/server';
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
import type { PayKitConfig } from '../config.js';
import { InvalidProofError } from '../errors.js';
import type { Gate } from '../gate.js';
import type { Payment } from '../payment.js';
import { caip2 } from '../protocol.js';
import { errorMessage, x402PaymentHeader } from './x402-shared.js';

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

    // In-flight/consumed dedup for exact payloads, mirroring the Rust x402
    // exact signature-consume store and the `inFlightUptoChannels` guard on the
    // upto path: without it, a duplicate X-PAYMENT payload racing (or trailing)
    // the original settles the resource twice for one payment before the ledger
    // can dedupe the broadcast. Keyed by the payload transaction's client
    // signature(s) — the fee-payer signature slot is zeroed until the
    // facilitator countersigns, so raw header bytes are malleable while the
    // client signature is not.
    //
    // When the configured replay store implements the atomic reserve capability
    // (put-if-absent, e.g. Redis SET NX EX), the claim is cross-process safe:
    // two replicas sharing the store cannot both settle the same payload. The
    // reservation is given a MAX_TIMEOUT_SECONDS TTL — past that window the
    // payment's blockhash has expired and a rebroadcast is rejected on-chain
    // anyway. Without a reserving store the guard degrades to a process-local
    // Map with the same TTL (single-process scope; see SECURITY.md).
    const reserveStore =
        config.replayStore !== undefined && isReservingStore(config.replayStore) ? config.replayStore : undefined;
    const consumedPayloads = new Map<string, number>();
    const CONSUMED_PREFIX = 'x402-exact:consumed:';

    function pruneConsumed(now: number): void {
        // Insertion order is timestamp order (keys are only ever added), so
        // stop at the first still-fresh entry.
        for (const [key, at] of consumedPayloads) {
            if (now - at <= MAX_TIMEOUT_SECONDS * 1000) break;
            consumedPayloads.delete(key);
        }
    }

    /**
     * Atomically claim `key` as consumed. Returns true when newly claimed,
     * false when a live duplicate already holds it. Uses the reserving store
     * (cross-process) when available, else the process-local Map.
     */
    async function claimPayload(key: string): Promise<boolean> {
        if (reserveStore) {
            return await reserveStore.reserve(`${CONSUMED_PREFIX}${key}`, true, MAX_TIMEOUT_SECONDS);
        }
        const now = Date.now();
        pruneConsumed(now);
        if (consumedPayloads.has(key)) return false;
        consumedPayloads.set(key, now);
        return true;
    }

    /** Release a claim so a failed settle can be retried. */
    async function releasePayload(key: string): Promise<void> {
        if (reserveStore) {
            await reserveStore.delete(`${CONSUMED_PREFIX}${key}`);
            return;
        }
        consumedPayloads.delete(key);
    }

    function payloadKey(header: string, payload: PaymentPayload): string {
        const txBase64 = (payload.payload as { transaction?: unknown } | undefined)?.transaction;
        if (typeof txBase64 !== 'string' || txBase64 === '') return `header:${header}`;
        try {
            const decoded = getTransactionDecoder().decode(getBase64Codec().encode(txBase64));
            const signatures = Object.values(decoded.signatures as Readonly<Record<string, Uint8Array | null>>)
                .filter((sig): sig is Uint8Array => sig !== null && sig.some(byte => byte !== 0))
                .map(sig => getBase58Decoder().decode(sig))
                .sort();
            if (signatures.length > 0) return `sig:${signatures.join(':')}`;
        } catch {
            // Undecodable transaction bytes: fall through to the raw-bytes
            // key; facilitator.verify() is the authority on acceptability.
        }
        return `tx:${txBase64}`;
    }

    function mintFor(gate: Gate): string {
        const coin = resolveCoin(gate.amount, config.stablecoins);
        return requireMint(coin, resolveStablecoinMint(coin, network), config.network);
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
            return x402PaymentHeader(request) !== undefined;
        },

        protocol: 'x402',
        scheme: 'exact',

        async verifyAndSettle(gate: Gate, request: Request): Promise<Payment> {
            const header = x402PaymentHeader(request);
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

            // Consume the payload before settling: a concurrent duplicate is
            // rejected here, and a settled payload stays consumed for the
            // advertised completion window. Only a FAILED settle releases the
            // key (the payment did not happen, a retry must be able to proceed).
            const key = payloadKey(header, payload);
            if (!(await claimPayload(key))) {
                throw new InvalidProofError('x402_payment_replayed', 'payment payload already used or in flight');
            }

            let settlement;
            try {
                settlement = await facilitator.settle(payload, requirements);
            } catch (error) {
                await releasePayload(key);
                throw error;
            }
            if (!settlement.success) {
                await releasePayload(key);
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
