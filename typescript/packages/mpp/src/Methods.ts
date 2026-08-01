import { Method, z } from 'mppx';

const sessionVoucherSigner = z.enum(['client', 'operator']);
const sessionAuthentication = z.object({
    challengeId: z.string(),
    payer: z.string(),
    signature: z.string(),
    type: z.literal('proof'),
});

/**
 * `expiresAt` is an i64 on the wire, but JSON numbers above 2^53 - 1 lose
 * precision in JavaScript — reject those at the parse boundary instead of
 * surfacing a generic safe-integer error deep inside verification.
 */
const voucherExpiresAt = z
    .number()
    .check(
        z.refine(
            value => Number.isSafeInteger(value),
            'expiresAt is an i64 but exceeds JavaScript safe-integer precision (2^53 - 1); larger values cannot be represented as JSON numbers',
        ),
    );

const signedVoucher = z.object({
    /** Base58 Ed25519 signature over the canonical voucher bytes. */
    signature: z.string(),

    /** Voucher signature algorithm. */
    signatureType: z.literal('ed25519'),

    /** Base58 public key that signed the voucher. */
    signer: z.string(),

    /**
     * The voucher content, carried on the wire as `voucher` per the spec's
     * Signed Voucher table (mpp-specs e702dd8).
     */
    voucher: z.object({
        /** Channel/session ID the voucher is bound to. */
        channelId: z.string(),
        /** Cumulative amount authorized in base units. */
        cumulativeAmount: z.string(),
        /** Unix timestamp at which this voucher expires. */
        expiresAt: z.optional(voucherExpiresAt),
    }),
});

/**
 * Solana charge method — shared schema used by both server and client.
 *
 * Supports two settlement modes:
 *
 * - **Pull mode** (`type="transaction"`, default): Client signs the
 *   transaction and sends the bytes to the server. The server broadcasts,
 *   confirms, and verifies the transfer on-chain.
 *
 * - **Push mode** (`type="signature"`): Client broadcasts the transaction
 *   itself and sends the confirmed signature. The server verifies on-chain.
 */
export const charge = Method.from({
    intent: 'charge',
    name: 'solana',
    schema: {
        credential: {
            payload: z.object({
                /** Base58-encoded transaction signature (when type="signature"). */
                signature: z.optional(z.string()),
                /** Base64-encoded serialized signed transaction (when type="transaction"). */
                transaction: z.optional(z.string()),
                /** Payload type: "transaction" (server broadcasts) or "signature" (client already broadcast). */
                type: z.string(),
            }),
        },
        request: z.object({
            /** Amount in smallest unit (lamports for SOL, base units for SPL tokens). */
            amount: z.string(),
            /** Identifies the unit for amount. "sol" (lowercase) for native SOL, or the token mint address for SPL tokens. */
            currency: z.string(),
            /** Human-readable memo describing the resource or service being paid for. */
            description: z.optional(z.string()),
            /** Merchant's reference (e.g., order ID, invoice number) for reconciliation. */
            externalId: z.optional(z.string()),
            methodDetails: z.object({
                /** Token decimals (required for SPL token transfers). */
                decimals: z.optional(z.number()),
                /** If true, server pays transaction fees. Client must use the server's feePayerKey. */
                feePayer: z.optional(z.boolean()),
                /** Server's base58-encoded public key for fee payment. Present when feePayer is true. */
                feePayerKey: z.optional(z.string()),
                /** Solana network: mainnet, devnet, or localnet. */
                network: z.optional(z.string()),
                /** Server-provided base58-encoded recent blockhash. Saves the client an RPC round-trip. */
                recentBlockhash: z.optional(z.string()),
                /** Additional payment splits (max 8). Same asset as primary payment. */
                splits: z.optional(
                    z.array(
                        z.object({
                            /** Amount in base units (same asset as primary). */
                            amount: z.string(),
                            /** If true, the split recipient ATA must be created idempotently before payment. */
                            ataCreationRequired: z.optional(z.boolean()),
                            /** Optional memo for this split (max 566 bytes). */
                            memo: z.optional(z.string()),
                            /** Base58-encoded recipient of this split. */
                            recipient: z.string(),
                        }),
                    ),
                ),
                /** Token program address (TOKEN_PROGRAM or TOKEN_2022_PROGRAM). Defaults from the currency mint. */
                tokenProgram: z.optional(z.string()),
            }),
            /** Base58-encoded recipient public key. */
            recipient: z.string(),
        }),
    },
});

const subscriptionPeriodUnit = z.enum(['day', 'week']);

/**
 * Solana subscription method — shared schema used by both server and client.
 *
 * A subscription creates an on-chain delegation that lets the server pull
 * a fixed token amount once per billing period. Activation atomically
 * creates the delegation and executes the first-period charge. Subsequent
 * renewals are server-driven and require no HTTP round-trip.
 *
 * Period mapping: `day` → `periodCount * 24` hours, `week` → `periodCount * 168`
 * hours. `month` is rejected because the on-chain program uses fixed elapsed
 * seconds and cannot represent calendar-month cadence exactly.
 */
export const subscription = Method.from({
    intent: 'subscription',
    name: 'solana',
    schema: {
        credential: {
            payload: z.object({
                /** Base58 transaction signature (when type="signature"). */
                signature: z.optional(z.string()),
                /** Base64-encoded serialized activation transaction (when type="transaction"). */
                transaction: z.optional(z.string()),
                /** Payload type: "transaction" (server broadcasts) or "signature" (client already broadcast). */
                type: z.string(),
            }),
        },
        request: z.object({
            /** Per-period token amount in base units. */
            amount: z.string(),
            /** Base58 SPL token mint address. */
            currency: z.string(),
            /** Human-readable subscription description. */
            description: z.optional(z.string()),
            /** Merchant reference for the subscription. */
            externalId: z.optional(z.string()),
            methodDetails: z.object({
                /** Token decimals. */
                decimals: z.number(),
                /** If true, server pays activation transaction fees. */
                feePayer: z.optional(z.boolean()),
                /** Server's base58 fee-payer pubkey. Required when feePayer is true. */
                feePayerKey: z.optional(z.string()),
                /** Base58 of the SPL token mint. Must equal the on-chain plan.mint. */
                mint: z.string(),
                /** Solana network: mainnet, devnet, or localnet. */
                network: z.optional(z.string()),
                /** Base58 of the on-chain Plan PDA. */
                planId: z.string(),
                /** Base58 of the subscriptions program ID. */
                programId: z.optional(z.string()),
                /** Base58 of the server's puller pubkey (must be in plan.pullers or plan.owner). */
                puller: z.string(),
                /** Pre-fetched recent blockhash to bind to the activation transaction. */
                recentBlockhash: z.optional(z.string()),
                /** Advisory distribution splits (on-chain split is governed by plan.destinations). */
                splits: z.optional(
                    z.array(
                        z.object({
                            /** Share in basis points. */
                            bps: z.number(),
                            /** Split recipient public key. */
                            recipient: z.string(),
                        }),
                    ),
                ),
                /** Base58 of the SPL Token or Token-2022 program ID. */
                tokenProgram: z.string(),
            }),
            /** Positive integer count of `periodUnit` values per billing period. */
            periodCount: z.string(),
            /** Billing period unit. The Solana profile supports `day` and `week` only. */
            periodUnit: subscriptionPeriodUnit,
            /** Primary recipient's wallet pubkey (base58). */
            recipient: z.string(),
            /** RFC3339 expiry of the recurring authorization. */
            subscriptionExpires: z.optional(z.string()),
        }),
    },
});

/**
 * Solana session method — shared schema used by both server and client.
 *
 * A session opens a payment channel once, then pays for later deliveries with
 * cumulative off-chain vouchers.
 */
export const session = Method.from({
    intent: 'session',
    name: 'solana',
    schema: {
        credential: {
            payload: z.discriminatedUnion('action', [
                z.object({
                    action: z.literal('open'),
                    authentication: z.optional(sessionAuthentication),
                    /** Opaque server-scoped authorization policy echoed on the wire. */
                    authorizationPolicy: z.optional(z.record(z.string(), z.unknown())),
                    authorizedSigner: z.string(),
                    /** Opaque capability map echoed on the wire. */
                    capabilities: z.optional(z.record(z.string(), z.unknown())),
                    channelId: z.string(),
                    depositAmount: z.string(),
                    distributionSplits: z.optional(z.array(z.object({ recipient: z.string(), shareBps: z.number() }))),
                    gracePeriodSeconds: z.number(),
                    idleTimeoutSeconds: z.optional(z.number()),
                    mint: z.string(),
                    openSlot: z.string(),
                    payee: z.string(),
                    payer: z.string(),
                    salt: z.string(),
                    transaction: z.string(),
                }),
                z.object({
                    action: z.literal('voucher'),
                    /**
                     * REQUIRED routing key next to the signed voucher; the
                     * server rejects the action when it differs from the
                     * signed voucher's inner `channelId`.
                     */
                    channelId: z.string(),
                    voucher: signedVoucher,
                }),
                z.object({
                    action: z.literal('use'),
                    authentication: sessionAuthentication,
                    channelId: z.string(),
                }),
                z.object({
                    action: z.literal('topUp'),
                    additionalAmount: z.string(),
                    channelId: z.string(),
                    transaction: z.string(),
                }),
                z.object({
                    action: z.literal('close'),
                    authentication: z.optional(sessionAuthentication),
                    channelId: z.string(),
                    voucher: z.optional(signedVoucher),
                }),
            ]),
        },
        request: z.object({
            /** Price per unit of service, in base units. */
            amount: z.string(),
            currency: z.string(),
            description: z.optional(z.string()),
            externalId: z.optional(z.string()),
            methodDetails: z.object({
                channelId: z.optional(z.string()),
                channelProgram: z.string(),
                decimals: z.optional(z.number()),
                distributionSplits: z.optional(z.array(z.object({ recipient: z.string(), shareBps: z.number() }))),
                feePayer: z.optional(z.boolean()),
                feePayerKey: z.optional(z.string()),
                gracePeriodSeconds: z.optional(z.number()),
                idleTimeoutOptionsSeconds: z.optional(z.array(z.number())),
                idleTimeoutSeconds: z.optional(z.number()),
                minVoucherDelta: z.optional(z.string()),
                network: z.string(),
                operator: z.optional(z.string()),
                /**
                 * Base58 blockhash the client MUST use as the open
                 * transaction's recent blockhash, and the RPC context slot
                 * from the same `getLatestBlockhash` response — the client's
                 * default `openSlot`, a u64 decimal string on the wire.
                 * Conditionally REQUIRED when `channelId` is absent (new
                 * channel); MUST be absent when resuming an existing channel.
                 */
                recentBlockhash: z.optional(z.string()),
                recentSlot: z.optional(z.string()),
                tokenProgram: z.optional(z.string()),
                ttlSeconds: z.optional(z.number()),
                voucherSigner: z.optional(sessionVoucherSigner),
            }),
            minimumDeposit: z.optional(z.string()),
            recipient: z.string(),
            suggestedDeposit: z.optional(z.string()),
            unitType: z.optional(z.string()),
        }),
    },
});
