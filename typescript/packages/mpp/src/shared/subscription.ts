import { type Address, address, getAddressEncoder, getProgramDerivedAddress } from '@solana/kit';
import {
    getSubscribeInstructionDataEncoder,
    getTransferSubscriptionInstructionDataEncoder,
} from '@solana/subscriptions';

/** Maximum `period_hours` supported by the subscriptions program. */
const MAX_PERIOD_HOURS = 8760;

/**
 * draft-solana-subscription-00 §Shared Fields: `amount` and `periodCount` are
 * positive base-10 integers "with no sign, decimal point, exponent, or
 * surrounding whitespace. Leading zeros MUST NOT be used."
 */
const POSITIVE_DECIMAL_INTEGER = /^[1-9][0-9]*$/;

/**
 * Parse a wire `amount` or `periodCount` under the profile's strict integer
 * format, refusing what `Number()` or `BigInt()` would silently accept
 * (`"030"`, `"+30"`, `"30.0"`, `"3e1"`, `" 30"`).
 *
 * @throws If `value` is not a positive base-10 integer without leading zeros.
 */
export function parseSubscriptionInteger(value: string, field: 'amount' | 'periodCount'): bigint {
    if (typeof value !== 'string' || !POSITIVE_DECIMAL_INTEGER.test(value)) {
        throw new Error(
            `${field} must be a positive base-10 integer with no sign, decimal point, exponent, whitespace, or leading zeros, got ${JSON.stringify(value)}`,
        );
    }
    return BigInt(value);
}

/**
 * Map the shared subscription period to the subscriptions program's
 * `period_hours` value. The Solana profile only supports `day` and `week`;
 * `month` cannot be represented exactly because the on-chain program uses
 * fixed elapsed seconds.
 *
 * `periodCount` may be the wire string, which is held to the profile's strict
 * integer format, or a number (server configuration).
 *
 * @throws If the inputs cannot be represented on-chain.
 */
export function mapSubscriptionPeriodToHours(periodUnit: 'day' | 'week', periodCountInput: number | string): number {
    const periodCount =
        typeof periodCountInput === 'string'
            ? Number(parseSubscriptionInteger(periodCountInput, 'periodCount'))
            : periodCountInput;
    if (!Number.isInteger(periodCount) || periodCount <= 0) {
        throw new Error(`periodCount must be a positive integer, got ${periodCount}`);
    }
    if (periodUnit === 'day') {
        if (periodCount > 365) {
            throw new Error(`periodCount=${periodCount} for periodUnit="day" exceeds 365`);
        }
        return periodCount * 24;
    }
    if (periodUnit === 'week') {
        if (periodCount > 52) {
            throw new Error(`periodCount=${periodCount} for periodUnit="week" exceeds 52`);
        }
        return periodCount * 168;
    }
    // The Zod schema rejects `month` at the framework boundary; this branch
    // exists for defense-in-depth and as a clear error for direct callers.
    throw new Error(`Solana subscription profile rejects periodUnit="${String(periodUnit)}"`);
}

/** Verify the computed `period_hours` is within the on-chain program's [1, 8760] bound. */
export function assertPeriodHoursInRange(periodHours: number): void {
    if (!Number.isInteger(periodHours) || periodHours < 1 || periodHours > MAX_PERIOD_HOURS) {
        throw new Error(`period_hours ${periodHours} out of [1, ${MAX_PERIOD_HOURS}] range`);
    }
}

/**
 * Derive the `SubscriptionAuthority` PDA for a given subscriber and mint.
 * Seeds: `["SubscriptionAuthority", subscriber, mint]`.
 */
export async function deriveSubscriptionAuthorityPda(params: {
    mint: Address;
    programId: Address;
    subscriber: Address;
}): Promise<Address> {
    const encoder = getAddressEncoder();
    const [pda] = await getProgramDerivedAddress({
        programAddress: params.programId,
        seeds: [
            new TextEncoder().encode('SubscriptionAuthority'),
            encoder.encode(params.subscriber),
            encoder.encode(params.mint),
        ],
    });
    return pda;
}

/**
 * Derive the `SubscriptionDelegation` PDA for a given plan and subscriber.
 * Seeds: `["subscription", plan_pda, subscriber]`.
 */
export async function deriveSubscriptionPda(params: {
    planPda: Address;
    programId: Address;
    subscriber: Address;
}): Promise<Address> {
    const encoder = getAddressEncoder();
    const [pda] = await getProgramDerivedAddress({
        programAddress: params.programId,
        seeds: [
            new TextEncoder().encode('subscription'),
            encoder.encode(params.planPda),
            encoder.encode(params.subscriber),
        ],
    });
    return pda;
}

/** Fields of the subscriptions program's `subscribe` instruction data. */
export type SubscribeInstructionDataFields = {
    /** Base-10 `expected_amount` (u64): the Plan's per-period amount. */
    amount: bigint | number | string;
    /** `expected_subscription_authority_init_id` (i64) of the subscriber's authority. */
    authorityInitId: bigint | number;
    /** `expected_created_at` (i64): the Plan's creation timestamp. */
    createdAt: bigint | number;
    /** Base58 `expected_mint`. */
    mint: string;
    /** `expected_period_hours` (u64). */
    periodHours: bigint | number;
    /** `plan_bump` (u8). */
    planBump: number;
    /** `plan_id` (u64). */
    planId: bigint | number;
};

/** Fields of the subscriptions program's `transfer_subscription` instruction data. */
export type TransferSubscriptionInstructionDataFields = {
    /** Base-10 amount (u64) pulled for the period. */
    amount: bigint | number | string;
    /** Base58 of the subscriber (the delegator). */
    delegator: string;
    /** Base58 of the token mint. */
    mint: string;
};

function u64(value: bigint | number | string, field: string): bigint {
    const parsed = typeof value === 'string' ? parseSubscriptionInteger(value, 'amount') : BigInt(value);
    if (parsed < 0n || parsed >= 1n << 64n) throw new Error(`${field} must fit in a u64`);
    return parsed;
}

/**
 * Encode the subscriptions program's `subscribe` instruction data
 * (discriminator 11, `plan_id` u64, `plan_bump` u8, expected mint, amount,
 * `period_hours`, `created_at` and authority `init_id`; 74 bytes), using the
 * program's generated codec.
 */
export function encodeSubscribeInstructionData(fields: SubscribeInstructionDataFields): Uint8Array {
    return new Uint8Array(
        getSubscribeInstructionDataEncoder().encode({
            subscribeData: {
                expectedAmount: u64(fields.amount, 'amount'),
                expectedCreatedAt: BigInt(fields.createdAt),
                expectedMint: address(fields.mint),
                expectedPeriodHours: u64(fields.periodHours, 'periodHours'),
                expectedSubscriptionAuthorityInitId: BigInt(fields.authorityInitId),
                planBump: fields.planBump,
                planId: u64(fields.planId, 'planId'),
            },
        }),
    );
}

/**
 * Encode the subscriptions program's `transfer_subscription` instruction data
 * (discriminator 10, amount u64, delegator, mint; 73 bytes), using the
 * program's generated codec.
 */
export function encodeTransferSubscriptionInstructionData(
    fields: TransferSubscriptionInstructionDataFields,
): Uint8Array {
    return new Uint8Array(
        getTransferSubscriptionInstructionDataEncoder().encode({
            transferData: {
                amount: u64(fields.amount, 'amount'),
                delegator: address(fields.delegator),
                mint: address(fields.mint),
            },
        }),
    );
}
