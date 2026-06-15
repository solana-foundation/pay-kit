/**
 * Vendored from
 * https://github.com/solana-foundation/payment-channel/blob/main/clients/typescript/src/generated/programs/paymentChannels.ts
 *
 * Minimal subset: only the program-address constant is needed by the
 * `open` instruction builder; the wider plugin surface is omitted.
 */

import type { Address } from '@solana/kit';

export const PAYMENT_CHANNELS_PROGRAM_ADDRESS =
    'GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc' as Address<'GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc'>;
