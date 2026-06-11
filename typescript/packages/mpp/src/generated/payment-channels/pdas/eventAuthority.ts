/**
 * Vendored from
 * https://github.com/solana-foundation/payment-channel/blob/main/clients/typescript/src/generated/pdas/eventAuthority.ts
 */

import { type Address, getProgramDerivedAddress, getUtf8Encoder, type ProgramDerivedAddress } from '@solana/kit';

export async function findEventAuthorityPda(
    config: { programAddress?: Address | undefined } = {},
): Promise<ProgramDerivedAddress> {
    const {
        programAddress = 'GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc' as Address<'GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc'>,
    } = config;
    return await getProgramDerivedAddress({
        programAddress,
        seeds: [getUtf8Encoder().encode('event_authority')],
    });
}
