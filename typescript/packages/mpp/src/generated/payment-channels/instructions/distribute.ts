/**
 * Vendored from
 * https://github.com/solana-foundation/payment-channel/blob/main/clients/typescript/src/generated/instructions/distribute.ts
 *
 * Parsing / async helpers omitted; only the synchronous
 * `getDistributeInstruction` builder is needed by the server. Imports
 * rewritten for Node16 module resolution.
 */

import {
    type AccountMeta,
    AccountRole,
    type Address,
    type Codec,
    combineCodec,
    type Decoder,
    type Encoder,
    getStructDecoder,
    getStructEncoder,
    type Instruction,
    type InstructionWithAccounts,
    type InstructionWithData,
    type ReadonlyAccount,
    type ReadonlyUint8Array,
    transformEncoder,
    type WritableAccount,
} from '@solana/kit';
import { getAccountMetaFactory, type ResolvedInstructionAccount } from '@solana/program-client-core';

import { PAYMENT_CHANNELS_PROGRAM_ADDRESS } from '../programs/paymentChannels.js';
import { getU8Decoder, getU8Encoder } from '../safe-codecs.js';
import {
    type DistributeArgs,
    type DistributeArgsArgs,
    getDistributeArgsDecoder,
    getDistributeArgsEncoder,
} from '../types/distributeArgs.js';

export const DISTRIBUTE_DISCRIMINATOR = 7;

export function getDistributeDiscriminatorBytes(): ReadonlyUint8Array {
    return getU8Encoder().encode(DISTRIBUTE_DISCRIMINATOR);
}

export type DistributeInstruction<
    TProgram extends string = typeof PAYMENT_CHANNELS_PROGRAM_ADDRESS,
    TAccountChannel extends AccountMeta<string> | string = string,
    TAccountPayer extends AccountMeta<string> | string = string,
    TAccountChannelTokenAccount extends AccountMeta<string> | string = string,
    TAccountPayerTokenAccount extends AccountMeta<string> | string = string,
    TAccountPayeeTokenAccount extends AccountMeta<string> | string = string,
    TAccountTreasuryTokenAccount extends AccountMeta<string> | string = string,
    TAccountMint extends AccountMeta<string> | string = string,
    TAccountTokenProgram extends AccountMeta<string> | string = string,
    TAccountEventAuthority extends AccountMeta<string> | string = string,
    TAccountSelfProgram extends AccountMeta<string> | string = 'GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc',
    TRemainingAccounts extends readonly AccountMeta<string>[] = [],
> = Instruction<TProgram> &
    InstructionWithAccounts<
        [
            TAccountChannel extends string ? WritableAccount<TAccountChannel> : TAccountChannel,
            TAccountPayer extends string ? WritableAccount<TAccountPayer> : TAccountPayer,
            TAccountChannelTokenAccount extends string
                ? WritableAccount<TAccountChannelTokenAccount>
                : TAccountChannelTokenAccount,
            TAccountPayerTokenAccount extends string
                ? WritableAccount<TAccountPayerTokenAccount>
                : TAccountPayerTokenAccount,
            TAccountPayeeTokenAccount extends string
                ? WritableAccount<TAccountPayeeTokenAccount>
                : TAccountPayeeTokenAccount,
            TAccountTreasuryTokenAccount extends string
                ? WritableAccount<TAccountTreasuryTokenAccount>
                : TAccountTreasuryTokenAccount,
            TAccountMint extends string ? ReadonlyAccount<TAccountMint> : TAccountMint,
            TAccountTokenProgram extends string ? ReadonlyAccount<TAccountTokenProgram> : TAccountTokenProgram,
            TAccountEventAuthority extends string ? ReadonlyAccount<TAccountEventAuthority> : TAccountEventAuthority,
            TAccountSelfProgram extends string ? ReadonlyAccount<TAccountSelfProgram> : TAccountSelfProgram,
            ...TRemainingAccounts,
        ]
    > &
    InstructionWithData<ReadonlyUint8Array>;

export type DistributeInstructionData = { discriminator: number; distributeArgs: DistributeArgs };
export type DistributeInstructionDataArgs = { distributeArgs: DistributeArgsArgs };

export function getDistributeInstructionDataEncoder(): Encoder<DistributeInstructionDataArgs> {
    return transformEncoder(
        getStructEncoder([
            ['discriminator', getU8Encoder()],
            ['distributeArgs', getDistributeArgsEncoder()],
        ]),
        value => ({ ...value, discriminator: DISTRIBUTE_DISCRIMINATOR }),
    );
}

export function getDistributeInstructionDataDecoder(): Decoder<DistributeInstructionData> {
    return getStructDecoder([
        ['discriminator', getU8Decoder()],
        ['distributeArgs', getDistributeArgsDecoder()],
    ]);
}

export function getDistributeInstructionDataCodec(): Codec<DistributeInstructionDataArgs, DistributeInstructionData> {
    return combineCodec(getDistributeInstructionDataEncoder(), getDistributeInstructionDataDecoder());
}

export type DistributeInput<
    TAccountChannel extends string = string,
    TAccountPayer extends string = string,
    TAccountChannelTokenAccount extends string = string,
    TAccountPayerTokenAccount extends string = string,
    TAccountPayeeTokenAccount extends string = string,
    TAccountTreasuryTokenAccount extends string = string,
    TAccountMint extends string = string,
    TAccountTokenProgram extends string = string,
    TAccountEventAuthority extends string = string,
    TAccountSelfProgram extends string = string,
> = {
    channel: Address<TAccountChannel>;
    channelTokenAccount: Address<TAccountChannelTokenAccount>;
    distributeArgs: DistributeInstructionDataArgs['distributeArgs'];
    eventAuthority: Address<TAccountEventAuthority>;
    mint: Address<TAccountMint>;
    payeeTokenAccount: Address<TAccountPayeeTokenAccount>;
    payer: Address<TAccountPayer>;
    payerTokenAccount: Address<TAccountPayerTokenAccount>;
    recipientTokenAccounts: Array<Address>;
    selfProgram?: Address<TAccountSelfProgram>;
    tokenProgram: Address<TAccountTokenProgram>;
    treasuryTokenAccount: Address<TAccountTreasuryTokenAccount>;
};

export function getDistributeInstruction<
    TAccountChannel extends string,
    TAccountPayer extends string,
    TAccountChannelTokenAccount extends string,
    TAccountPayerTokenAccount extends string,
    TAccountPayeeTokenAccount extends string,
    TAccountTreasuryTokenAccount extends string,
    TAccountMint extends string,
    TAccountTokenProgram extends string,
    TAccountEventAuthority extends string,
    TAccountSelfProgram extends string,
    TProgramAddress extends Address = typeof PAYMENT_CHANNELS_PROGRAM_ADDRESS,
>(
    input: DistributeInput<
        TAccountChannel,
        TAccountPayer,
        TAccountChannelTokenAccount,
        TAccountPayerTokenAccount,
        TAccountPayeeTokenAccount,
        TAccountTreasuryTokenAccount,
        TAccountMint,
        TAccountTokenProgram,
        TAccountEventAuthority,
        TAccountSelfProgram
    >,
    config?: { programAddress?: TProgramAddress },
): DistributeInstruction<
    TProgramAddress,
    TAccountChannel,
    TAccountPayer,
    TAccountChannelTokenAccount,
    TAccountPayerTokenAccount,
    TAccountPayeeTokenAccount,
    TAccountTreasuryTokenAccount,
    TAccountMint,
    TAccountTokenProgram,
    TAccountEventAuthority,
    TAccountSelfProgram
> {
    const programAddress = config?.programAddress ?? PAYMENT_CHANNELS_PROGRAM_ADDRESS;

    const originalAccounts = {
        channel: { isWritable: true, value: input.channel ?? null },
        channelTokenAccount: { isWritable: true, value: input.channelTokenAccount ?? null },
        eventAuthority: { isWritable: false, value: input.eventAuthority ?? null },
        mint: { isWritable: false, value: input.mint ?? null },
        payeeTokenAccount: { isWritable: true, value: input.payeeTokenAccount ?? null },
        payer: { isWritable: true, value: input.payer ?? null },
        payerTokenAccount: { isWritable: true, value: input.payerTokenAccount ?? null },
        selfProgram: { isWritable: false, value: input.selfProgram ?? null },
        tokenProgram: { isWritable: false, value: input.tokenProgram ?? null },
        treasuryTokenAccount: { isWritable: true, value: input.treasuryTokenAccount ?? null },
    };
    const accounts = originalAccounts as Record<keyof typeof originalAccounts, ResolvedInstructionAccount>;

    const args = { ...input };

    if (!accounts.selfProgram.value) {
        accounts.selfProgram.value =
            'GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc' as Address<'GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc'>;
    }

    const remainingAccounts: AccountMeta[] = args.recipientTokenAccounts.map(recipientAddress => ({
        address: recipientAddress,
        role: AccountRole.WRITABLE,
    }));

    const getAccountMeta = getAccountMetaFactory(programAddress, 'programId');
    return Object.freeze({
        accounts: [
            getAccountMeta('channel', accounts.channel),
            getAccountMeta('payer', accounts.payer),
            getAccountMeta('channelTokenAccount', accounts.channelTokenAccount),
            getAccountMeta('payerTokenAccount', accounts.payerTokenAccount),
            getAccountMeta('payeeTokenAccount', accounts.payeeTokenAccount),
            getAccountMeta('treasuryTokenAccount', accounts.treasuryTokenAccount),
            getAccountMeta('mint', accounts.mint),
            getAccountMeta('tokenProgram', accounts.tokenProgram),
            getAccountMeta('eventAuthority', accounts.eventAuthority),
            getAccountMeta('selfProgram', accounts.selfProgram),
            ...remainingAccounts,
        ],
        data: getDistributeInstructionDataEncoder().encode(args as DistributeInstructionDataArgs),
        programAddress,
    } as DistributeInstruction<
        TProgramAddress,
        TAccountChannel,
        TAccountPayer,
        TAccountChannelTokenAccount,
        TAccountPayerTokenAccount,
        TAccountPayeeTokenAccount,
        TAccountTreasuryTokenAccount,
        TAccountMint,
        TAccountTokenProgram,
        TAccountEventAuthority,
        TAccountSelfProgram
    >);
}
