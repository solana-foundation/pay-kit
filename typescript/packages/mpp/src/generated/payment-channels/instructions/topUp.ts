/**
 * Vendored from
 * https://github.com/solana-foundation/payment-channel/blob/main/clients/typescript/src/generated/instructions/topUp.ts
 *
 * Parsing helpers omitted; only the synchronous `getTopUpInstruction`
 * builder is needed by the server. Imports rewritten for Node16 module resolution.
 */

import {
    type AccountMeta,
    type AccountSignerMeta,
    type Address,
    combineCodec,
    type FixedSizeCodec,
    type FixedSizeDecoder,
    type FixedSizeEncoder,
    getStructDecoder,
    getStructEncoder,
    type Instruction,
    type InstructionWithAccounts,
    type InstructionWithData,
    type ReadonlyAccount,
    type ReadonlyUint8Array,
    type TransactionSigner,
    transformEncoder,
    type WritableAccount,
    type WritableSignerAccount,
} from '@solana/kit';
import { getAccountMetaFactory, type ResolvedInstructionAccount } from '@solana/program-client-core';

import { PAYMENT_CHANNELS_PROGRAM_ADDRESS } from '../programs/paymentChannels.js';
import { getU8Decoder, getU8Encoder } from '../safe-codecs.js';
import { getTopUpArgsDecoder, getTopUpArgsEncoder, type TopUpArgs, type TopUpArgsArgs } from '../types/topUpArgs.js';

export const TOP_UP_DISCRIMINATOR = 3;

export function getTopUpDiscriminatorBytes(): ReadonlyUint8Array {
    return getU8Encoder().encode(TOP_UP_DISCRIMINATOR);
}

export type TopUpInstruction<
    TProgram extends string = typeof PAYMENT_CHANNELS_PROGRAM_ADDRESS,
    TAccountPayer extends AccountMeta<string> | string = string,
    TAccountChannel extends AccountMeta<string> | string = string,
    TAccountPayerTokenAccount extends AccountMeta<string> | string = string,
    TAccountChannelTokenAccount extends AccountMeta<string> | string = string,
    TAccountMint extends AccountMeta<string> | string = string,
    TAccountTokenProgram extends AccountMeta<string> | string = string,
    TRemainingAccounts extends readonly AccountMeta<string>[] = [],
> = Instruction<TProgram> &
    InstructionWithAccounts<
        [
            TAccountPayer extends string
                ? AccountSignerMeta<TAccountPayer> & WritableSignerAccount<TAccountPayer>
                : TAccountPayer,
            TAccountChannel extends string ? WritableAccount<TAccountChannel> : TAccountChannel,
            TAccountPayerTokenAccount extends string
                ? WritableAccount<TAccountPayerTokenAccount>
                : TAccountPayerTokenAccount,
            TAccountChannelTokenAccount extends string
                ? WritableAccount<TAccountChannelTokenAccount>
                : TAccountChannelTokenAccount,
            TAccountMint extends string ? ReadonlyAccount<TAccountMint> : TAccountMint,
            TAccountTokenProgram extends string ? ReadonlyAccount<TAccountTokenProgram> : TAccountTokenProgram,
            ...TRemainingAccounts,
        ]
    > &
    InstructionWithData<ReadonlyUint8Array>;

export type TopUpInstructionData = { discriminator: number; topUpArgs: TopUpArgs };
export type TopUpInstructionDataArgs = { topUpArgs: TopUpArgsArgs };

export function getTopUpInstructionDataEncoder(): FixedSizeEncoder<TopUpInstructionDataArgs> {
    return transformEncoder(
        getStructEncoder([
            ['discriminator', getU8Encoder()],
            ['topUpArgs', getTopUpArgsEncoder()],
        ]),
        value => ({ ...value, discriminator: TOP_UP_DISCRIMINATOR }),
    );
}

export function getTopUpInstructionDataDecoder(): FixedSizeDecoder<TopUpInstructionData> {
    return getStructDecoder([
        ['discriminator', getU8Decoder()],
        ['topUpArgs', getTopUpArgsDecoder()],
    ]);
}

export function getTopUpInstructionDataCodec(): FixedSizeCodec<TopUpInstructionDataArgs, TopUpInstructionData> {
    return combineCodec(getTopUpInstructionDataEncoder(), getTopUpInstructionDataDecoder());
}

export type TopUpInput<
    TAccountPayer extends string = string,
    TAccountChannel extends string = string,
    TAccountPayerTokenAccount extends string = string,
    TAccountChannelTokenAccount extends string = string,
    TAccountMint extends string = string,
    TAccountTokenProgram extends string = string,
> = {
    channel: Address<TAccountChannel>;
    channelTokenAccount: Address<TAccountChannelTokenAccount>;
    mint: Address<TAccountMint>;
    payer: TransactionSigner<TAccountPayer>;
    payerTokenAccount: Address<TAccountPayerTokenAccount>;
    tokenProgram: Address<TAccountTokenProgram>;
    topUpArgs: TopUpInstructionDataArgs['topUpArgs'];
};

export function getTopUpInstruction<
    TAccountPayer extends string,
    TAccountChannel extends string,
    TAccountPayerTokenAccount extends string,
    TAccountChannelTokenAccount extends string,
    TAccountMint extends string,
    TAccountTokenProgram extends string,
    TProgramAddress extends Address = typeof PAYMENT_CHANNELS_PROGRAM_ADDRESS,
>(
    input: TopUpInput<
        TAccountPayer,
        TAccountChannel,
        TAccountPayerTokenAccount,
        TAccountChannelTokenAccount,
        TAccountMint,
        TAccountTokenProgram
    >,
    config?: { programAddress?: TProgramAddress },
): TopUpInstruction<
    TProgramAddress,
    TAccountPayer,
    TAccountChannel,
    TAccountPayerTokenAccount,
    TAccountChannelTokenAccount,
    TAccountMint,
    TAccountTokenProgram
> {
    const programAddress = config?.programAddress ?? PAYMENT_CHANNELS_PROGRAM_ADDRESS;

    const originalAccounts = {
        channel: { isWritable: true, value: input.channel ?? null },
        channelTokenAccount: { isWritable: true, value: input.channelTokenAccount ?? null },
        mint: { isWritable: false, value: input.mint ?? null },
        payer: { isWritable: true, value: input.payer ?? null },
        payerTokenAccount: { isWritable: true, value: input.payerTokenAccount ?? null },
        tokenProgram: { isWritable: false, value: input.tokenProgram ?? null },
    };
    const accounts = originalAccounts as Record<keyof typeof originalAccounts, ResolvedInstructionAccount>;

    const args = { ...input };

    const getAccountMeta = getAccountMetaFactory(programAddress, 'programId');
    return Object.freeze({
        accounts: [
            getAccountMeta('payer', accounts.payer),
            getAccountMeta('channel', accounts.channel),
            getAccountMeta('payerTokenAccount', accounts.payerTokenAccount),
            getAccountMeta('channelTokenAccount', accounts.channelTokenAccount),
            getAccountMeta('mint', accounts.mint),
            getAccountMeta('tokenProgram', accounts.tokenProgram),
        ],
        data: getTopUpInstructionDataEncoder().encode(args as TopUpInstructionDataArgs),
        programAddress,
    } as TopUpInstruction<
        TProgramAddress,
        TAccountPayer,
        TAccountChannel,
        TAccountPayerTokenAccount,
        TAccountChannelTokenAccount,
        TAccountMint,
        TAccountTokenProgram
    >);
}
