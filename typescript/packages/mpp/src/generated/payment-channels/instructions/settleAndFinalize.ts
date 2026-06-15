/**
 * Vendored from
 * https://github.com/solana-foundation/payment-channel/blob/main/clients/typescript/src/generated/instructions/settleAndFinalize.ts
 *
 * Parsing helpers omitted; only the synchronous `getSettleAndFinalizeInstruction`
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
    type ReadonlySignerAccount,
    type ReadonlyUint8Array,
    type TransactionSigner,
    transformEncoder,
    type WritableAccount,
} from '@solana/kit';
import { getAccountMetaFactory, type ResolvedInstructionAccount } from '@solana/program-client-core';

import { PAYMENT_CHANNELS_PROGRAM_ADDRESS } from '../programs/paymentChannels.js';
import { getU8Decoder, getU8Encoder } from '../safe-codecs.js';
import {
    getSettleAndFinalizeArgsDecoder,
    getSettleAndFinalizeArgsEncoder,
    type SettleAndFinalizeArgs,
    type SettleAndFinalizeArgsArgs,
} from '../types/settleAndFinalizeArgs.js';

export const SETTLE_AND_FINALIZE_DISCRIMINATOR = 4;

export function getSettleAndFinalizeDiscriminatorBytes(): ReadonlyUint8Array {
    return getU8Encoder().encode(SETTLE_AND_FINALIZE_DISCRIMINATOR);
}

export type SettleAndFinalizeInstruction<
    TProgram extends string = typeof PAYMENT_CHANNELS_PROGRAM_ADDRESS,
    TAccountMerchant extends AccountMeta<string> | string = string,
    TAccountChannel extends AccountMeta<string> | string = string,
    TAccountInstructionsSysvar extends AccountMeta<string> | string = string,
    TRemainingAccounts extends readonly AccountMeta<string>[] = [],
> = Instruction<TProgram> &
    InstructionWithAccounts<
        [
            TAccountMerchant extends string
                ? AccountSignerMeta<TAccountMerchant> & ReadonlySignerAccount<TAccountMerchant>
                : TAccountMerchant,
            TAccountChannel extends string ? WritableAccount<TAccountChannel> : TAccountChannel,
            TAccountInstructionsSysvar extends string
                ? ReadonlyAccount<TAccountInstructionsSysvar>
                : TAccountInstructionsSysvar,
            ...TRemainingAccounts,
        ]
    > &
    InstructionWithData<ReadonlyUint8Array>;

export type SettleAndFinalizeInstructionData = {
    discriminator: number;
    settleAndFinalizeArgs: SettleAndFinalizeArgs;
};

export type SettleAndFinalizeInstructionDataArgs = {
    settleAndFinalizeArgs: SettleAndFinalizeArgsArgs;
};

export function getSettleAndFinalizeInstructionDataEncoder(): FixedSizeEncoder<SettleAndFinalizeInstructionDataArgs> {
    return transformEncoder(
        getStructEncoder([
            ['discriminator', getU8Encoder()],
            ['settleAndFinalizeArgs', getSettleAndFinalizeArgsEncoder()],
        ]),
        value => ({ ...value, discriminator: SETTLE_AND_FINALIZE_DISCRIMINATOR }),
    );
}

export function getSettleAndFinalizeInstructionDataDecoder(): FixedSizeDecoder<SettleAndFinalizeInstructionData> {
    return getStructDecoder([
        ['discriminator', getU8Decoder()],
        ['settleAndFinalizeArgs', getSettleAndFinalizeArgsDecoder()],
    ]);
}

export function getSettleAndFinalizeInstructionDataCodec(): FixedSizeCodec<
    SettleAndFinalizeInstructionDataArgs,
    SettleAndFinalizeInstructionData
> {
    return combineCodec(getSettleAndFinalizeInstructionDataEncoder(), getSettleAndFinalizeInstructionDataDecoder());
}

export type SettleAndFinalizeInput<
    TAccountMerchant extends string = string,
    TAccountChannel extends string = string,
    TAccountInstructionsSysvar extends string = string,
> = {
    channel: Address<TAccountChannel>;
    instructionsSysvar: Address<TAccountInstructionsSysvar>;
    merchant: TransactionSigner<TAccountMerchant>;
    settleAndFinalizeArgs: SettleAndFinalizeInstructionDataArgs['settleAndFinalizeArgs'];
};

export function getSettleAndFinalizeInstruction<
    TAccountMerchant extends string,
    TAccountChannel extends string,
    TAccountInstructionsSysvar extends string,
    TProgramAddress extends Address = typeof PAYMENT_CHANNELS_PROGRAM_ADDRESS,
>(
    input: SettleAndFinalizeInput<TAccountMerchant, TAccountChannel, TAccountInstructionsSysvar>,
    config?: { programAddress?: TProgramAddress },
): SettleAndFinalizeInstruction<TProgramAddress, TAccountMerchant, TAccountChannel, TAccountInstructionsSysvar> {
    const programAddress = config?.programAddress ?? PAYMENT_CHANNELS_PROGRAM_ADDRESS;

    const originalAccounts = {
        channel: { isWritable: true, value: input.channel ?? null },
        instructionsSysvar: { isWritable: false, value: input.instructionsSysvar ?? null },
        merchant: { isWritable: false, value: input.merchant ?? null },
    };
    const accounts = originalAccounts as Record<keyof typeof originalAccounts, ResolvedInstructionAccount>;

    const args = { ...input };

    const getAccountMeta = getAccountMetaFactory(programAddress, 'programId');
    return Object.freeze({
        accounts: [
            getAccountMeta('merchant', accounts.merchant),
            getAccountMeta('channel', accounts.channel),
            getAccountMeta('instructionsSysvar', accounts.instructionsSysvar),
        ],
        data: getSettleAndFinalizeInstructionDataEncoder().encode(args as SettleAndFinalizeInstructionDataArgs),
        programAddress,
    } as SettleAndFinalizeInstruction<TProgramAddress, TAccountMerchant, TAccountChannel, TAccountInstructionsSysvar>);
}
