/**
 * Vendored from
 * https://github.com/solana-foundation/payment-channel/blob/main/clients/typescript/src/generated/instructions/open.ts
 *
 * Parsing / async helpers from the upstream file are intentionally
 * omitted; this package only needs the synchronous `getOpenInstruction`
 * builder. Imports are rewritten for Node16 module resolution.
 */

import {
    type AccountMeta,
    type AccountSignerMeta,
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
    type TransactionSigner,
    transformEncoder,
    type WritableAccount,
    type WritableSignerAccount,
} from '@solana/kit';
import { getAccountMetaFactory, type ResolvedInstructionAccount } from '@solana/program-client-core';

import { PAYMENT_CHANNELS_PROGRAM_ADDRESS } from '../programs/paymentChannels.js';
import { getU8Decoder, getU8Encoder } from '../safe-codecs.js';
import { getOpenArgsDecoder, getOpenArgsEncoder, type OpenArgs, type OpenArgsArgs } from '../types/openArgs.js';

export const OPEN_DISCRIMINATOR = 1;

export function getOpenDiscriminatorBytes(): ReadonlyUint8Array {
    return getU8Encoder().encode(OPEN_DISCRIMINATOR);
}

export type OpenInstruction<
    TProgram extends string = typeof PAYMENT_CHANNELS_PROGRAM_ADDRESS,
    TAccountPayer extends AccountMeta<string> | string = string,
    TAccountPayee extends AccountMeta<string> | string = string,
    TAccountMint extends AccountMeta<string> | string = string,
    TAccountAuthorizedSigner extends AccountMeta<string> | string = string,
    TAccountChannel extends AccountMeta<string> | string = string,
    TAccountPayerTokenAccount extends AccountMeta<string> | string = string,
    TAccountChannelTokenAccount extends AccountMeta<string> | string = string,
    TAccountTokenProgram extends AccountMeta<string> | string = string,
    TAccountSystemProgram extends AccountMeta<string> | string = '11111111111111111111111111111111',
    TAccountRent extends AccountMeta<string> | string = string,
    TAccountAssociatedTokenProgram extends AccountMeta<string> | string = string,
    TAccountEventAuthority extends AccountMeta<string> | string = string,
    TAccountSelfProgram extends AccountMeta<string> | string = 'GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc',
    TRemainingAccounts extends readonly AccountMeta<string>[] = [],
> = Instruction<TProgram> &
    InstructionWithAccounts<
        [
            TAccountPayer extends string
                ? AccountSignerMeta<TAccountPayer> & WritableSignerAccount<TAccountPayer>
                : TAccountPayer,
            TAccountPayee extends string ? ReadonlyAccount<TAccountPayee> : TAccountPayee,
            TAccountMint extends string ? ReadonlyAccount<TAccountMint> : TAccountMint,
            TAccountAuthorizedSigner extends string
                ? ReadonlyAccount<TAccountAuthorizedSigner>
                : TAccountAuthorizedSigner,
            TAccountChannel extends string ? WritableAccount<TAccountChannel> : TAccountChannel,
            TAccountPayerTokenAccount extends string
                ? WritableAccount<TAccountPayerTokenAccount>
                : TAccountPayerTokenAccount,
            TAccountChannelTokenAccount extends string
                ? WritableAccount<TAccountChannelTokenAccount>
                : TAccountChannelTokenAccount,
            TAccountTokenProgram extends string ? ReadonlyAccount<TAccountTokenProgram> : TAccountTokenProgram,
            TAccountSystemProgram extends string ? ReadonlyAccount<TAccountSystemProgram> : TAccountSystemProgram,
            TAccountRent extends string ? ReadonlyAccount<TAccountRent> : TAccountRent,
            TAccountAssociatedTokenProgram extends string
                ? ReadonlyAccount<TAccountAssociatedTokenProgram>
                : TAccountAssociatedTokenProgram,
            TAccountEventAuthority extends string ? ReadonlyAccount<TAccountEventAuthority> : TAccountEventAuthority,
            TAccountSelfProgram extends string ? ReadonlyAccount<TAccountSelfProgram> : TAccountSelfProgram,
            ...TRemainingAccounts,
        ]
    > &
    InstructionWithData<ReadonlyUint8Array>;

export type OpenInstructionData = { discriminator: number; openArgs: OpenArgs };

export type OpenInstructionDataArgs = { openArgs: OpenArgsArgs };

export function getOpenInstructionDataEncoder(): Encoder<OpenInstructionDataArgs> {
    return transformEncoder(
        getStructEncoder([
            ['discriminator', getU8Encoder()],
            ['openArgs', getOpenArgsEncoder()],
        ]),
        value => ({ ...value, discriminator: OPEN_DISCRIMINATOR }),
    );
}

export function getOpenInstructionDataDecoder(): Decoder<OpenInstructionData> {
    return getStructDecoder([
        ['discriminator', getU8Decoder()],
        ['openArgs', getOpenArgsDecoder()],
    ]);
}

export function getOpenInstructionDataCodec(): Codec<OpenInstructionDataArgs, OpenInstructionData> {
    return combineCodec(getOpenInstructionDataEncoder(), getOpenInstructionDataDecoder());
}

export type OpenInput<
    TAccountPayer extends string = string,
    TAccountPayee extends string = string,
    TAccountMint extends string = string,
    TAccountAuthorizedSigner extends string = string,
    TAccountChannel extends string = string,
    TAccountPayerTokenAccount extends string = string,
    TAccountChannelTokenAccount extends string = string,
    TAccountTokenProgram extends string = string,
    TAccountSystemProgram extends string = string,
    TAccountRent extends string = string,
    TAccountAssociatedTokenProgram extends string = string,
    TAccountEventAuthority extends string = string,
    TAccountSelfProgram extends string = string,
> = {
    associatedTokenProgram: Address<TAccountAssociatedTokenProgram>;
    authorizedSigner: Address<TAccountAuthorizedSigner>;
    channel: Address<TAccountChannel>;
    channelTokenAccount: Address<TAccountChannelTokenAccount>;
    eventAuthority: Address<TAccountEventAuthority>;
    mint: Address<TAccountMint>;
    openArgs: OpenInstructionDataArgs['openArgs'];
    payee: Address<TAccountPayee>;
    payer: TransactionSigner<TAccountPayer>;
    payerTokenAccount: Address<TAccountPayerTokenAccount>;
    rent: Address<TAccountRent>;
    selfProgram?: Address<TAccountSelfProgram>;
    systemProgram?: Address<TAccountSystemProgram>;
    tokenProgram: Address<TAccountTokenProgram>;
};

export function getOpenInstruction<
    TAccountPayer extends string,
    TAccountPayee extends string,
    TAccountMint extends string,
    TAccountAuthorizedSigner extends string,
    TAccountChannel extends string,
    TAccountPayerTokenAccount extends string,
    TAccountChannelTokenAccount extends string,
    TAccountTokenProgram extends string,
    TAccountSystemProgram extends string,
    TAccountRent extends string,
    TAccountAssociatedTokenProgram extends string,
    TAccountEventAuthority extends string,
    TAccountSelfProgram extends string,
    TProgramAddress extends Address = typeof PAYMENT_CHANNELS_PROGRAM_ADDRESS,
>(
    input: OpenInput<
        TAccountPayer,
        TAccountPayee,
        TAccountMint,
        TAccountAuthorizedSigner,
        TAccountChannel,
        TAccountPayerTokenAccount,
        TAccountChannelTokenAccount,
        TAccountTokenProgram,
        TAccountSystemProgram,
        TAccountRent,
        TAccountAssociatedTokenProgram,
        TAccountEventAuthority,
        TAccountSelfProgram
    >,
    config?: { programAddress?: TProgramAddress },
): OpenInstruction<
    TProgramAddress,
    TAccountPayer,
    TAccountPayee,
    TAccountMint,
    TAccountAuthorizedSigner,
    TAccountChannel,
    TAccountPayerTokenAccount,
    TAccountChannelTokenAccount,
    TAccountTokenProgram,
    TAccountSystemProgram,
    TAccountRent,
    TAccountAssociatedTokenProgram,
    TAccountEventAuthority,
    TAccountSelfProgram
> {
    const programAddress = config?.programAddress ?? PAYMENT_CHANNELS_PROGRAM_ADDRESS;

    const originalAccounts = {
        authorizedSigner: { isWritable: false, value: input.authorizedSigner ?? null },
        associatedTokenProgram: { isWritable: false, value: input.associatedTokenProgram ?? null },
        channel: { isWritable: true, value: input.channel ?? null },
        channelTokenAccount: { isWritable: true, value: input.channelTokenAccount ?? null },
        eventAuthority: { isWritable: false, value: input.eventAuthority ?? null },
        mint: { isWritable: false, value: input.mint ?? null },
        payee: { isWritable: false, value: input.payee ?? null },
        payer: { isWritable: true, value: input.payer ?? null },
        payerTokenAccount: { isWritable: true, value: input.payerTokenAccount ?? null },
        rent: { isWritable: false, value: input.rent ?? null },
        selfProgram: { isWritable: false, value: input.selfProgram ?? null },
        systemProgram: { isWritable: false, value: input.systemProgram ?? null },
        tokenProgram: { isWritable: false, value: input.tokenProgram ?? null },
    };
    const accounts = originalAccounts as Record<keyof typeof originalAccounts, ResolvedInstructionAccount>;

    const args = { ...input };

    if (!accounts.systemProgram.value) {
        accounts.systemProgram.value =
            '11111111111111111111111111111111' as Address<'11111111111111111111111111111111'>;
    }
    if (!accounts.selfProgram.value) {
        accounts.selfProgram.value =
            'GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc' as Address<'GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc'>;
    }

    const getAccountMeta = getAccountMetaFactory(programAddress, 'programId');
    return Object.freeze({
        accounts: [
            getAccountMeta('payer', accounts.payer),
            getAccountMeta('payee', accounts.payee),
            getAccountMeta('mint', accounts.mint),
            getAccountMeta('authorizedSigner', accounts.authorizedSigner),
            getAccountMeta('channel', accounts.channel),
            getAccountMeta('payerTokenAccount', accounts.payerTokenAccount),
            getAccountMeta('channelTokenAccount', accounts.channelTokenAccount),
            getAccountMeta('tokenProgram', accounts.tokenProgram),
            getAccountMeta('systemProgram', accounts.systemProgram),
            getAccountMeta('rent', accounts.rent),
            getAccountMeta('associatedTokenProgram', accounts.associatedTokenProgram),
            getAccountMeta('eventAuthority', accounts.eventAuthority),
            getAccountMeta('selfProgram', accounts.selfProgram),
        ],
        data: getOpenInstructionDataEncoder().encode(args as OpenInstructionDataArgs),
        programAddress,
    } as OpenInstruction<
        TProgramAddress,
        TAccountPayer,
        TAccountPayee,
        TAccountMint,
        TAccountAuthorizedSigner,
        TAccountChannel,
        TAccountPayerTokenAccount,
        TAccountChannelTokenAccount,
        TAccountTokenProgram,
        TAccountSystemProgram,
        TAccountRent,
        TAccountAssociatedTokenProgram,
        TAccountEventAuthority,
        TAccountSelfProgram
    >);
}
