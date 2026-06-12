/**
 * Vendored from
 * https://github.com/solana-foundation/payment-channel/blob/main/clients/typescript/src/generated/types/settleAndFinalizeArgs.ts
 */

import {
    combineCodec,
    type FixedSizeCodec,
    type FixedSizeDecoder,
    type FixedSizeEncoder,
    getStructDecoder,
    getStructEncoder,
} from '@solana/kit';

import { getU8Decoder, getU8Encoder } from '../safe-codecs.js';
import { getVoucherArgsDecoder, getVoucherArgsEncoder, type VoucherArgs, type VoucherArgsArgs } from './voucherArgs.js';

export type SettleAndFinalizeArgs = {
    hasVoucher: number;
    voucher: VoucherArgs;
};

export type SettleAndFinalizeArgsArgs = {
    hasVoucher: number;
    voucher: VoucherArgsArgs;
};

export function getSettleAndFinalizeArgsEncoder(): FixedSizeEncoder<SettleAndFinalizeArgsArgs> {
    return getStructEncoder([
        ['voucher', getVoucherArgsEncoder()],
        ['hasVoucher', getU8Encoder()],
    ]);
}

export function getSettleAndFinalizeArgsDecoder(): FixedSizeDecoder<SettleAndFinalizeArgs> {
    return getStructDecoder([
        ['voucher', getVoucherArgsDecoder()],
        ['hasVoucher', getU8Decoder()],
    ]);
}

export function getSettleAndFinalizeArgsCodec(): FixedSizeCodec<SettleAndFinalizeArgsArgs, SettleAndFinalizeArgs> {
    return combineCodec(getSettleAndFinalizeArgsEncoder(), getSettleAndFinalizeArgsDecoder());
}
