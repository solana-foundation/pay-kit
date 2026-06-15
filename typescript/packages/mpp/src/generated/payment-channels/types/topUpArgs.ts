/**
 * Vendored from
 * https://github.com/solana-foundation/payment-channel/blob/main/clients/typescript/src/generated/types/topUpArgs.ts
 */

import {
    combineCodec,
    type FixedSizeCodec,
    type FixedSizeDecoder,
    type FixedSizeEncoder,
    getStructDecoder,
    getStructEncoder,
} from '@solana/kit';

import { getU64Decoder, getU64Encoder } from '../safe-codecs.js';

export type TopUpArgs = { amount: bigint };

export type TopUpArgsArgs = { amount: bigint };

export function getTopUpArgsEncoder(): FixedSizeEncoder<TopUpArgsArgs> {
    return getStructEncoder([['amount', getU64Encoder()]]);
}

export function getTopUpArgsDecoder(): FixedSizeDecoder<TopUpArgs> {
    return getStructDecoder([['amount', getU64Decoder()]]);
}

export function getTopUpArgsCodec(): FixedSizeCodec<TopUpArgsArgs, TopUpArgs> {
    return combineCodec(getTopUpArgsEncoder(), getTopUpArgsDecoder());
}
