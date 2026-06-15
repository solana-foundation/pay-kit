import {
    address,
    type Blockhash,
    createKeyPairSignerFromPrivateKeyBytes,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getTransactionDecoder,
} from '@solana/kit';
import { findAssociatedTokenPda } from '@solana-program/token';
import { expect, test } from 'vitest';

import { buildOpenPaymentChannelTransaction } from '../client/PaymentChannels.js';
import type { SessionRequest } from '../client/Session.js';
import { PYUSD, TOKEN_2022_PROGRAM, TOKEN_PROGRAM, USDC } from '../constants.js';

/**
 * Golden buffer captured from the hand-encoded `getOpenInstructionData`
 * helper that previously lived in `client/PaymentChannels.ts` (pre-Codama
 * refactor). Byte-equivalence guarantees the Codama TS client encodes the
 * `open` instruction the same way for fixed inputs.
 *
 * Inputs (all bigints/decimals are exact):
 *   salt         = 42
 *   deposit      = 1_000_000
 *   gracePeriod  = 900
 *   recipients   = [{ recipient: HQyfh1JGDB47A6Az4MD9KgF9LqcL3ESCkN8AT9Y8atGD, bps: 250 }]
 */
const GOLDEN_DATA_HEX =
    '012a0000000000000040420f00000000008403000001000000f3df6c4f444efb2d860ce6dae0b568b6dadee3c402fc33edab10836490385896fa00';

const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash;
function makeSeed(byte: number): Uint8Array {
    const seed = new Uint8Array(32);
    seed.fill(byte);
    return seed;
}
const PAYER_SEED = makeSeed(0x01);
const OPERATOR_SEED = makeSeed(0x02);
const PAYEE_SEED = makeSeed(0x03);
const AUTHORIZED_SEED = makeSeed(0x04);

type TestCompiledMessage = {
    instructions: readonly { data: Uint8Array }[];
    staticAccounts?: readonly string[];
};

test('open instruction bytes match the pre-Codama golden buffer', async () => {
    const [payer, operator, payee, authorizedSigner] = await Promise.all([
        createKeyPairSignerFromPrivateKeyBytes(PAYER_SEED),
        createKeyPairSignerFromPrivateKeyBytes(OPERATOR_SEED),
        createKeyPairSignerFromPrivateKeyBytes(PAYEE_SEED),
        createKeyPairSignerFromPrivateKeyBytes(AUTHORIZED_SEED),
    ]);

    const request: SessionRequest = {
        cap: '1000000',
        currency: USDC.mainnet,
        decimals: 6,
        modes: ['pull'],
        network: 'localnet',
        operator: operator.address,
        pullVoucherStrategy: 'clientVoucher',
        recentBlockhash: BLOCKHASH,
        recipient: payee.address,
        splits: [{ bps: 250, recipient: address('HQyfh1JGDB47A6Az4MD9KgF9LqcL3ESCkN8AT9Y8atGD') }],
    };

    const open = await buildOpenPaymentChannelTransaction({
        authorizedSigner: authorizedSigner.address,
        deposit: 1_000_000n,
        gracePeriod: 900,
        request,
        salt: 42n,
        signer: payer,
    });

    const decoded = getTransactionDecoder().decode(getBase64Codec().encode(open.transaction));
    const message = getCompiledTransactionMessageDecoder().decode(
        decoded.messageBytes,
    ) as unknown as TestCompiledMessage;
    expect(message.instructions).toHaveLength(1);

    const actualHex = Buffer.from(message.instructions[0]!.data).toString('hex');
    expect(actualHex).toBe(GOLDEN_DATA_HEX);
});

test('a PYUSD challenge derives Token-2022 accounts by default', async () => {
    const [payer, operator, payee, authorizedSigner] = await Promise.all([
        createKeyPairSignerFromPrivateKeyBytes(PAYER_SEED),
        createKeyPairSignerFromPrivateKeyBytes(OPERATOR_SEED),
        createKeyPairSignerFromPrivateKeyBytes(PAYEE_SEED),
        createKeyPairSignerFromPrivateKeyBytes(AUTHORIZED_SEED),
    ]);

    const request: SessionRequest = {
        cap: '1000000',
        currency: 'PYUSD',
        decimals: 6,
        modes: ['pull'],
        network: 'mainnet',
        operator: operator.address,
        pullVoucherStrategy: 'clientVoucher',
        recentBlockhash: BLOCKHASH,
        recipient: payee.address,
    };

    const open = await buildOpenPaymentChannelTransaction({
        authorizedSigner: authorizedSigner.address,
        deposit: 1_000_000n,
        gracePeriod: 900,
        request,
        salt: 42n,
        signer: payer,
    });

    expect(open.mint).toBe(PYUSD.mainnet);

    const decoded = getTransactionDecoder().decode(getBase64Codec().encode(open.transaction));
    const message = getCompiledTransactionMessageDecoder().decode(
        decoded.messageBytes,
    ) as unknown as TestCompiledMessage;
    const staticAccounts = message.staticAccounts ?? [];
    expect(staticAccounts).toContain(TOKEN_2022_PROGRAM);
    expect(staticAccounts).not.toContain(TOKEN_PROGRAM);

    const [payerTokenAccount] = await findAssociatedTokenPda({
        mint: address(PYUSD.mainnet!),
        owner: payer.address,
        tokenProgram: address(TOKEN_2022_PROGRAM),
    });
    expect(staticAccounts).toContain(payerTokenAccount);
});
