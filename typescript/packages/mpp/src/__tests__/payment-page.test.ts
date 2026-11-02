/**
 * The bundled payment page (`html/src`, shipped as `PAYMENT_UI_JS`) must
 * build transactions this SDK's charge verifier admits. MPP refuses legacy
 * messages, so the page compiles version 0 and refuses challenges that do not
 * accept it.
 */
import { describe, expect, test } from 'vitest';
import { type Blockhash } from '@solana/kit';

import {
    assertPageCanBuildVersion,
    bs58Decode,
    bs58Encode,
    compileMessage,
    computeBudgetInstructions,
    systemTransfer,
    unsignedTransaction,
} from '../../../../../html/src/transaction.js';
import { type ChallengeRequest, verifyChargeTransaction } from '../server/Charge.js';
import { type TransactionVersion } from '../utils/transaction-versions.js';

const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const FEE_PAYER = 'FPkeyQ8m5jHq2mBb1xC3yP2T3f9aG2pZ6vK3sX4uN7bR';
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash;
const AMOUNT = 1_000_000n;

function solRequest(methodDetails: Partial<ChallengeRequest['methodDetails']> = {}): ChallengeRequest {
    return {
        amount: AMOUNT.toString(),
        currency: 'sol',
        methodDetails: { network: 'devnet', recentBlockhash: BLOCKHASH, ...methodDetails },
        recipient: RECIPIENT,
    };
}

/** Builds and signs a SOL charge exactly as the page's test-mode flow does. */
async function buildPagePayment(options: { feePayer?: string } = {}) {
    const keyPair = (await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify'])) as CryptoKeyPair;
    const payer = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
    const feePayer = options.feePayer ? bs58Decode(options.feePayer) : payer;
    const instructions = [...computeBudgetInstructions(), systemTransfer(payer, bs58Decode(RECIPIENT), AMOUNT)];
    const message = compileMessage(instructions, feePayer, payer, bs58Decode(BLOCKHASH));
    const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', keyPair.privateKey, message));
    const tx = unsignedTransaction(message, options.feePayer ? 2 : 1);
    tx.set(signature, options.feePayer ? 1 + 64 : 1);
    return { message, payer: bs58Encode(payer), tx: Buffer.from(tx).toString('base64') };
}

describe('payment page transactions', () => {
    test('compiles a version-0 message: 0x80 prefix and an empty lookup-table section', async () => {
        const { message } = await buildPagePayment();
        expect(message[0]).toBe(0x80);
        expect(message[message.length - 1]).toBe(0);
    });

    test.each<[TransactionVersion[] | undefined]>([[undefined], [[0]], [[0, 1]]])(
        'verifyChargeTransaction admits the page build when transactionVersions is %j',
        async transactionVersions => {
            const { tx } = await buildPagePayment();
            const request = solRequest(transactionVersions ? { transactionVersions } : {});
            assertPageCanBuildVersion(request.methodDetails.transactionVersions);
            await expect(verifyChargeTransaction(tx, request)).resolves.toBeUndefined();
        },
    );

    test('verifyChargeTransaction admits a sponsored page build with the fee-payer slot empty', async () => {
        const { tx } = await buildPagePayment({ feePayer: FEE_PAYER });
        await expect(
            verifyChargeTransaction(tx, solRequest({ feePayer: true, feePayerKey: FEE_PAYER })),
        ).resolves.toBeUndefined();
    });

    test('refuses a version-1-only challenge before building', async () => {
        expect(() => assertPageCanBuildVersion([1])).toThrow(
            'This payment page builds version-0 transactions, but the server accepts versions [1]',
        );
        expect(() => assertPageCanBuildVersion([])).toThrow('accepts versions []');
        const { tx } = await buildPagePayment();
        await expect(verifyChargeTransaction(tx, solRequest({ transactionVersions: [1] }))).rejects.toThrow(
            'transaction version 0 is not accepted',
        );
    });
});
