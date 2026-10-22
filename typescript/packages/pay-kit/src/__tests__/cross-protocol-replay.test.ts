/**
 * Regression: one on-chain payment authorizes one request across protocols.
 *
 * The x402 facilitator re-sends a transaction without preflight, so a
 * transaction already settled through MPP "settles" again under the same
 * signature. The x402 adapter must therefore claim the settled signature in
 * the consumed-signature ledger MPP charge claims in, held in the replay store
 * every adapter of a PayKit shares.
 */
import {
    address,
    type Blockhash,
    compileTransaction,
    createTransactionMessage,
    getBase64EncodedWireTransaction,
    pipe,
    setTransactionMessageFeePayer,
    setTransactionMessageLifetimeUsingBlockhash,
} from '@solana/kit';
import { claimConsumedSignature } from '@solana/mpp/server';
import { encodePaymentSignatureHeader } from '@x402/core/http';
import { describe, expect, it, vi } from 'vitest';

const settled = vi.hoisted(() => ({ signature: '' }));
vi.mock('@x402/core/facilitator', () => ({
    x402Facilitator: class {
        register() {
            return this;
        }
        verify() {
            return Promise.resolve({ isValid: true, payer: 'payer' });
        }
        settle() {
            return Promise.resolve({
                network: 'solana',
                payer: 'payer',
                success: true,
                transaction: settled.signature,
            });
        }
    },
}));

import { createX402ExactAdapter } from '../adapters/x402.js';
import { configure } from '../config.js';
import { InvalidProofError } from '../errors.js';
import { Gate } from '../gate.js';
import { usd } from '../price.js';
import { gateDefaults } from '../pricing.js';

/**
 * An unsigned, instruction-less version-0 wire transaction: the adapter
 * decodes the payload before it reaches the (mocked) facilitator.
 */
function wireTransaction(): string {
    const message = pipe(
        createTransactionMessage({ version: 0 }),
        m => setTransactionMessageFeePayer(address('11111111111111111111111111111111'), m),
        m =>
            setTransactionMessageLifetimeUsingBlockhash(
                { blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash, lastValidBlockHeight: 1n },
                m,
            ),
    );
    return getBase64EncodedWireTransaction(compileTransaction(message));
}

describe('x402 exact shares the MPP consumed-signature ledger', () => {
    it('refuses a signature already consumed by either protocol', async () => {
        const config = await configure({
            accept: ['mpp', 'x402'],
            mpp: { challengeBindingSecret: 'cross-protocol-replay-test-secret' },
            network: 'solana_localnet',
        });
        const adapter = createX402ExactAdapter(config);
        const gate = Gate.create({ amount: usd('0.10'), name: 'test' }, gateDefaults(config));
        const accepted = await adapter.acceptsEntry(gate, new Request('http://localhost/r'));
        const header = encodePaymentSignatureHeader({
            accepted,
            payload: { transaction: wireTransaction() },
            x402Version: 2,
        } as never);
        const paid = () =>
            adapter.verifyAndSettle(gate, new Request('http://localhost/r', { headers: { 'x-payment': header } }));

        // Settled through MPP first: the x402 presentation is refused.
        settled.signature = 'mpp-settled-signature';
        expect(await claimConsumedSignature(config.replayStore, settled.signature)).toBe(true);
        const error = await paid().catch((e: unknown) => e);
        expect(error).toBeInstanceOf(InvalidProofError);
        expect((error as InvalidProofError).code).toBe('signature_consumed');

        // A fresh payment settles once, and its claim blocks MPP from crediting it.
        settled.signature = 'x402-settled-signature';
        await expect(paid()).resolves.toMatchObject({ transaction: 'x402-settled-signature' });
        expect(await claimConsumedSignature(config.replayStore, settled.signature)).toBe(false);
        await expect(paid()).rejects.toMatchObject({ code: 'signature_consumed' });
    });
});
