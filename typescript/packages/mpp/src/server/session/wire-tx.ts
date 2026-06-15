import {
    appendTransactionMessageInstructions,
    type Blockhash,
    createTransactionMessage,
    getBase64EncodedWireTransaction,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signTransactionMessageWithSigners,
    type TransactionSigner,
} from '@solana/kit';

import type { ServerInstruction } from './on-chain.js';

interface RpcWithBlockhash {
    getLatestBlockhash: (config?: { commitment?: 'confirmed' | 'finalized' | 'processed' }) => {
        send: () => Promise<{
            value: { blockhash: Blockhash; lastValidBlockHeight: bigint };
        }>;
    };
}

/**
 * Compile a list of instructions into a signed v0 transaction's base64 wire
 * bytes. Fetches a recent blockhash from `rpc`, sets `signer` as the fee
 * payer, signs, and encodes.
 *
 * This is the canonical `buildAndSignWireTransaction` callback for
 * `submitSettleAndDistribute` — keeping the kit/RPC plumbing in one place so
 * `closeAndSettleChannel` doesn't have to know about transaction messages.
 */
export async function buildAndSignWireTransaction(
    rpc: RpcWithBlockhash,
    signer: TransactionSigner,
    instructions: readonly ServerInstruction[],
): Promise<string> {
    const { value: latestBlockhash } = await rpc.getLatestBlockhash({ commitment: 'confirmed' }).send();
    const message = pipe(
        createTransactionMessage({ version: 0 }),
        m => setTransactionMessageFeePayerSigner(signer, m),
        m => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, m),
        m => appendTransactionMessageInstructions(instructions, m),
    );
    const signed = await signTransactionMessageWithSigners(message);
    return getBase64EncodedWireTransaction(signed);
}
