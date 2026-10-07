/**
 * Regression: a completed MPP charge authorizes exactly one handler execution.
 * Reusing its credential must fail for both identical and changed request bodies.
 *
 * Uses the real challenge, signed transaction, verifier, adapter, and fetch
 * wrapper. Only Solana RPC is stubbed; no network or funds are used. This is not
 * a substitute for the reporter's HTTP-server/offline-ledger reproduction.
 */
import { findAssociatedTokenPda, getTransferCheckedInstruction } from '@solana-program/token';
import {
    address,
    appendTransactionMessageInstructions,
    blockhash,
    createTransactionMessage,
    generateKeyPairSigner,
    getBase64EncodedWireTransaction,
    partiallySignTransactionMessageWithSigners,
    pipe,
    setTransactionMessageFeePayer,
    setTransactionMessageLifetimeUsingBlockhash,
    type Instruction,
} from '@solana/kit';
import { MEMO_PROGRAM, TOKEN_PROGRAM } from '@solana/mpp';
import { Challenge, Credential, Receipt, Store } from 'mppx';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { transactionSignatureFromBase64 } from '../../../mpp/src/utils/transactions.js';
import { createMppAdapter } from '../adapters/mpp.js';
import { configure } from '../config.js';
import { createPayKit } from '../paykit.js';
import { usd } from '../price.js';
import { Signer } from '../signer.js';

const RPC_URL = 'http://rpc.test';
const RESOURCE = 'http://merchant.test/jobs';
const BLOCKHASH = blockhash('EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N');

afterEach(() => vi.unstubAllGlobals());

describe.each([false, true])('MPP charge replay: fee sponsorship=%s', feePayer => {
    it.each([
        { externalId: false, sharedStore: false },
        { externalId: true, sharedStore: false },
        { externalId: false, sharedStore: true },
        { externalId: true, sharedStore: true },
    ])('executes once: %j', async ({ externalId, sharedStore }) => {
        const operator = await Signer.generate();
        const payer = await generateKeyPairSigner();
        const config = await configure({
            accept: ['mpp'],
            mpp: { challengeBindingSecret: 'charge-replay-test-secret-at-least-32-bytes' },
            network: 'devnet',
            operator: { feePayer, signer: operator },
            // Dynamic externalIds create separate adapter handlers. Both the
            // default and explicit stores must share consumption across them.
            ...(sharedStore ? { replayStore: Store.memory() } : {}),
            rpcUrl: RPC_URL,
        });
        const pay = await createPayKit({
            adapters: [createMppAdapter(config)],
            config,
            pricing: {
                job: async request => ({
                    amount: usd('0.10'),
                    ...(externalId ? { externalId: await request.clone().text() } : {}),
                }),
            },
        });
        const executed: string[] = [];
        const handler = pay.fetch('job', async request => {
            const job = await request.text();
            executed.push(job);
            return Response.json({ job });
        });
        const request = (job: string, credential?: string) =>
            new Request(RESOURCE, {
                body: job,
                headers: credential ? { authorization: credential } : {},
                method: 'POST',
            });

        const rpcMethods: string[] = [];
        let submittedSignature: string | undefined;
        let confirmedInstructions: unknown[] = [];
        vi.stubGlobal('fetch', async (input: RequestInfo | URL, init?: RequestInit) => {
            expect(String(input)).toBe(RPC_URL);
            const { id, method, params } = JSON.parse(String(init?.body)) as {
                id: number;
                method: string;
                params: string[];
            };
            rpcMethods.push(method);
            let result: unknown;
            switch (method) {
                case 'getLatestBlockhash':
                    result = { value: { blockhash: BLOCKHASH, lastValidBlockHeight: 100 } };
                    break;
                case 'simulateTransaction':
                    result = { value: { err: null, logs: [] } };
                    break;
                case 'sendTransaction':
                    submittedSignature = transactionSignatureFromBase64(params[0]);
                    result = submittedSignature;
                    break;
                case 'getSignatureStatuses':
                    result = { value: [{ confirmationStatus: 'confirmed', err: null }] };
                    break;
                case 'getTransaction':
                    expect(params[0]).toBe(submittedSignature);
                    result = {
                        meta: { err: null },
                        transaction: { message: { instructions: confirmedInstructions } },
                        version: 0,
                    };
                    break;
                default:
                    throw new Error(`Unexpected RPC method: ${method}`);
            }
            return Response.json({ id, jsonrpc: '2.0', result });
        });

        const unpaid = await handler(request('A'));
        expect(unpaid.status).toBe(402);
        expect(executed).toEqual([]);
        const challenge = Challenge.fromResponse(unpaid);
        const mint = address(String(challenge.request.currency));
        const recipient = address(config.operator.recipient);
        const [source] = await findAssociatedTokenPda({
            mint,
            owner: payer.address,
            tokenProgram: address(TOKEN_PROGRAM),
        });
        const [destination] = await findAssociatedTokenPda({
            mint,
            owner: recipient,
            tokenProgram: address(TOKEN_PROGRAM),
        });
        const amount = String(challenge.request.amount);
        const instructions: Instruction[] = [
            getTransferCheckedInstruction({
                amount: BigInt(amount),
                authority: payer,
                decimals: 6,
                destination,
                mint,
                source,
            }),
        ];
        confirmedInstructions = [
            {
                parsed: { info: { destination, mint, tokenAmount: { amount } }, type: 'transferChecked' },
                programId: TOKEN_PROGRAM,
            },
        ];
        if (externalId) {
            instructions.push({
                accounts: [],
                data: new TextEncoder().encode('A'),
                programAddress: address(MEMO_PROGRAM),
            });
            confirmedInstructions.push({ parsed: 'A', program: 'spl-memo', programId: MEMO_PROGRAM });
        }
        const message = pipe(
            createTransactionMessage({ version: 0 }),
            msg => setTransactionMessageFeePayer(feePayer ? operator.signer.address : payer.address, msg),
            msg =>
                setTransactionMessageLifetimeUsingBlockhash({ blockhash: BLOCKHASH, lastValidBlockHeight: 100n }, msg),
            msg => appendTransactionMessageInstructions(instructions, msg),
        );
        const transaction = getBase64EncodedWireTransaction(await partiallySignTransactionMessageWithSigners(message));
        const credential = Credential.serialize(
            Credential.from({ challenge, payload: { transaction, type: 'transaction' } }),
        );

        for (const [index, job] of ['A', 'B', 'C', 'A'].entries()) {
            const response = await handler(request(job, credential));
            if (index > 0) {
                expect(response.status).toBe(402);
                expect(response.headers.get('payment-receipt')).toBeNull();
                continue;
            }
            expect(response.status).toBe(200);
            expect(await response.json()).toEqual({ job });
            const receipt = Receipt.deserialize(response.headers.get('payment-receipt')!);
            expect(receipt.reference).toBe(submittedSignature);
            expect(receipt.externalId).toBe(externalId ? 'A' : undefined);
        }
        expect(rpcMethods.filter(method => method === 'sendTransaction')).toHaveLength(1);
        expect(rpcMethods.filter(method => method === 'simulateTransaction')).toHaveLength(1);
        expect(executed).toEqual(['A']);
    });
});
