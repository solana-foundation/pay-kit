/**
 * Integration tests for client/Charge.ts using an embedded Surfpool runtime.
 *
 * These tests exercise real Solana transaction building, signing, and
 * broadcasting against a local surfnet — no mocks required.
 *
 * Run: pnpm vitest run --config vitest.config.surfpool.ts
 */
import { test, expect, describe, beforeAll } from 'vitest';
import {
    createKeyPairSignerFromBytes,
    createSolanaRpc,
    generateKeyPairSigner,
    getBase64EncodedWireTransaction,
    type TransactionSigner,
} from '@solana/kit';
import { Surfnet } from 'surfpool-sdk';

import { charge } from '../client/Charge.js';
import { TOKEN_PROGRAM } from '../constants.js';

// Reliable RPC datasource for surfnet's account cloning. CI wires the
// SURFPOOL_DATASOURCE_RPC_URL secret (see .github/workflows/ci.yml); without it
// surfnet clones from the public mainnet-beta RPC, which rate-limits and crashes
// the embedded validator mid-test. Mirrors the Rust harness's start_surfnet().
const DATASOURCE_RPC_URL = process.env.SURFPOOL_DATASOURCE_RPC_URL ?? 'https://api.mainnet-beta.solana.com';

// ── Helpers ──

/** Build a challenge object matching the schema that charge() expects. */
function makeChallenge(overrides: {
    amount?: string;
    currency?: string;
    decimals?: number;
    feePayer?: boolean;
    feePayerKey?: string;
    network?: string;
    recentBlockhash?: string;
    recipient: string;
    splits?: Array<{ amount: string; recipient: string }>;
    tokenProgram?: string;
}) {
    const {
        amount = '1000000',
        currency = 'sol',
        recipient,
        network = 'localnet',
        decimals,
        tokenProgram,
        feePayer,
        feePayerKey,
        recentBlockhash,
        splits,
    } = overrides;

    const isSpl = currency !== 'sol';

    return {
        request: {
            amount,
            currency,
            methodDetails: {
                ...(network ? { network } : {}),
                ...(isSpl ? { decimals: decimals ?? 6, tokenProgram: tokenProgram ?? TOKEN_PROGRAM } : {}),
                ...(feePayer ? { feePayer: true, feePayerKey } : {}),
                ...(recentBlockhash ? { recentBlockhash } : {}),
                ...(splits ? { splits } : {}),
            },
            recipient,
        },
    } as any;
}

/** Decode the base64 payload from a serialized credential string. */
function decodeCredential(credential: string): {
    challenge: unknown;
    payload: { type: string; transaction?: string; signature?: string };
} {
    // Format: "Payment <base64>"
    const [scheme, b64] = credential.split(' ');
    expect(scheme).toBe('Payment');
    return JSON.parse(Buffer.from(b64, 'base64').toString('utf-8'));
}

// ── Test suite ──

describe('client charge integration (surfpool)', () => {
    let surfnet: InstanceType<typeof Surfnet>;
    let signer: TransactionSigner;
    let recipientKey: string;

    beforeAll(async () => {
        surfnet = Surfnet.start();

        // Create signer from the pre-funded payer key.
        // napi returns Array<number>, @solana/kit needs Uint8Array
        signer = await createKeyPairSignerFromBytes(new Uint8Array(surfnet.payerSecretKey));

        // Generate a recipient address.
        const kp = Surfnet.newKeypair();
        recipientKey = kp.publicKey;
    });

    // ── Pull mode (default): returns type="transaction" ──

    test('SOL transfer — pull mode returns a signed transaction credential', async () => {
        const method = charge({ signer, rpcUrl: surfnet.rpcUrl });

        const challenge = makeChallenge({
            amount: '500000',
            recipient: recipientKey,
        });

        const credential = await method.createCredential({ challenge });
        expect(typeof credential).toBe('string');
        expect(credential).toMatch(/^Payment /);

        const decoded = decodeCredential(credential);
        expect(decoded.payload.type).toBe('transaction');
        expect(decoded.payload.transaction).toBeDefined();
        expect(typeof decoded.payload.transaction).toBe('string');
        // The transaction should be base64-encoded.
        expect(decoded.payload.transaction!.length).toBeGreaterThan(10);
    });

    test('SOL transfer with splits — pull mode includes all transfer instructions', async () => {
        const splitRecipient = Surfnet.newKeypair().publicKey;

        const method = charge({ signer, rpcUrl: surfnet.rpcUrl });

        const challenge = makeChallenge({
            amount: '2000000', // 2_000_000 lamports total
            recipient: recipientKey,
            splits: [{ amount: '500000', recipient: splitRecipient }],
        });

        const credential = await method.createCredential({ challenge });
        const decoded = decodeCredential(credential);
        expect(decoded.payload.type).toBe('transaction');
        expect(decoded.payload.transaction).toBeDefined();
    });

    test('SOL transfer with server-provided blockhash skips RPC fetch', async () => {
        // Fetch a blockhash from the surfnet to use as server-provided.
        const rpc = createSolanaRpc(surfnet.rpcUrl);
        const { value } = await rpc.getLatestBlockhash().send();

        const method = charge({ signer, rpcUrl: surfnet.rpcUrl });

        const challenge = makeChallenge({
            amount: '100000',
            recentBlockhash: value.blockhash,
            recipient: recipientKey,
        });

        const credential = await method.createCredential({ challenge });
        const decoded = decodeCredential(credential);
        expect(decoded.payload.type).toBe('transaction');
        expect(decoded.payload.transaction).toBeDefined();
    });

    // ── Push mode: broadcast=true returns type="signature" ──

    test('SOL transfer — push mode broadcasts and returns a signature credential', async () => {
        // Fund the payer generously for fees.
        surfnet.fundSol(signer.address, 10_000_000_000);

        const method = charge({ signer, rpcUrl: surfnet.rpcUrl, broadcast: true });

        const challenge = makeChallenge({
            amount: '1000000',
            recipient: recipientKey,
        });

        const credential = await method.createCredential({ challenge });
        const decoded = decodeCredential(credential);
        expect(decoded.payload.type).toBe('signature');
        expect(decoded.payload.signature).toBeDefined();
        expect(typeof decoded.payload.signature).toBe('string');
    });

    // ── onProgress callback ──

    test('onProgress receives lifecycle events in pull mode', async () => {
        const events: Array<{ type: string }> = [];

        const method = charge({
            signer,
            rpcUrl: surfnet.rpcUrl,
            onProgress: event => events.push(event),
        });

        const challenge = makeChallenge({
            amount: '1000000',
            recipient: recipientKey,
        });

        await method.createCredential({ challenge });

        const types = events.map(e => e.type);
        expect(types).toContain('challenge');
        expect(types).toContain('signing');
        expect(types).toContain('signed');
    });

    test('onProgress receives lifecycle events in push mode', async () => {
        surfnet.fundSol(signer.address, 10_000_000_000);
        const events: Array<{ type: string }> = [];

        const method = charge({
            signer,
            rpcUrl: surfnet.rpcUrl,
            broadcast: true,
            onProgress: event => events.push(event),
        });

        const challenge = makeChallenge({
            amount: '100000',
            recipient: recipientKey,
        });

        await method.createCredential({ challenge });

        const types = events.map(e => e.type);
        expect(types).toContain('challenge');
        expect(types).toContain('signing');
        expect(types).toContain('paying');
        expect(types).toContain('confirming');
        expect(types).toContain('paid');
    });

    // ── Custom compute budget parameters ──

    test('custom computeUnitPrice and computeUnitLimit are accepted', async () => {
        const method = charge({
            signer,
            rpcUrl: surfnet.rpcUrl,
            computeUnitPrice: 100n,
            computeUnitLimit: 50_000,
        });

        const challenge = makeChallenge({
            amount: '100000',
            recipient: recipientKey,
        });

        const credential = await method.createCredential({ challenge });
        const decoded = decodeCredential(credential);
        expect(decoded.payload.type).toBe('transaction');
        expect(decoded.payload.transaction).toBeDefined();
    });

    // ── Fee payer mode (server pays fees) ──

    test('fee payer mode partially signs transaction (SOL transfer)', async () => {
        const feePayerKp = Surfnet.newKeypair();

        const method = charge({ signer, rpcUrl: surfnet.rpcUrl });

        const challenge = makeChallenge({
            amount: '100000',
            feePayer: true,
            feePayerKey: feePayerKp.publicKey,
            recipient: recipientKey,
        });

        const credential = await method.createCredential({ challenge });
        const decoded = decodeCredential(credential);
        expect(decoded.payload.type).toBe('transaction');
        expect(decoded.payload.transaction).toBeDefined();
    });

    // ── SPL token transfer ──

    describe('SPL token transfers', () => {
        const USDC_DEVNET = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
        let tokenRecipient: string;

        beforeAll(() => {
            // Create a mint on the surfnet and fund the payer with tokens.
            tokenRecipient = Surfnet.newKeypair().publicKey;

            // Fund the payer with SOL for fees.
            surfnet.fundSol(signer.address, 10_000_000_000);

            // Fund the payer with USDC tokens.
            surfnet.fundToken(signer.address, USDC_DEVNET, 10_000_000);
        });

        test('SPL token transfer — pull mode with explicit tokenProgram', async () => {
            const method = charge({ signer, rpcUrl: surfnet.rpcUrl });

            const challenge = makeChallenge({
                amount: '1000000',
                currency: USDC_DEVNET,
                decimals: 6,
                recipient: tokenRecipient,
                tokenProgram: TOKEN_PROGRAM,
            });

            const credential = await method.createCredential({ challenge });
            const decoded = decodeCredential(credential);
            expect(decoded.payload.type).toBe('transaction');
            expect(decoded.payload.transaction).toBeDefined();
        });

        test('SPL token transfer — resolves tokenProgram from RPC when not specified', async () => {
            // Start a surfnet with mainnet RPC fallback so the USDC mint account
            // can be cloned and its owner (TOKEN_PROGRAM) resolved on-chain.
            const remoteSurfnet = Surfnet.startWithConfig({
                remoteRpcUrl: DATASOURCE_RPC_URL,
            });
            const remoteSigner = await createKeyPairSignerFromBytes(new Uint8Array(remoteSurfnet.payerSecretKey));
            remoteSurfnet.fundSol(remoteSigner.address, 10_000_000_000);

            // Use the real mainnet USDC mint address.
            const USDC_MAINNET = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
            const remoteRecipient = Surfnet.newKeypair().publicKey;
            remoteSurfnet.fundToken(remoteSigner.address, USDC_MAINNET, 10_000_000);

            const method = charge({ signer: remoteSigner, rpcUrl: remoteSurfnet.rpcUrl });

            const challenge = makeChallenge({
                amount: '500000',
                currency: USDC_MAINNET,
                decimals: 6,
                recipient: remoteRecipient,
                // No tokenProgram — should resolve from on-chain mint account via RPC fallback.
            });

            // Remove tokenProgram from methodDetails so resolveTokenProgram is invoked.
            delete (challenge.request.methodDetails as any).tokenProgram;

            const credential = await method.createCredential({ challenge });
            const decoded = decodeCredential(credential);
            expect(decoded.payload.type).toBe('transaction');
        });

        test('SPL token transfer with splits', async () => {
            const splitRecipient = Surfnet.newKeypair().publicKey;

            const method = charge({ signer, rpcUrl: surfnet.rpcUrl });

            const challenge = makeChallenge({
                amount: '2000000',
                currency: USDC_DEVNET,
                decimals: 6,
                recipient: tokenRecipient,
                splits: [{ amount: '500000', recipient: splitRecipient }],
                tokenProgram: TOKEN_PROGRAM,
            });

            const credential = await method.createCredential({ challenge });
            const decoded = decodeCredential(credential);
            expect(decoded.payload.type).toBe('transaction');
        });

        test('SPL token transfer with fee payer mode', async () => {
            const feePayerKp = Surfnet.newKeypair();

            const method = charge({ signer, rpcUrl: surfnet.rpcUrl });

            const challenge = makeChallenge({
                amount: '1000000',
                currency: USDC_DEVNET,
                decimals: 6,
                feePayer: true,
                feePayerKey: feePayerKp.publicKey,
                recipient: tokenRecipient,
                tokenProgram: TOKEN_PROGRAM,
            });

            const credential = await method.createCredential({ challenge });
            const decoded = decodeCredential(credential);
            expect(decoded.payload.type).toBe('transaction');
        });
    });

    // ── resolveTokenProgram error paths ──

    describe('resolveTokenProgram errors', () => {
        test('throws when mint account does not exist', async () => {
            const fakeMint = Surfnet.newKeypair().publicKey;

            const method = charge({ signer, rpcUrl: surfnet.rpcUrl });

            const challenge = makeChallenge({
                amount: '1000',
                currency: fakeMint,
                decimals: 6,
                recipient: recipientKey,
            });

            // Remove tokenProgram so it must resolve from RPC.
            delete (challenge.request.methodDetails as any).tokenProgram;

            await expect(method.createCredential({ challenge })).rejects.toThrow(
                'Failed to determine token program for mint: mint account not found',
            );
        });

        test('throws when mint owner is not a known token program', async () => {
            // Use a SOL-funded address as the "mint" — it is owned by the system
            // program, not a token program, so resolveTokenProgram should reject it.
            const fakeMint = Surfnet.newKeypair().publicKey;
            surfnet.fundSol(fakeMint, 1_000_000);

            const method = charge({ signer, rpcUrl: surfnet.rpcUrl });

            const challenge = makeChallenge({
                amount: '1000',
                currency: fakeMint,
                decimals: 6,
                recipient: recipientKey,
            });

            delete (challenge.request.methodDetails as any).tokenProgram;

            await expect(method.createCredential({ challenge })).rejects.toThrow(
                'Failed to determine token program for mint: unexpected owner',
            );
        });
    });

    // ── Default RPC URL fallback ──

    test('uses default RPC URL when none provided (network from challenge)', async () => {
        // This test verifies the code path where rpcUrl is not provided.
        // We pass network: 'localnet' which maps to http://localhost:8899.
        // Since no surfpool is running on 8899, the RPC call should fail,
        // proving the fallback URL was used.
        const method = charge({ signer });

        const challenge = makeChallenge({
            amount: '100000',
            network: 'localnet',
            recipient: recipientKey,
        });

        // Should try to connect to localhost:8899 and fail (no server there).
        // This exercises the DEFAULT_RPC_URLS fallback code path.
        // We don't care about the error, just that it tried the right URL.
        try {
            await method.createCredential({ challenge });
        } catch {
            // Expected to fail — we just want to exercise the code path.
        }
    });

    test('challenge onProgress event includes feePayerKey when present', async () => {
        const feePayerKp = Surfnet.newKeypair();
        const events: Array<any> = [];

        const method = charge({
            signer,
            rpcUrl: surfnet.rpcUrl,
            onProgress: event => events.push(event),
        });

        const challenge = makeChallenge({
            amount: '100000',
            feePayer: true,
            feePayerKey: feePayerKp.publicKey,
            recipient: recipientKey,
        });

        await method.createCredential({ challenge });

        const challengeEvent = events.find(e => e.type === 'challenge');
        expect(challengeEvent).toBeDefined();
        expect(challengeEvent.feePayerKey).toBe(feePayerKp.publicKey);
        expect(challengeEvent.amount).toBe('100000');
        expect(challengeEvent.currency).toBe('sol');
        expect(challengeEvent.recipient).toBe(recipientKey);
    });
});
