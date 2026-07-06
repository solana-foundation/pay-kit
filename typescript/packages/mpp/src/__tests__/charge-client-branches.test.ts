// Branch-coverage tests for client/Charge.ts.
//
// Targets the createCredential-side branches (broadcast + fee-sponsorship
// mutual exclusivity, expectedNetwork match, malformed expires, native
// pull-mode success with a server blockhash) plus buildChargeTransaction
// branches the validation suite does not reach: an explicit rpcUrl, a known
// Token-2022 stablecoin mint (the stablecoin-symbol guard's non-undefined
// arm), and server-fee-payer ATA creation for a flagged split.
// All paths use a server-provided recentBlockhash so no live RPC is needed.
// No production code is touched.

import { afterEach, beforeEach, describe, expect, test } from 'vitest';
import {
    generateKeyPairSigner,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getTransactionDecoder,
    type Blockhash,
} from '@solana/kit';

import { buildChargeTransaction, charge } from '../client/Charge.js';
import { ASSOCIATED_TOKEN_PROGRAM, PYUSD, TOKEN_2022_PROGRAM, TOKEN_PROGRAM } from '../constants.js';

let originalFetch: typeof globalThis.fetch;
beforeEach(() => {
    originalFetch = globalThis.fetch;
});
afterEach(() => {
    globalThis.fetch = originalFetch;
});

function rpcSuccess(result: unknown) {
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
        headers: { 'Content-Type': 'application/json' },
    });
}

const RECIPIENT = '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ';
const PLATFORM = '3pF8Kg2aHbNvJkLMwEqR7YtDxZ5sGhJn4UV6mWcXrT9A';
const USDC_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const FEE_PAYER_KEY = '11111111111111111111111111111112';
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash;

async function newSigner() {
    return await generateKeyPairSigner();
}

function programAddressesOf(base64Tx: string): string[] {
    const decoded = getTransactionDecoder().decode(getBase64Codec().encode(base64Tx));
    const message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes) as unknown as {
        instructions: readonly { programAddressIndex: number }[];
        staticAccounts: readonly string[];
    };
    return message.instructions.map(ix => String(message.staticAccounts[ix.programAddressIndex]));
}

function challengeFor(request: Record<string, unknown>, expires?: string) {
    return { expires, id: 'test-id', method: 'solana', request } as never;
}

// ── charge().createCredential branches ──

describe('charge() createCredential branches', () => {
    test('rejects broadcast=true combined with fee sponsorship through createCredential', async () => {
        const signer = await newSigner();
        const method = charge({ signer, broadcast: true });
        const challenge = challengeFor({
            amount: '1000',
            currency: 'sol',
            recipient: RECIPIENT,
            methodDetails: {
                feePayer: true,
                feePayerKey: FEE_PAYER_KEY,
                network: 'devnet',
                recentBlockhash: BLOCKHASH,
            },
        });
        await expect(method.createCredential({ challenge })).rejects.toThrow(/cannot be used with fee sponsorship/);
    });

    test('emits a pull-mode transaction credential for a native SOL challenge', async () => {
        const signer = await newSigner();
        const method = charge({ signer });
        const challenge = challengeFor({
            amount: '1000000',
            currency: 'sol',
            recipient: RECIPIENT,
            methodDetails: { network: 'devnet', recentBlockhash: BLOCKHASH },
        });
        const credential = await method.createCredential({ challenge });
        expect(typeof credential).toBe('string');
        expect(credential.length).toBeGreaterThan(0);
    });

    test('accepts a challenge whose network matches expectedNetwork', async () => {
        const signer = await newSigner();
        const method = charge({ signer, expectedNetwork: 'devnet' });
        const challenge = challengeFor({
            amount: '1000',
            currency: 'sol',
            recipient: RECIPIENT,
            methodDetails: { network: 'devnet', recentBlockhash: BLOCKHASH },
        });
        await expect(method.createCredential({ challenge })).resolves.toEqual(expect.any(String));
    });

    test('defaults a missing network to mainnet when checking expectedNetwork', async () => {
        const signer = await newSigner();
        const method = charge({ signer, expectedNetwork: 'mainnet' });
        // No network in methodDetails → defaults to 'mainnet', which matches.
        const challenge = challengeFor({
            amount: '1000',
            currency: 'sol',
            recipient: RECIPIENT,
            methodDetails: { recentBlockhash: BLOCKHASH },
        });
        await expect(method.createCredential({ challenge })).resolves.toEqual(expect.any(String));
    });

    test('refuses a challenge with a malformed expires timestamp', async () => {
        const signer = await newSigner();
        const method = charge({ signer });
        const challenge = challengeFor(
            {
                amount: '1000',
                currency: 'sol',
                recipient: RECIPIENT,
                methodDetails: { network: 'devnet', recentBlockhash: BLOCKHASH },
            },
            'not-a-real-timestamp',
        );
        await expect(method.createCredential({ challenge })).rejects.toThrow(/malformed challenge expires timestamp/);
    });

    test('accepts a challenge whose expires timestamp is in the future', async () => {
        // A valid, future expires reaches the `expiresAt < Date.now()` check and
        // takes its not-expired arm.
        const signer = await newSigner();
        const method = charge({ signer });
        const challenge = challengeFor(
            {
                amount: '1000',
                currency: 'sol',
                recipient: RECIPIENT,
                methodDetails: { network: 'devnet', recentBlockhash: BLOCKHASH },
            },
            new Date(Date.now() + 60_000).toISOString(),
        );
        await expect(method.createCredential({ challenge })).resolves.toEqual(expect.any(String));
    });
});

// ── buildChargeTransaction branches ──

describe('buildChargeTransaction branches', () => {
    test('honours an explicit rpcUrl (server blockhash path, no RPC call)', async () => {
        const signer = await newSigner();
        const tx = await buildChargeTransaction({
            rpcUrl: 'https://explicit-rpc.example',
            signer,
            request: {
                amount: '1000000',
                currency: 'sol',
                recipient: RECIPIENT,
                methodDetails: { network: 'devnet', recentBlockhash: BLOCKHASH },
            },
        });
        expect(tx.length).toBeGreaterThan(0);
    });

    test('signs a known Token-2022 stablecoin mint without opt-in', async () => {
        // PYUSD mainnet is a known Token-2022 stablecoin, so
        // stablecoinSymbolForCurrency(mint) !== undefined and the unknown-mint
        // guard's non-undefined arm is taken (transaction proceeds).
        const signer = await newSigner();
        const tx = await buildChargeTransaction({
            signer,
            request: {
                amount: '1000000',
                currency: PYUSD.mainnet!,
                recipient: RECIPIENT,
                methodDetails: {
                    decimals: 6,
                    network: 'mainnet',
                    recentBlockhash: BLOCKHASH,
                    tokenProgram: TOKEN_2022_PROGRAM,
                },
            },
        });
        expect(tx.length).toBeGreaterThan(0);
    });

    test('server fee-payer creates a flagged split ATA with the server as payer', async () => {
        const signer = await newSigner();
        const tx = await buildChargeTransaction({
            signer,
            request: {
                amount: '1000000',
                currency: USDC_MINT,
                recipient: RECIPIENT,
                methodDetails: {
                    decimals: 6,
                    feePayer: true,
                    feePayerKey: FEE_PAYER_KEY,
                    network: 'devnet',
                    recentBlockhash: BLOCKHASH,
                    splits: [{ amount: '50000', ataCreationRequired: true, recipient: PLATFORM }],
                    tokenProgram: TOKEN_PROGRAM,
                },
            },
        });
        // The idempotent ATA-create instruction is emitted for the flagged split.
        expect(programAddressesOf(tx)).toContain(ASSOCIATED_TOKEN_PROGRAM);
    });

    test('resolves the token program from the mint account when tokenProgram is omitted', async () => {
        // No tokenProgram in methodDetails → resolveTokenProgram queries the
        // mint account via getAccountInfo; the stub reports a TOKEN_PROGRAM owner.
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'getAccountInfo') {
                return rpcSuccess({ context: { slot: 1 }, value: { owner: TOKEN_PROGRAM } });
            }
            return rpcSuccess({});
        };
        const signer = await newSigner();
        const tx = await buildChargeTransaction({
            rpcUrl: 'https://mock-rpc',
            signer,
            request: {
                amount: '1000000',
                currency: USDC_MINT,
                recipient: RECIPIENT,
                methodDetails: { decimals: 6, network: 'devnet', recentBlockhash: BLOCKHASH },
            },
        });
        expect(tx.length).toBeGreaterThan(0);
    });

    test('rejects when the mint account owner is not a known token program', async () => {
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'getAccountInfo') {
                return rpcSuccess({ context: { slot: 1 }, value: { owner: '11111111111111111111111111111111' } });
            }
            return rpcSuccess({});
        };
        const signer = await newSigner();
        await expect(
            buildChargeTransaction({
                rpcUrl: 'https://mock-rpc',
                signer,
                request: {
                    amount: '1000000',
                    currency: USDC_MINT,
                    recipient: RECIPIENT,
                    methodDetails: { decimals: 6, network: 'devnet', recentBlockhash: BLOCKHASH },
                },
            }),
        ).rejects.toThrow(/unexpected owner/);
    });

    test('rejects when the mint account does not exist', async () => {
        globalThis.fetch = async (_input, init) => {
            const body = JSON.parse(init?.body as string) as { method?: string };
            if (body.method === 'getAccountInfo') {
                return rpcSuccess({ context: { slot: 1 }, value: null });
            }
            return rpcSuccess({});
        };
        const signer = await newSigner();
        await expect(
            buildChargeTransaction({
                rpcUrl: 'https://mock-rpc',
                signer,
                request: {
                    amount: '1000000',
                    currency: USDC_MINT,
                    recipient: RECIPIENT,
                    methodDetails: { decimals: 6, network: 'devnet', recentBlockhash: BLOCKHASH },
                },
            }),
        ).rejects.toThrow(/mint account not found/);
    });
});
