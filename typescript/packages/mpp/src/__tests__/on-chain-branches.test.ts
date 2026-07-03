// Branch-coverage tests for server/session/on-chain.ts.
//
// Targets the uncovered error paths, validation rejections, optional-field
// defaulting, and the fetch/decode/bind mismatch branches that the existing
// happy-path suites (session-on-chain, session-server-on-chain) do not reach.
// No production code is touched; every branch is exercised through the public
// builder/verifier surface or by tampering a compiled open transaction so a
// single account or byte diverges.

import {
    createKeyPairSignerFromPrivateKeyBytes,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getCompiledTransactionMessageEncoder,
    getSignatureFromTransaction,
    getTransactionDecoder,
    getTransactionEncoder,
    type KeyPairSigner,
    type Signature,
} from '@solana/kit';
import { describe, expect, test } from 'vitest';

import { buildOpenPaymentChannelTransaction } from '../client/PaymentChannels.js';
import type { SessionRequest, SignedVoucher } from '../client/Session.js';
import { TOKEN_PROGRAM, USDC } from '../constants.js';
import {
    buildEd25519VerifyInstruction,
    buildDistributeInstruction,
    buildSettleAndFinalizeInstructions,
    encodeVoucherMessageBytes,
    PAYMENT_CHANNELS_PROGRAM_ID,
    submitInitMultiDelegateTxIfMissing,
    submitOpenTx,
    submitSettleAndDistribute,
    verifyOpenTx,
    waitForSignatureConfirmation,
} from '../server/session/on-chain.js';

// ── fixtures ─────────────────────────────────────────────────────────────

function makeSeed(byte: number): Uint8Array {
    const seed = new Uint8Array(32);
    seed.fill(byte);
    return seed;
}

async function loadFixedSigners() {
    return await Promise.all([
        createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x21)),
        createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x22)),
        createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x23)),
    ]);
}

async function buildClientOpen(payer: KeyPairSigner, payee: KeyPairSigner, authorizedSigner: KeyPairSigner) {
    const request: SessionRequest = {
        cap: '1000000',
        currency: USDC.mainnet!,
        decimals: 6,
        network: 'localnet',
        operator: payer.address,
        recentBlockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as never,
        recipient: payee.address,
    };
    const open = await buildOpenPaymentChannelTransaction({
        authorizedSigner: authorizedSigner.address,
        deposit: 1_000_000n,
        gracePeriod: 900,
        programAddress: PAYMENT_CHANNELS_PROGRAM_ID,
        request,
        salt: 7n,
        signer: payer,
    });
    return { open };
}

function expectedFor(payer: KeyPairSigner, payee: KeyPairSigner, authorizedSigner: KeyPairSigner) {
    return {
        authorizedSigner: authorizedSigner.address,
        currency: USDC.mainnet!,
        maxCap: 5_000_000n,
        network: 'localnet',
        operator: payer.address,
        programId: PAYMENT_CHANNELS_PROGRAM_ID as string,
        recipient: payee.address,
    };
}

const PLACEHOLDER_SIG = '1'.repeat(88);

/** Extract the first (fee-payer) signature of a base64 wire transaction. */
function txSignature(transactionBase64: string): string {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    return getSignatureFromTransaction(tx);
}

/**
 * Decode a base64 open tx, mutate its compiled message via `mutate`, and
 * re-encode it. Lets a test swap a single static account or splice the open
 * instruction data to exercise one mismatch branch at a time.
 */
function remapTransaction(
    transactionBase64: string,
    mutate: (message: Record<string, unknown>) => Record<string, unknown>,
): string {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    const message = getCompiledTransactionMessageDecoder().decode(tx.messageBytes) as Record<string, unknown>;
    const mutated = mutate({ ...message });
    const messageBytes = new Uint8Array(getCompiledTransactionMessageEncoder().encode(mutated as never));
    const rebuilt = getTransactionEncoder().encode({ ...tx, messageBytes } as never);
    return getBase64Codec().decode(new Uint8Array(rebuilt));
}

/** Locate the payment-channels open instruction inside a compiled message. */
function findOpenIx(message: Record<string, unknown>): {
    accountIndices: number[];
    data: Uint8Array;
    index: number;
} {
    const staticAccounts = message.staticAccounts as string[];
    const instructions = message.instructions as {
        accountIndices?: number[];
        data?: Uint8Array;
        programAddressIndex: number;
    }[];
    for (let i = 0; i < instructions.length; i++) {
        const ix = instructions[i]!;
        if (staticAccounts[ix.programAddressIndex] !== (PAYMENT_CHANNELS_PROGRAM_ID as string)) continue;
        if (!ix.data || ix.data.length < 1 || ix.data[0] !== 1) continue;
        return { accountIndices: ix.accountIndices ?? [], data: ix.data, index: i };
    }
    throw new Error('open ix not found in fixture');
}

/** Swap the static account referenced by open-instruction slot `slot`. */
function swapOpenAccount(transactionBase64: string, slot: number, newAddress: string): string {
    return remapTransaction(transactionBase64, message => {
        const open = findOpenIx(message);
        const staticAccounts = [...(message.staticAccounts as string[])];
        const targetStaticIndex = open.accountIndices[slot]!;
        staticAccounts[targetStaticIndex] = newAddress;
        return { ...message, staticAccounts };
    });
}

// ── pure builder validation branches ───────────────────────────────────────

describe('on-chain builder validation branches', () => {
    test('encodeVoucherMessageBytes rejects a channelId that is not 32 bytes', () => {
        expect(() => encodeVoucherMessageBytes({ channelId: 'abc', cumulativeAmount: 0n, expiresAt: 0n })).toThrow(
            /must decode to 32 bytes/,
        );
    });

    test('buildEd25519VerifyInstruction rejects an over-long voucher message', () => {
        expect(() =>
            buildEd25519VerifyInstruction({
                message: new Uint8Array(0x10000),
                signature: new Uint8Array(64),
                signer: new Uint8Array(32),
            }),
        ).toThrow(/voucher message too long/);
    });

    test('buildSettleAndFinalizeInstructions rejects an authorizedSigner that is not 32 bytes', async () => {
        const merchant = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x24));
        const signed: SignedVoucher = {
            data: { channelId: '11111111111111111111111111111111', cumulativeAmount: '5', expiresAt: 0 },
            signature: '1'.repeat(88),
        };
        expect(() =>
            buildSettleAndFinalizeInstructions({
                channelId: '11111111111111111111111111111111',
                merchantSigner: merchant,
                voucher: { authorizedSigner: 'abc', signed },
            }),
        ).toThrow(/authorizedSigner must decode to 32 bytes/);
    });

    test('buildSettleAndFinalizeInstructions rejects a voucher signature that is not 64 bytes', async () => {
        const merchant = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x25));
        const authorizedSigner = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x26));
        // A base58 that decodes to 32 bytes (a valid address), not 64.
        const signed: SignedVoucher = {
            data: { channelId: '11111111111111111111111111111111', cumulativeAmount: '5', expiresAt: 0 },
            signature: authorizedSigner.address,
        };
        expect(() =>
            buildSettleAndFinalizeInstructions({
                channelId: '11111111111111111111111111111111',
                merchantSigner: merchant,
                voucher: { authorizedSigner: authorizedSigner.address, signed },
            }),
        ).toThrow(/voucher signature must decode to 64 bytes/);
    });

    test('buildDistributeInstruction rejects a missing rentPayer', async () => {
        const [payer, , payee] = await loadFixedSigners();
        await expect(
            buildDistributeInstruction({
                channelState: {
                    channelId: '11111111111111111111111111111111',
                    payee: payee.address,
                    payer: payer.address,
                },
                mint: USDC.mainnet!,
                rentPayer: '',
                splits: [],
                tokenProgram: TOKEN_PROGRAM,
            }),
        ).rejects.toThrow(/rentPayer is required/);
    });
});

// ── verifyOpenTx: guard + mismatch branches ─────────────────────────────────

describe('verifyOpenTx guard branches', () => {
    test('rejects when the payload carries no transaction', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        await expect(
            verifyOpenTx({
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                } as never,
            }),
        ).rejects.toThrow(/transaction is required/);
    });

    test('rejects a non-placeholder signature when the tx carries no fee-payer signature', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        // Zero out the fee-payer signature so the binding check sees an all-zero sig.
        const zeroed = getTransactionDecoder().decode(getBase64Codec().encode(open.transaction));
        const sigs = { ...(zeroed.signatures as Record<string, Uint8Array | null>) };
        const feePayer = Object.keys(sigs)[0]!;
        sigs[feePayer] = new Uint8Array(64);
        const rebuilt = getTransactionEncoder().encode({ ...zeroed, signatures: sigs } as never);
        const unsignedTx = getBase64Codec().decode(new Uint8Array(rebuilt));

        await expect(
            verifyOpenTx({
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    // Any non-placeholder base58 signature triggers the binding path.
                    signature: '2'.repeat(88),
                    transaction: unsignedTx,
                },
            }),
        ).rejects.toThrow(/carries no fee-payer signature/);
    });

    test('rejects when no payment-channels open instruction is present', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        // Flip the open instruction's discriminator byte so the loop skips it.
        const noOpen = remapTransaction(open.transaction, message => {
            const instructions = (message.instructions as { data?: Uint8Array }[]).map(ix => {
                if (ix.data && ix.data.length > 0 && ix.data[0] === 1) {
                    const data = new Uint8Array(ix.data);
                    data[0] = 9;
                    return { ...ix, data };
                }
                return ix;
            });
            return { ...message, instructions };
        });
        await expect(
            verifyOpenTx({
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: noOpen,
                },
            }),
        ).rejects.toThrow(/no payment-channels open instruction/);
    });

    test('rejects when the mint does not match the expected mint', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        // Slot 3 is the mint; swap it for a different valid address.
        const tampered = swapOpenAccount(open.transaction, 3, '9xAXssX9j7vuK99c7cFwqbixzL3bFrzPy9PUhCtDPAYJ');
        await expect(
            verifyOpenTx({
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: tampered,
                },
            }),
        ).rejects.toThrow(/mint/);
    });

    test('rejects when the authorizedSigner account does not match', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const other = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x27));
        // Slot 4 is authorizedSigner.
        const tampered = swapOpenAccount(open.transaction, 4, other.address);
        await expect(
            verifyOpenTx({
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: tampered,
                },
            }),
        ).rejects.toThrow(/authorizedSigner/);
    });

    test('rejects when expected.operator is empty', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        await expect(
            verifyOpenTx({
                expected: { ...expectedFor(payer, payee, authorizedSigner), operator: '' },
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: open.transaction,
                },
            }),
        ).rejects.toThrow(/operator/);
    });

    test('rejects when the rentPayer account does not match the operator', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const other = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x28));
        // Slot 1 is rentPayer; leave expected.operator as the payer.
        const tampered = swapOpenAccount(open.transaction, 1, other.address);
        await expect(
            verifyOpenTx({
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: tampered,
                },
            }),
        ).rejects.toThrow(/rentPayer/);
    });

    test('rejects when deposit is zero', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        // Zero the deposit u64 (bytes 9..17 of the open ix data).
        const zeroDeposit = remapTransaction(open.transaction, message => {
            const instructions = (message.instructions as { data?: Uint8Array }[]).map(ix => {
                if (ix.data && ix.data.length > 0 && ix.data[0] === 1) {
                    const data = new Uint8Array(ix.data);
                    for (let i = 9; i < 17; i++) data[i] = 0;
                    return { ...ix, data };
                }
                return ix;
            });
            return { ...message, instructions };
        });
        await expect(
            verifyOpenTx({
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: zeroDeposit,
                },
            }),
        ).rejects.toThrow(/deposit must be greater than zero/);
    });

    test('rejects when the channel PDA does not match the derived value', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const other = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x29));
        // Slot 5 is the channel account; swapping it breaks the PDA derivation.
        const tampered = swapOpenAccount(open.transaction, 5, other.address);
        await expect(
            verifyOpenTx({
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: tampered,
                },
            }),
        ).rejects.toThrow(/channel PDA/);
    });

    test('rejects when openPayload.channelId disagrees with the tx channel', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        await expect(
            verifyOpenTx({
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    channelId: '11111111111111111111111111111111',
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: open.transaction,
                },
            }),
        ).rejects.toThrow(/openPayload.channelId/);
    });

    test('rejects when the RPC reports the signature is not found', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const realSig = txSignature(open.transaction);
        const rpc = {
            getSignatureStatuses: () => ({
                send: async () => ({ value: [null] }),
            }),
        };
        await expect(
            verifyOpenTx({
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: realSig,
                    transaction: open.transaction,
                },
                rpc,
            }),
        ).rejects.toThrow(/not found on-chain/);
    });

    test('resolves the mint from currency/network when no explicit mint is given', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        // Omit mint on `expected` so the mainnet USDC mint is resolved via currency.
        const result = await verifyOpenTx({
            expected: {
                authorizedSigner: authorizedSigner.address,
                currency: USDC.mainnet!,
                maxCap: 5_000_000n,
                network: 'mainnet',
                operator: payer.address,
                programId: PAYMENT_CHANNELS_PROGRAM_ID as string,
                recipient: payee.address,
            },
            openPayload: {
                authorizedSigner: authorizedSigner.address,
                mode: 'push',
                signature: PLACEHOLDER_SIG,
                transaction: open.transaction,
            },
        });
        expect(result.channelId).toBe(open.channelId);
    });
});

// ── submitOpenTx / submitSettleAndDistribute / waitForSignatureConfirmation ──

describe('submit + confirmation branches', () => {
    test('submitOpenTx co-signs when the payerSigner slot is present in the tx', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const sends: string[] = [];
        const rpc = {
            getSignatureStatuses: () => ({
                send: async () => ({ value: [{ confirmationStatus: 'confirmed', err: null }] }),
            }),
            sendTransaction: (wire: string) => ({
                send: async () => {
                    sends.push(wire);
                    return 'OpenSig111111111111111111111111111111111111111111' as Signature;
                },
            }),
        };
        // The payer is the fee payer / signer already present in the tx, so the
        // co-sign branch (decoded.signatures[address] !== undefined) is taken.
        const result = await submitOpenTx({
            confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
            expected: expectedFor(payer, payee, authorizedSigner),
            openPayload: {
                authorizedSigner: authorizedSigner.address,
                mode: 'push',
                signature: PLACEHOLDER_SIG,
                transaction: open.transaction,
            },
            payerSigner: payer as never,
            rpc,
        });
        expect(result.signature).toBeDefined();
        expect(sends).toHaveLength(1);
    });

    test('submitSettleAndDistribute derives the token program from currency when omitted', async () => {
        const [payer, payee, operator] = await loadFixedSigners();
        const built: unknown[] = [];
        const result = await submitSettleAndDistribute({
            buildAndSignWireTransaction: async instructions => {
                built.push(instructions);
                return 'WIRE-BASE64';
            },
            channelId: '11111111111111111111111111111111',
            currency: USDC.mainnet!,
            mint: USDC.mainnet!,
            network: 'mainnet',
            payee: payee.address,
            payer: payer.address,
            rentPayer: operator.address,
            rpc: {
                sendTransaction: () => ({
                    send: async () => 'SettleSig1111111111111111111111111111111111111111' as Signature,
                }),
            },
            signer: operator,
            splits: [],
        });
        expect(result.signature).toBeDefined();
        expect(result.instructions.length).toBeGreaterThan(0);
    });

    test('submitSettleAndDistribute rejects when neither tokenProgram nor currency is given', async () => {
        const [payer, payee, operator] = await loadFixedSigners();
        await expect(
            submitSettleAndDistribute({
                buildAndSignWireTransaction: async () => 'WIRE',
                channelId: '11111111111111111111111111111111',
                mint: USDC.mainnet!,
                payee: payee.address,
                payer: payer.address,
                rentPayer: operator.address,
                rpc: {
                    sendTransaction: () => ({ send: async () => 'sig' as Signature }),
                },
                signer: operator,
                splits: [],
            }),
        ).rejects.toThrow(/tokenProgram or currency is required/);
    });

    test('waitForSignatureConfirmation uses its default context in error messages', async () => {
        const rpc = {
            getSignatureStatuses: () => ({
                send: async () => ({ value: [{ confirmationStatus: 'confirmed', err: { X: 1 } }] }),
            }),
        };
        await expect(
            waitForSignatureConfirmation({
                rpc,
                signature: 'sig111111111111111111111111111111111111111' as Signature,
            }),
        ).rejects.toThrow(/waitForSignatureConfirmation: tx .* failed on-chain/);
    });

    test('waitForSignatureConfirmation treats an omitted confirmationStatus as confirmed', async () => {
        const rpc = {
            getSignatureStatuses: () => ({
                send: async () => ({ value: [{ err: null }] }),
            }),
        };
        await expect(
            waitForSignatureConfirmation({
                options: { pollIntervalMs: 1, timeoutMs: 500 },
                rpc,
                signature: 'sig222222222222222222222222222222222222222' as Signature,
            }),
        ).resolves.toBeUndefined();
    });
});

// ── submitInitMultiDelegateTxIfMissing skip branch ──────────────────────────

describe('submitInitMultiDelegateTxIfMissing existing-PDA branch', () => {
    test('returns undefined and never broadcasts when the PDA already exists', async () => {
        const [owner] = await loadFixedSigners();
        const sends: string[] = [];
        const rpc = {
            getAccountInfo: () => ({
                send: async () => ({ value: { lamports: 1n } }),
            }),
            getSignatureStatuses: () => ({
                send: async () => ({ value: [{ confirmationStatus: 'confirmed', err: null }] }),
            }),
            sendTransaction: (wire: string) => ({
                send: async () => {
                    sends.push(wire);
                    return 'sig' as Signature;
                },
            }),
        };
        const signature = await submitInitMultiDelegateTxIfMissing({
            initMultiDelegateTx: 'BASE64-INIT-TX',
            mint: USDC.mainnet!,
            owner: owner.address,
            rpc: rpc as never,
        });
        expect(signature).toBeUndefined();
        expect(sends).toHaveLength(0);
    });

    test('broadcasts and confirms when the PDA is missing', async () => {
        const [owner] = await loadFixedSigners();
        const sends: string[] = [];
        const rpc = {
            getAccountInfo: () => ({
                send: async () => ({ value: null }),
            }),
            getSignatureStatuses: () => ({
                send: async () => ({ value: [{ confirmationStatus: 'confirmed', err: null }] }),
            }),
            sendTransaction: (wire: string) => ({
                send: async () => {
                    sends.push(wire);
                    return 'InitSig11111111111111111111111111111111111111' as Signature;
                },
            }),
        };
        const signature = await submitInitMultiDelegateTxIfMissing({
            confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
            initMultiDelegateTx: 'BASE64-INIT-TX',
            mint: USDC.mainnet!,
            owner: owner.address,
            rpc: rpc as never,
        });
        expect(signature).toBeDefined();
        expect(sends).toEqual(['BASE64-INIT-TX']);
    });
});

// ── additional defaulting / short-input / decoy-instruction branches ────────

describe('verifyOpenTx defaulting and malformed-input branches', () => {
    test('defaults the program id when expected.programId is omitted', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const result = await verifyOpenTx({
            expected: {
                authorizedSigner: authorizedSigner.address,
                currency: USDC.mainnet!,
                maxCap: 5_000_000n,
                network: 'localnet',
                operator: payer.address,
                // programId omitted → PAYMENT_CHANNELS_PROGRAM_ID default.
                recipient: payee.address,
            },
            openPayload: {
                authorizedSigner: authorizedSigner.address,
                mode: 'push',
                signature: PLACEHOLDER_SIG,
                transaction: open.transaction,
            },
        });
        expect(result.channelId).toBe(open.channelId);
    });

    test('rejects when the mint cannot be resolved from currency/network', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        await expect(
            verifyOpenTx({
                expected: {
                    authorizedSigner: authorizedSigner.address,
                    // Empty currency + unknown network → nothing to resolve.
                    currency: '',
                    maxCap: 5_000_000n,
                    network: 'no-such-network',
                    operator: payer.address,
                    programId: PAYMENT_CHANNELS_PROGRAM_ID as string,
                    recipient: payee.address,
                },
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: open.transaction,
                },
            }),
        ).rejects.toThrow(/could not resolve mint/);
    });

    test('skips a non-open payment-channels instruction while scanning', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        // Prepend a decoy payment-channels instruction with a non-open
        // discriminator so the scan loop takes the `data[0] !== OPEN` continue
        // before finding the real open instruction later in the list.
        const withDecoy = remapTransaction(open.transaction, message => {
            const staticAccounts = message.staticAccounts as string[];
            const instructions = message.instructions as {
                accountIndices?: number[];
                data?: Uint8Array;
                programAddressIndex: number;
            }[];
            const openIx = instructions.find(
                ix =>
                    staticAccounts[ix.programAddressIndex] === (PAYMENT_CHANNELS_PROGRAM_ID as string) &&
                    ix.data &&
                    ix.data[0] === 1,
            )!;
            const decoy = {
                accountIndices: openIx.accountIndices ?? [],
                data: new Uint8Array([9]),
                programAddressIndex: openIx.programAddressIndex,
            };
            // Also add an empty-data decoy so the `data.length < 1` continue runs.
            const emptyDecoy = {
                accountIndices: openIx.accountIndices ?? [],
                data: new Uint8Array([]),
                programAddressIndex: openIx.programAddressIndex,
            };
            return { ...message, instructions: [emptyDecoy, decoy, ...instructions] };
        });
        const result = await verifyOpenTx({
            expected: expectedFor(payer, payee, authorizedSigner),
            openPayload: {
                authorizedSigner: authorizedSigner.address,
                mode: 'push',
                signature: PLACEHOLDER_SIG,
                transaction: withDecoy,
            },
        });
        expect(result.channelId).toBe(open.channelId);
    });

    test('rejects an open instruction with too few accounts', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const truncated = remapTransaction(open.transaction, message => {
            const staticAccounts = message.staticAccounts as string[];
            const instructions = (
                message.instructions as {
                    accountIndices?: number[];
                    data?: Uint8Array;
                    programAddressIndex: number;
                }[]
            ).map(ix => {
                if (
                    staticAccounts[ix.programAddressIndex] === (PAYMENT_CHANNELS_PROGRAM_ID as string) &&
                    ix.data &&
                    ix.data[0] === 1
                ) {
                    return { ...ix, accountIndices: (ix.accountIndices ?? []).slice(0, 4) };
                }
                return ix;
            });
            return { ...message, instructions };
        });
        await expect(
            verifyOpenTx({
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: truncated,
                },
            }),
        ).rejects.toThrow(/too few accounts/);
    });

    test('rejects when the open instruction data is too short', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const shortData = remapTransaction(open.transaction, message => {
            const staticAccounts = message.staticAccounts as string[];
            const instructions = (
                message.instructions as {
                    accountIndices?: number[];
                    data?: Uint8Array;
                    programAddressIndex: number;
                }[]
            ).map(ix => {
                if (
                    staticAccounts[ix.programAddressIndex] === (PAYMENT_CHANNELS_PROGRAM_ID as string) &&
                    ix.data &&
                    ix.data[0] === 1
                ) {
                    // Keep the discriminator but drop the salt/deposit/grace bytes.
                    return { ...ix, data: new Uint8Array([1, 2, 3]) };
                }
                return ix;
            });
            return { ...message, instructions };
        });
        await expect(
            verifyOpenTx({
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: shortData,
                },
            }),
        ).rejects.toThrow(/data too short/);
    });
});

// ── submitOpenTx payerSigner-absent + valid-voucher settle path ─────────────

describe('submitOpenTx payerSigner-absent branch', () => {
    test('does not co-sign when payerSigner is not a signer of the tx', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const outsider = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x2a));
        const sends: string[] = [];
        const rpc = {
            getSignatureStatuses: () => ({
                send: async () => ({ value: [{ confirmationStatus: 'confirmed', err: null }] }),
            }),
            sendTransaction: (wire: string) => ({
                send: async () => {
                    sends.push(wire);
                    return 'OpenSig222222222222222222222222222222222222222222' as Signature;
                },
            }),
        };
        // The outsider is not in the tx's signatures map, so the co-sign branch
        // is skipped and the original wire is broadcast unchanged.
        const result = await submitOpenTx({
            confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
            expected: expectedFor(payer, payee, authorizedSigner),
            openPayload: {
                authorizedSigner: authorizedSigner.address,
                mode: 'push',
                signature: PLACEHOLDER_SIG,
                transaction: open.transaction,
            },
            payerSigner: outsider as never,
            rpc,
        });
        expect(result.signature).toBeDefined();
        expect(sends[0]).toBe(open.transaction);
    });
});

describe('buildSettleAndFinalizeInstructions valid voucher path', () => {
    test('parses the voucher amount and encodes hasVoucher=1', async () => {
        const merchant = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x2b));
        const authorizedSigner = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x2c));
        const channelId = '11111111111111111111111111111111';
        // A base58 signature that decodes to exactly 64 bytes.
        const sig64 = bs58Encode(new Uint8Array(64).fill(7));
        const signed: SignedVoucher = {
            // cumulativeAmount is a decimal string (parseU64String happy path);
            // expiresAt is a number (toBigInt number branch).
            data: { channelId, cumulativeAmount: '500', expiresAt: 1_700_000_000 },
            signature: sig64,
        };
        const out = buildSettleAndFinalizeInstructions({
            channelId,
            merchantSigner: merchant,
            voucher: { authorizedSigner: authorizedSigner.address, signed },
        });
        expect(out.requiresEd25519Precompile).toBe(true);
        expect(out.instructions).toHaveLength(2);
        const settle = out.instructions[1]!;
        const data = new Uint8Array(settle.data);
        expect(data[data.byteLength - 1]).toBe(1);
    });

    test('accepts a bigint expiresAt on the voucher (toBigInt bigint branch)', async () => {
        const merchant = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x2d));
        const authorizedSigner = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x2e));
        const channelId = '11111111111111111111111111111111';
        const sig64 = bs58Encode(new Uint8Array(64).fill(7));
        const signed = {
            data: { channelId, cumulativeAmount: '500', expiresAt: 1_700_000_000n },
            signature: sig64,
        } as unknown as SignedVoucher;
        const out = buildSettleAndFinalizeInstructions({
            channelId,
            merchantSigner: merchant,
            voucher: { authorizedSigner: authorizedSigner.address, signed },
        });
        expect(out.requiresEd25519Precompile).toBe(true);
    });

    test('rejects a non-numeric voucher cumulativeAmount (parseU64String)', async () => {
        const merchant = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x2f));
        const authorizedSigner = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x30));
        const channelId = '11111111111111111111111111111111';
        const sig64 = bs58Encode(new Uint8Array(64).fill(7));
        const signed = {
            data: { channelId, cumulativeAmount: 'not-a-number', expiresAt: 0 },
            signature: sig64,
        } as unknown as SignedVoucher;
        expect(() =>
            buildSettleAndFinalizeInstructions({
                channelId,
                merchantSigner: merchant,
                voucher: { authorizedSigner: authorizedSigner.address, signed },
            }),
        ).toThrow(/not an unsigned integer string/);
    });

    test('rejects a voucher cumulativeAmount outside u64 range (parseU64String)', async () => {
        const merchant = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x31));
        const authorizedSigner = await createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x32));
        const channelId = '11111111111111111111111111111111';
        const sig64 = bs58Encode(new Uint8Array(64).fill(7));
        // 2^64 (one past the u64 max) as a decimal string.
        const signed = {
            data: { channelId, cumulativeAmount: '18446744073709551616', expiresAt: 0 },
            signature: sig64,
        } as unknown as SignedVoucher;
        expect(() =>
            buildSettleAndFinalizeInstructions({
                channelId,
                merchantSigner: merchant,
                voucher: { authorizedSigner: authorizedSigner.address, signed },
            }),
        ).toThrow(/outside u64 range/);
    });
});

// ── verifyOpenTx: remaining mint/account-index branches ─────────────────────

describe('verifyOpenTx mint-fallback and account-index branches', () => {
    test('falls back to the currency string when it is not a known stablecoin mint', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        // Build an open tx whose mint is an arbitrary (non-stablecoin) address.
        // resolveStablecoinMint returns undefined for it, so `expected.mint`
        // defaults to `expected.currency` (the same address).
        const customMint = 'HQyfh1JGDB47A6Az4MD9KgF9LqcL3ESCkN8AT9Y8atGD';
        const request: SessionRequest = {
            cap: '1000000',
            currency: customMint,
            decimals: 6,
            network: 'localnet',
            operator: payer.address,
            recentBlockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as never,
            recipient: payee.address,
        };
        const open = await buildOpenPaymentChannelTransaction({
            authorizedSigner: authorizedSigner.address,
            deposit: 1_000_000n,
            gracePeriod: 900,
            programAddress: PAYMENT_CHANNELS_PROGRAM_ID,
            request,
            salt: 7n,
            signer: payer,
        });
        const result = await verifyOpenTx({
            expected: {
                authorizedSigner: authorizedSigner.address,
                currency: customMint,
                maxCap: 5_000_000n,
                network: 'localnet',
                operator: payer.address,
                programId: PAYMENT_CHANNELS_PROGRAM_ID as string,
                recipient: payee.address,
            },
            openPayload: {
                authorizedSigner: authorizedSigner.address,
                mode: 'push',
                signature: PLACEHOLDER_SIG,
                transaction: open.transaction,
            },
        });
        expect(result.channelId).toBe(open.channelId);
    });

    test('skips instructions that target a different program while scanning', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        // Prepend a decoy instruction that targets a non-payment-channels
        // program, so the scan loop takes the program-mismatch continue.
        const withForeign = remapTransaction(open.transaction, message => {
            const staticAccounts = [...(message.staticAccounts as string[])];
            const foreignIndex = staticAccounts.length;
            staticAccounts.push('11111111111111111111111111111111');
            const instructions = message.instructions as {
                accountIndices?: number[];
                data?: Uint8Array;
                programAddressIndex: number;
            }[];
            const decoy = {
                accountIndices: [],
                data: new Uint8Array([1]),
                programAddressIndex: foreignIndex,
            };
            return { ...message, instructions: [decoy, ...instructions], staticAccounts };
        });
        const result = await verifyOpenTx({
            expected: expectedFor(payer, payee, authorizedSigner),
            openPayload: {
                authorizedSigner: authorizedSigner.address,
                mode: 'push',
                signature: PLACEHOLDER_SIG,
                transaction: withForeign,
            },
        });
        expect(result.channelId).toBe(open.channelId);
    });

    test('rejects when an open-instruction account index points past the account table', async () => {
        const [payer, payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        // Keep >= 8 indices (so the length guard passes) but point slot 0 at an
        // out-of-range static-account index, so `accountAt` sees no address.
        const badIndex = remapTransaction(open.transaction, message => {
            const staticAccounts = message.staticAccounts as string[];
            const outOfRange = staticAccounts.length + 5;
            const instructions = (
                message.instructions as {
                    accountIndices?: number[];
                    data?: Uint8Array;
                    programAddressIndex: number;
                }[]
            ).map(ix => {
                if (
                    staticAccounts[ix.programAddressIndex] === (PAYMENT_CHANNELS_PROGRAM_ID as string) &&
                    ix.data &&
                    ix.data[0] === 1
                ) {
                    const accountIndices = [...(ix.accountIndices ?? [])];
                    accountIndices[0] = outOfRange;
                    return { ...ix, accountIndices };
                }
                return ix;
            });
            return { ...message, instructions };
        });
        await expect(
            verifyOpenTx({
                expected: expectedFor(payer, payee, authorizedSigner),
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    mode: 'push',
                    signature: PLACEHOLDER_SIG,
                    transaction: badIndex,
                },
            }),
        ).rejects.toThrow(/missing account at slot 0/);
    });
});

/** Minimal base58 encoder for fixed-byte signatures used in tests. */
function bs58Encode(bytes: Uint8Array): string {
    const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    let zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    const digits = [0];
    for (let i = zeros; i < bytes.length; i++) {
        let carry = bytes[i]!;
        for (let j = 0; j < digits.length; j++) {
            carry += digits[j]! << 8;
            digits[j] = carry % 58;
            carry = Math.floor(carry / 58);
        }
        while (carry > 0) {
            digits.push(carry % 58);
            carry = Math.floor(carry / 58);
        }
    }
    let out = '';
    for (let i = 0; i < zeros; i++) out += '1';
    for (let i = digits.length - 1; i >= 0; i--) out += ALPHABET[digits[i]!];
    return out;
}
