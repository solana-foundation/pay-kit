/**
 * verifyOpenTx / submitOpenTx hardening coverage.
 *
 * Reinstates the server-side on-chain hardening tests that lived in the
 * deleted `session-server-on-chain.test.ts`, ported to the challenge-bound
 * verifyOpenTx API, plus coverage for the verifier checks that landed with
 * it:
 *
 *   - verifyOpenTx accepts both legacy and v0 transaction encodings and
 *     rejects malformed wire bytes.
 *   - verifyOpenTx rejects v0 opens carrying address-lookup tables — every
 *     account it inspects must be static.
 *   - verifyOpenTx binds the open instruction's accounts (payee, mint,
 *     tokenProgram, authorizedSigner, rentPayer, fee payer) and args
 *     (deposit, minimumDeposit, openSlot) to the challenge.
 *   - waitForSignatureConfirmation accepts confirmed/finalized (and RPC
 *     endpoints that omit confirmationStatus), rejects on-chain errors,
 *     times out, and honors abort signals.
 *   - submitOpenTx verifies before broadcasting, waits for confirmation,
 *     and binds the confirmed channel account to the verified open.
 *
 * The blockhash/slot challenge-binding and distributionSplits-binding legs
 * are covered in `session-open-context.test.ts` — not duplicated here.
 */
import {
    address,
    generateKeyPairSigner,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getCompiledTransactionMessageEncoder,
    getTransactionDecoder,
    getTransactionEncoder,
    type Signature,
} from '@solana/kit';
import { describe, expect, test } from 'vitest';

import { buildOpenPaymentChannelTransaction } from '../client/PaymentChannels.js';
import type { SessionRequest } from '../client/Session.js';
import { getChannelEncoder } from '../generated/payment-channels/accounts/channel.js';
import { ChannelStatus } from '../generated/payment-channels/types/channelStatus.js';
import {
    PAYMENT_CHANNELS_PROGRAM_ID,
    type SignatureStatus,
    submitOpenTx,
    verifyOpenTx,
    type VerifyOpenTxExpected,
    waitForSignatureConfirmation,
} from '../server/session/on-chain.js';
import type { OpenPayload } from '../shared/session-types.js';

const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
// resolveStablecoinMint('USDC', 'devnet') / ('USDC', 'mainnet')
const USDC_DEVNET_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const USDC_MAINNET_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const ADDRESS_LOOKUP_TABLE_PROGRAM = 'AddressLookupTab1e1111111111111111111111111';
const CHALLENGED_BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';
const CHALLENGED_SLOT = 314n;
const OPEN_SIGNATURE = 'OpenSig1111111111111111111111111111111111111111111111111111111' as Signature;

// ── fixtures (same conventions as session-open-context.test.ts) ────────

function challengeRequest(recipient: string, methodDetails: Record<string, unknown> = {}) {
    return {
        amount: '100',
        currency: 'USDC',
        recipient,
        suggestedDeposit: '5000',
        methodDetails: {
            channelProgram: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
            gracePeriodSeconds: 900,
            network: 'devnet',
            recentBlockhash: CHALLENGED_BLOCKHASH,
            recentSlot: CHALLENGED_SLOT.toString(),
            tokenProgram: TOKEN_PROGRAM,
            ...methodDetails,
        },
    };
}

async function clientOpenFixture() {
    const payer = await generateKeyPairSigner();
    const sessionSigner = await generateKeyPairSigner();
    const payee = await generateKeyPairSigner();
    const request = challengeRequest(payee.address) as unknown as SessionRequest;
    return { payee, payer, request, sessionSigner };
}

async function verifiedOpenFixture() {
    const { payee, payer, request, sessionSigner } = await clientOpenFixture();
    const open = await buildOpenPaymentChannelTransaction({
        authorizedSigner: sessionSigner.address,
        request,
        salt: 7n,
        signer: payer,
    });
    const openPayload: OpenPayload = {
        authorizedSigner: sessionSigner.address,
        channelId: open.channelId,
        depositAmount: open.deposit,
        gracePeriodSeconds: open.gracePeriod,
        mint: open.mint,
        openSlot: open.openSlot,
        payee: open.payee,
        payer: open.payer,
        salt: open.salt,
        transaction: open.transaction,
    };
    const expected: VerifyOpenTxExpected = {
        authorizedSigner: sessionSigner.address,
        channelProgram: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
        currency: 'USDC',
        feePayer: payer.address,
        network: 'devnet',
        openSlot: CHALLENGED_SLOT,
        recentBlockhash: CHALLENGED_BLOCKHASH,
        recipient: open.payee,
        rentPayer: payer.address,
        splits: [],
        tokenProgram: TOKEN_PROGRAM,
    };
    return { expected, open, openPayload, payee, payer, sessionSigner };
}

/** Re-encode a v0 wire transaction as a legacy wire transaction. */
function reencodeAsLegacy(transactionBase64: string): string {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    const compiled = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
    const legacyMessageBytes = getCompiledTransactionMessageEncoder().encode({
        ...compiled,
        version: 'legacy',
    } as never);
    const legacyTx = getTransactionEncoder().encode({
        messageBytes: legacyMessageBytes as never,
        signatures: tx.signatures,
    });
    return getBase64Codec().decode(legacyTx);
}

/** Re-encode a v0 wire transaction with an injected address-lookup table. */
function injectAddressTableLookup(transactionBase64: string): string {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    const compiled = getCompiledTransactionMessageDecoder().decode(tx.messageBytes);
    const messageBytes = getCompiledTransactionMessageEncoder().encode({
        ...compiled,
        addressTableLookups: [
            {
                lookupTableAddress: address(ADDRESS_LOOKUP_TABLE_PROGRAM),
                readonlyIndexes: [0],
                writableIndexes: [],
            },
        ],
    } as never);
    const withLookup = getTransactionEncoder().encode({
        messageBytes: messageBytes as never,
        signatures: tx.signatures,
    });
    return getBase64Codec().decode(withLookup);
}

/** Replace the payer's signature with a null (all-zero placeholder) entry. */
function stripSignature(transactionBase64: string, signer: string): string {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    const signatures = { ...tx.signatures, [signer]: null };
    const stripped = getTransactionEncoder().encode({
        messageBytes: tx.messageBytes,
        signatures: signatures as never,
    });
    return getBase64Codec().decode(stripped);
}

// ── verifyOpenTx: transaction shape ─────────────────────────────────────

describe('verifyOpenTx transaction shape', () => {
    test('accepts a well-formed v0 open and returns the channel facts', async () => {
        const { expected, open, openPayload } = await verifiedOpenFixture();
        const verified = await verifyOpenTx({ expected, openPayload });
        expect(verified.channelId).toBe(open.channelId);
        expect(verified.deposit).toBe(5_000n);
        expect(verified.gracePeriod).toBe(900);
        expect(verified.openSlot).toBe(CHALLENGED_SLOT);
        expect(verified.payer).toBe(open.payer);
        expect(verified.salt).toBe(7n);
    });

    test('accepts a legacy-encoded open transaction (Rust client wire format)', async () => {
        const { expected, open, openPayload } = await verifiedOpenFixture();
        const legacyTransaction = reencodeAsLegacy(open.transaction);
        expect(legacyTransaction).not.toBe(open.transaction);

        const verified = await verifyOpenTx({
            expected,
            openPayload: { ...openPayload, transaction: legacyTransaction },
        });
        expect(verified.channelId).toBe(open.channelId);
        expect(verified.deposit).toBe(5_000n);
        expect(verified.salt).toBe(7n);
    });

    test('rejects a v0 open carrying an address-lookup table', async () => {
        const { expected, open, openPayload } = await verifiedOpenFixture();
        const withLookup = injectAddressTableLookup(open.transaction);

        await expect(
            verifyOpenTx({ expected, openPayload: { ...openPayload, transaction: withLookup } }),
        ).rejects.toThrow(/address-lookup tables are not permitted/);
    });

    test('rejects a payload without a transaction', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        await expect(verifyOpenTx({ expected, openPayload: { ...openPayload, transaction: '' } })).rejects.toThrow(
            /openPayload\.transaction is required/,
        );
    });

    test('rejects a transaction that is not base64', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        await expect(
            verifyOpenTx({ expected, openPayload: { ...openPayload, transaction: '@@@not-base64@@@' } }),
        ).rejects.toThrow();
    });

    test('rejects truncated transaction bytes', async () => {
        const { expected, open, openPayload } = await verifiedOpenFixture();
        const truncated = open.transaction.slice(0, 32);
        await expect(
            verifyOpenTx({ expected, openPayload: { ...openPayload, transaction: truncated } }),
        ).rejects.toThrow();
    });
});

// ── verifyOpenTx: challenge binding of accounts and args ────────────────

describe('verifyOpenTx binds the open instruction to the challenge', () => {
    test('rejects a payee that is not the expected recipient', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        const other = await generateKeyPairSigner();
        await expect(
            verifyOpenTx({ expected: { ...expected, recipient: other.address }, openPayload }),
        ).rejects.toThrow(/payee .* != expected recipient/);
    });

    test('rejects a mint that does not match the challenge currency', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        await expect(verifyOpenTx({ expected: { ...expected, mint: USDC_MAINNET_MINT }, openPayload })).rejects.toThrow(
            /mint .* != expected mint/,
        );
    });

    test('rejects a token program that does not match the challenge', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        await expect(
            verifyOpenTx({ expected: { ...expected, tokenProgram: TOKEN_2022_PROGRAM }, openPayload }),
        ).rejects.toThrow(/tokenProgram .* != expected/);
    });

    test('rejects an authorizedSigner that does not match the challenge', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        const other = await generateKeyPairSigner();
        await expect(
            verifyOpenTx({ expected: { ...expected, authorizedSigner: other.address }, openPayload }),
        ).rejects.toThrow(/authorizedSigner .* != expected/);
    });

    test('rejects a rentPayer that is not the expected operator', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        const other = await generateKeyPairSigner();
        await expect(
            verifyOpenTx({ expected: { ...expected, rentPayer: other.address }, openPayload }),
        ).rejects.toThrow(/rentPayer .* != expected/);
    });

    test('rejects a transaction fee payer that does not match the challenge policy', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        const other = await generateKeyPairSigner();
        await expect(verifyOpenTx({ expected: { ...expected, feePayer: other.address }, openPayload })).rejects.toThrow(
            /transaction fee payer .* != expected/,
        );
    });

    test('rejects an open the channel payer never signed', async () => {
        const { expected, open, openPayload, payer } = await verifiedOpenFixture();
        const unsigned = stripSignature(open.transaction, payer.address);
        await expect(
            verifyOpenTx({ expected, openPayload: { ...openPayload, transaction: unsigned } }),
        ).rejects.toThrow(/channel payer must sign the open transaction/);
    });

    test('rejects a deposit below the challenged minimumDeposit', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        await expect(verifyOpenTx({ expected: { ...expected, minimumDeposit: 5_001n }, openPayload })).rejects.toThrow(
            /deposit 5000 is below minimumDeposit 5001/,
        );
    });

    test('rejects a declared depositAmount that disagrees with the instruction', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        await expect(
            verifyOpenTx({ expected, openPayload: { ...openPayload, depositAmount: '4999' } }),
        ).rejects.toThrow(/deposit 5000 != payload depositAmount 4999/);
    });

    test('rejects an openSlot that disagrees with the challenged slot', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        await expect(
            verifyOpenTx({ expected: { ...expected, openSlot: CHALLENGED_SLOT - 1n }, openPayload }),
        ).rejects.toThrow(/openSlot .* does not match the payload/);
    });
});

// ── waitForSignatureConfirmation: RPC status polling ────────────────────

function statusRpc(statusSequence: (SignatureStatus | null)[]) {
    let statusCalls = 0;
    return {
        getSignatureStatuses: (_signatures: readonly Signature[]) => ({
            send: async () => {
                const status =
                    statusCalls < statusSequence.length
                        ? statusSequence[statusCalls]
                        : statusSequence[statusSequence.length - 1];
                statusCalls += 1;
                return { value: [status ?? null] };
            },
        }),
        statusCallCount: () => statusCalls,
    };
}

describe('waitForSignatureConfirmation status polling', () => {
    test("resolves once the signature reaches 'confirmed'", async () => {
        const rpc = statusRpc([{ confirmationStatus: 'confirmed', err: null }]);
        await waitForSignatureConfirmation({
            options: { pollIntervalMs: 1, timeoutMs: 2_000 },
            rpc,
            signature: OPEN_SIGNATURE,
        });
        expect(rpc.statusCallCount()).toBe(1);
    });

    test("resolves once the signature reaches 'finalized'", async () => {
        const rpc = statusRpc([{ confirmationStatus: 'finalized', err: null }]);
        await waitForSignatureConfirmation({
            options: { pollIntervalMs: 1, timeoutMs: 2_000 },
            rpc,
            signature: OPEN_SIGNATURE,
        });
        expect(rpc.statusCallCount()).toBe(1);
    });

    test('treats an RPC response that omits confirmationStatus as confirmed', async () => {
        const rpc = statusRpc([{ err: null }]);
        await waitForSignatureConfirmation({
            options: { pollIntervalMs: 1, timeoutMs: 2_000 },
            rpc,
            signature: OPEN_SIGNATURE,
        });
        expect(rpc.statusCallCount()).toBe(1);
    });

    test("keeps polling through null and 'processed' statuses", async () => {
        const rpc = statusRpc([
            null,
            { confirmationStatus: 'processed', err: null },
            { confirmationStatus: 'confirmed', err: null },
        ]);
        await waitForSignatureConfirmation({
            options: { pollIntervalMs: 1, timeoutMs: 2_000 },
            rpc,
            signature: OPEN_SIGNATURE,
        });
        expect(rpc.statusCallCount()).toBe(3);
    });

    test('rejects as soon as the status carries an on-chain error, even before confirmed', async () => {
        const rpc = statusRpc([{ confirmationStatus: 'processed', err: { InstructionError: [0, 'Custom'] } }]);
        await expect(
            waitForSignatureConfirmation({
                options: { pollIntervalMs: 1, timeoutMs: 2_000 },
                rpc,
                signature: OPEN_SIGNATURE,
            }),
        ).rejects.toThrow(/failed on-chain/);
    });

    test('times out when the signature never lands', async () => {
        const rpc = statusRpc([null]);
        await expect(
            waitForSignatureConfirmation({
                options: { pollIntervalMs: 1, timeoutMs: 20 },
                rpc,
                signature: OPEN_SIGNATURE,
            }),
        ).rejects.toThrow(/timed out/);
    });

    test('aborts without polling when the signal already fired', async () => {
        const rpc = statusRpc([null]);
        const controller = new AbortController();
        controller.abort();
        await expect(
            waitForSignatureConfirmation({
                options: { pollIntervalMs: 1, signal: controller.signal, timeoutMs: 2_000 },
                rpc,
                signature: OPEN_SIGNATURE,
            }),
        ).rejects.toThrow(/aborted/);
        expect(rpc.statusCallCount()).toBe(0);
    });
});

// ── submitOpenTx: verify → broadcast → confirm → bind channel state ─────

interface ChannelAccountFacts {
    readonly authorizedSigner: string;
    readonly deposit: bigint;
    readonly mint: string;
    readonly payee: string;
    readonly payer: string;
    readonly rentPayer: string;
}

/** Base64 account data for a confirmed Channel account with the given facts. */
function channelAccountData(facts: ChannelAccountFacts): string {
    const data = getChannelEncoder().encode({
        authorizedSigner: address(facts.authorizedSigner),
        bump: 255,
        closureStartedAt: 0n,
        deposit: facts.deposit,
        discriminator: 1,
        distributionHash: new Array<number>(32).fill(0),
        gracePeriod: 900,
        mint: address(facts.mint),
        openSlot: CHALLENGED_SLOT,
        payee: address(facts.payee),
        payer: address(facts.payer),
        payerWithdrawnAt: 0n,
        rentPayer: address(facts.rentPayer),
        salt: 7n,
        settlement: { payoutWatermark: 0n, settled: 0n },
        status: Number(ChannelStatus.Open),
        version: 1,
    });
    return getBase64Codec().decode(data as Uint8Array);
}

function submitRpc(statusSequence: (SignatureStatus | null)[], channelData?: string) {
    const sends: string[] = [];
    const accountLookups: string[] = [];
    let statusCalls = 0;
    return {
        accountLookups,
        getAccountInfo: (accountAddress: string) => ({
            send: async () => {
                accountLookups.push(accountAddress);
                return {
                    context: { slot: 1n },
                    value:
                        channelData === undefined
                            ? null
                            : {
                                  data: [channelData, 'base64'],
                                  executable: false,
                                  lamports: 1_000_000n,
                                  owner: PAYMENT_CHANNELS_PROGRAM_ID.toString(),
                                  rentEpoch: 0n,
                                  space: BigInt(getBase64Codec().encode(channelData).byteLength),
                              },
                };
            },
        }),
        getSignatureStatuses: (_signatures: readonly Signature[]) => ({
            send: async () => {
                const status =
                    statusCalls < statusSequence.length
                        ? statusSequence[statusCalls]
                        : statusSequence[statusSequence.length - 1];
                statusCalls += 1;
                return { value: [status ?? null] };
            },
        }),
        sendTransaction: (wire: string) => ({
            send: async () => {
                sends.push(wire);
                return OPEN_SIGNATURE;
            },
        }),
        sends,
        statusCallCount: () => statusCalls,
    };
}

describe('submitOpenTx confirmation gating', () => {
    test('a verification failure rejects before anything is broadcast', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        const other = await generateKeyPairSigner();
        const rpc = submitRpc([{ confirmationStatus: 'confirmed', err: null }]);

        await expect(
            submitOpenTx({
                confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
                expected: { ...expected, recipient: other.address },
                openPayload,
                rpc: rpc as never,
            }),
        ).rejects.toThrow(/payee .* != expected recipient/);
        expect(rpc.sends).toHaveLength(0);
    });

    test('polls until confirmed, then binds the confirmed channel account', async () => {
        const { expected, open, openPayload, payer, sessionSigner } = await verifiedOpenFixture();
        const rpc = submitRpc(
            [null, { confirmationStatus: 'processed', err: null }, { confirmationStatus: 'confirmed', err: null }],
            channelAccountData({
                authorizedSigner: sessionSigner.address,
                deposit: 5_000n,
                mint: USDC_DEVNET_MINT,
                payee: open.payee,
                payer: payer.address,
                rentPayer: payer.address,
            }),
        );

        const result = await submitOpenTx({
            confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
            expected,
            openPayload,
            rpc: rpc as never,
        });
        expect(result.channelId).toBe(open.channelId);
        expect(result.signature).toBe(OPEN_SIGNATURE);
        expect(rpc.sends).toEqual([open.transaction]);
        expect(rpc.statusCallCount()).toBeGreaterThanOrEqual(3);
        expect(rpc.accountLookups).toEqual([open.channelId]);
    });

    test('a preflight-rejected duplicate whose open landed is rescued by the confirmed account', async () => {
        // First submission landed but the response (or the persist after it)
        // was lost; the retry dies at preflight like mainnet. The confirmed
        // channel account matches the verified open params only if this
        // exact open succeeded, so the retry must succeed.
        const { expected, open, openPayload, payer, sessionSigner } = await verifiedOpenFixture();
        const rpc = submitRpc(
            [{ confirmationStatus: 'confirmed', err: null }],
            channelAccountData({
                authorizedSigner: sessionSigner.address,
                deposit: 5_000n,
                mint: USDC_DEVNET_MINT,
                payee: open.payee,
                payer: payer.address,
                rentPayer: payer.address,
            }),
        );
        rpc.sendTransaction = () => ({
            send: async () => {
                throw new Error('Transaction simulation failed: This transaction has already been processed');
            },
        });

        const result = await submitOpenTx({
            confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
            expected,
            openPayload,
            rpc: rpc as never,
        });
        expect(result.channelId).toBe(open.channelId);
        expect(rpc.accountLookups).toEqual([open.channelId]);
    });

    test('a preflight-rejected open without a matching confirmed account keeps the broadcast error', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        const rpc = submitRpc([{ confirmationStatus: 'confirmed', err: null }]);
        rpc.sendTransaction = () => ({
            send: async () => {
                throw new Error('Transaction simulation failed: This transaction has already been processed');
            },
        });

        await expect(
            submitOpenTx({
                confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
                expected,
                openPayload,
                rpc: rpc as never,
            }),
        ).rejects.toThrow(/already been processed/);
    });

    test('throws when confirmation never arrives within the timeout', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        const rpc = submitRpc([null]);

        await expect(
            submitOpenTx({
                confirm: { pollIntervalMs: 1, timeoutMs: 20 },
                expected,
                openPayload,
                rpc: rpc as never,
            }),
        ).rejects.toThrow(/timed out/);
    });

    test('throws when the transaction failed on-chain', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        const rpc = submitRpc([{ confirmationStatus: 'confirmed', err: { InstructionError: [0, 'Custom'] } }]);

        await expect(
            submitOpenTx({
                confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
                expected,
                openPayload,
                rpc: rpc as never,
            }),
        ).rejects.toThrow(/failed on-chain/);
    });

    test('aborts when the signal fires', async () => {
        const { expected, openPayload } = await verifiedOpenFixture();
        const rpc = submitRpc([null]);
        const controller = new AbortController();
        controller.abort();

        await expect(
            submitOpenTx({
                confirm: { pollIntervalMs: 1, signal: controller.signal, timeoutMs: 2_000 },
                expected,
                openPayload,
                rpc: rpc as never,
            }),
        ).rejects.toThrow(/aborted/);
    });

    test('rejects when the confirmed channel account does not match the verified open', async () => {
        const { expected, open, openPayload, payer, sessionSigner } = await verifiedOpenFixture();
        const rpc = submitRpc(
            [{ confirmationStatus: 'confirmed', err: null }],
            channelAccountData({
                authorizedSigner: sessionSigner.address,
                // The chain reports a smaller deposit than the open declared.
                deposit: 4_000n,
                mint: USDC_DEVNET_MINT,
                payee: open.payee,
                payer: payer.address,
                rentPayer: payer.address,
            }),
        );

        await expect(
            submitOpenTx({
                confirm: { pollIntervalMs: 1, timeoutMs: 2_000 },
                expected,
                openPayload,
                rpc: rpc as never,
            }),
        ).rejects.toThrow(/confirmed channel state does not match/);
    });
});
