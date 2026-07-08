// On-chain instruction byte-equivalence and verifyOpenTx tests.
//
// Goal: lock in the IX encoding so any drift from the Rust mirror
// (`mpp/src/program/payment_channels.rs`) is caught at unit-test time.
// Surfpool integration is deferred to Phase F.

import {
    address,
    AccountRole,
    createKeyPairSignerFromPrivateKeyBytes,
    generateKeyPairSigner,
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
import { USDC, TOKEN_PROGRAM } from '../constants.js';
import {
    buildDistributeInstruction,
    buildEd25519VerifyInstruction,
    buildMultiDelegatorInitInstruction,
    buildMultiDelegatorUpdateInstruction,
    buildSettleAndFinalizeInstructions,
    buildTopUpInstruction,
    ED25519_PROGRAM_ADDRESS,
    encodeVoucherMessageBytes,
    INSTRUCTIONS_SYSVAR_ADDRESS,
    MULTI_DELEGATOR_PROGRAM_ID,
    PAYMENT_CHANNELS_PROGRAM_ID,
    verifyOpenTx,
} from '../server/session/on-chain.js';

function makeSeed(byte: number): Uint8Array {
    const seed = new Uint8Array(32);
    seed.fill(byte);
    return seed;
}

const PAYER_SEED = makeSeed(0x01);
const OPERATOR_SEED = makeSeed(0x02);
const PAYEE_SEED = makeSeed(0x03);
const AUTHORIZED_SEED = makeSeed(0x04);
const MERCHANT_SEED = makeSeed(0x05);

async function loadFixedSigners() {
    return await Promise.all([
        createKeyPairSignerFromPrivateKeyBytes(PAYER_SEED),
        createKeyPairSignerFromPrivateKeyBytes(OPERATOR_SEED),
        createKeyPairSignerFromPrivateKeyBytes(PAYEE_SEED),
        createKeyPairSignerFromPrivateKeyBytes(AUTHORIZED_SEED),
        createKeyPairSignerFromPrivateKeyBytes(MERCHANT_SEED),
    ]);
}

// ── encodeVoucherMessageBytes parity check ─────────────────────────────────

describe('encodeVoucherMessageBytes', () => {
    test('produces the 48-byte canonical voucher payload', () => {
        const bytes = encodeVoucherMessageBytes({
            channelId: '11111111111111111111111111111111',
            cumulativeAmount: 0n,
            expiresAt: 0n,
        });
        expect(bytes.byteLength).toBe(48);
        expect(bytes.every(b => b === 0)).toBe(true);
    });

    test('encodes channelId, cumulative (u64 LE), expiresAt (i64 LE) in order', () => {
        // Pick an address that encodes to exactly 32 bytes; use deterministic numbers.
        const bytes = encodeVoucherMessageBytes({
            channelId: '11111111111111111111111111111111',
            cumulativeAmount: 0x1234_5678n,
            expiresAt: 0x7fff_ffff_ffff_fff0n,
        });
        const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
        expect(view.getBigUint64(32, true)).toBe(0x1234_5678n);
        expect(view.getBigInt64(40, true)).toBe(0x7fff_ffff_ffff_fff0n);
    });
});

// ── Ed25519 precompile byte-equivalence ─────────────────────────────────────

describe('buildEd25519VerifyInstruction', () => {
    test('header layout matches Rust precompile', () => {
        const signer = new Uint8Array(32).fill(0xaa);
        const signature = new Uint8Array(64).fill(0xbb);
        const message = new Uint8Array(48).fill(0xcc);
        const ix = buildEd25519VerifyInstruction({ message, signature, signer });

        expect(ix.programAddress).toBe(ED25519_PROGRAM_ADDRESS);
        expect(ix.accounts).toEqual([]);

        const data = new Uint8Array(ix.data);
        expect(data[0]).toBe(1); // num_signatures
        expect(data[1]).toBe(0); // padding
        // signature_offset = 48 (public_key_offset 16 + 32) → bytes 2..4
        expect(data[2]).toBe(48);
        expect(data[3]).toBe(0);
        // signature_instruction_index = 0xFFFF
        expect(data[4]).toBe(0xff);
        expect(data[5]).toBe(0xff);
        // public_key_offset = 16
        expect(data[6]).toBe(16);
        expect(data[7]).toBe(0);
        // public_key_instruction_index = 0xFFFF
        expect(data[8]).toBe(0xff);
        expect(data[9]).toBe(0xff);
        // message_data_offset = 112 (48 + 64)
        expect(data[10]).toBe(112);
        expect(data[11]).toBe(0);
        // message_data_size = 48
        expect(data[12]).toBe(48);
        expect(data[13]).toBe(0);
        // message_instruction_index = 0xFFFF
        expect(data[14]).toBe(0xff);
        expect(data[15]).toBe(0xff);

        // pubkey at 16..48
        expect(data.slice(16, 48)).toEqual(signer);
        // signature at 48..112
        expect(data.slice(48, 112)).toEqual(signature);
        // message at 112..160
        expect(data.slice(112, 160)).toEqual(message);
        expect(data.byteLength).toBe(160);
    });

    test('rejects malformed signer / signature lengths', () => {
        expect(() =>
            buildEd25519VerifyInstruction({
                message: new Uint8Array(48),
                signature: new Uint8Array(64),
                signer: new Uint8Array(31),
            }),
        ).toThrow(/signer must be 32 bytes/);
        expect(() =>
            buildEd25519VerifyInstruction({
                message: new Uint8Array(48),
                signature: new Uint8Array(63),
                signer: new Uint8Array(32),
            }),
        ).toThrow(/signature must be 64 bytes/);
    });
});

// ── settle_and_finalize ─────────────────────────────────────────────────────

describe('buildSettleAndFinalizeInstructions', () => {
    test('voucher-less variant emits a single instruction with hasVoucher=0', async () => {
        const [, , , , merchant] = await loadFixedSigners();
        const channelId = '11111111111111111111111111111111';

        const out = buildSettleAndFinalizeInstructions({
            channelId,
            merchantSigner: merchant,
        });
        expect(out.requiresEd25519Precompile).toBe(false);
        expect(out.instructions).toHaveLength(1);

        const ix = out.instructions[0]!;
        expect(ix.programAddress).toBe(PAYMENT_CHANNELS_PROGRAM_ID);
        // accounts: merchant (signer/readonly), channel (writable), instructions sysvar (readonly)
        expect(ix.accounts).toHaveLength(3);
        expect(ix.accounts[0]!.address).toBe(merchant.address);
        expect(ix.accounts[0]!.role).toBe(AccountRole.READONLY_SIGNER);
        expect(ix.accounts[1]!.address).toBe(channelId);
        expect(ix.accounts[1]!.role).toBe(AccountRole.WRITABLE);
        expect(ix.accounts[2]!.address).toBe(INSTRUCTIONS_SYSVAR_ADDRESS);
        expect(ix.accounts[2]!.role).toBe(AccountRole.READONLY);

        // data = [disc=4][voucher(48 zero)][hasVoucher=0] => 50 bytes
        // The voucher is read from the ed25519 precompile, so the data is just
        // [disc=4][hasVoucher=0] => 2 bytes.
        const data = new Uint8Array(ix.data);
        expect(data.byteLength).toBe(2);
        expect(data[0]).toBe(4);
        expect(data[data.byteLength - 1]).toBe(0);
    });

    test('voucher variant prepends an Ed25519 precompile IX', async () => {
        const [, , , , merchant] = await loadFixedSigners();
        const authorizedSignerSk = await generateKeyPairSigner();
        const channelId = '11111111111111111111111111111111';
        // Forge a SignedVoucher with a base58-encoded 64-byte signature
        // (content is opaque to this test — we only assert byte structure).
        const fixedSig = bs58Encode(new Uint8Array(64).fill(0xaa));
        const signed: SignedVoucher = {
            data: { channelId, cumulativeAmount: '500', expiresAt: 0 },
            signature: fixedSig,
        };

        const out = buildSettleAndFinalizeInstructions({
            channelId,
            merchantSigner: merchant,
            voucher: { authorizedSigner: authorizedSignerSk.address, signed },
        });
        expect(out.requiresEd25519Precompile).toBe(true);
        expect(out.instructions).toHaveLength(2);
        const precompile = out.instructions[0]!;
        expect(precompile.programAddress).toBe(ED25519_PROGRAM_ADDRESS);
        const settle = out.instructions[1]!;
        const data = new Uint8Array(settle.data);
        // Voucher lives in the precompile; settle data is [disc=4][hasVoucher=1].
        expect(data.byteLength).toBe(2);
        expect(data[0]).toBe(4);
        expect(data[data.byteLength - 1]).toBe(1);
    });
});

// ── top_up ──────────────────────────────────────────────────────────────────

describe('buildTopUpInstruction', () => {
    test('encodes discriminator + amount and lists 6 accounts', async () => {
        const [payer] = await loadFixedSigners();
        const channelId = '11111111111111111111111111111111';
        const ix = await buildTopUpInstruction({
            amount: 1_234_567n,
            channelId,
            mint: USDC.mainnet!,
            payer,
            tokenProgram: TOKEN_PROGRAM,
        });
        expect(ix.programAddress).toBe(PAYMENT_CHANNELS_PROGRAM_ID);
        expect(ix.accounts).toHaveLength(6);
        const data = new Uint8Array(ix.data);
        expect(data.byteLength).toBe(1 + 8);
        expect(data[0]).toBe(3); // discriminator
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        expect(view.getBigUint64(1, true)).toBe(1_234_567n);
    });
});

// ── distribute ──────────────────────────────────────────────────────────────

describe('buildDistributeInstruction', () => {
    test('appends one writable recipient ATA per split', async () => {
        const [payer, operator, payee] = await loadFixedSigners();
        const channelId = '11111111111111111111111111111111';
        const splitRecipient = address('HQyfh1JGDB47A6Az4MD9KgF9LqcL3ESCkN8AT9Y8atGD');
        const ix = await buildDistributeInstruction({
            channelState: { channelId, payee: payee.address, payer: payer.address },
            mint: USDC.mainnet!,
            rentPayer: operator.address,
            splits: [
                { bps: 1000, recipient: splitRecipient },
                { bps: 250, recipient: splitRecipient },
            ],
            tokenProgram: TOKEN_PROGRAM,
        });
        expect(ix.programAddress).toBe(PAYMENT_CHANNELS_PROGRAM_ID);
        // 11 fixed (after the rentPayer +1 shift) + 2 recipient ATAs
        expect(ix.accounts).toHaveLength(13);
        // tail accounts must be writable
        expect(ix.accounts[11]!.role).toBe(AccountRole.WRITABLE);
        expect(ix.accounts[12]!.role).toBe(AccountRole.WRITABLE);

        const data = new Uint8Array(ix.data);
        // [disc=7][recipients_count u32=2][(pubkey32 + bps u16) x 2]
        expect(data[0]).toBe(7);
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        expect(view.getUint32(1, true)).toBe(2);
        expect(view.getUint16(5 + 32, true)).toBe(1000);
        expect(view.getUint16(5 + 32 + 34, true)).toBe(250);
    });

    test('zero-split distribute has only 11 fixed accounts', async () => {
        const [payer, operator, payee] = await loadFixedSigners();
        const channelId = '11111111111111111111111111111111';
        const ix = await buildDistributeInstruction({
            channelState: { channelId, payee: payee.address, payer: payer.address },
            mint: USDC.mainnet!,
            rentPayer: operator.address,
            splits: [],
            tokenProgram: TOKEN_PROGRAM,
        });
        // 11 fixed accounts after the rentPayer (+1) shift.
        expect(ix.accounts).toHaveLength(11);
        const data = new Uint8Array(ix.data);
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        expect(view.getUint32(1, true)).toBe(0);
        expect(data.byteLength).toBe(1 + 4);
    });
});

// ── multi-delegator (hand-encoded) ─────────────────────────────────────────

describe('multi-delegator instructions', () => {
    test('init: discriminator 0x00, 6 accounts, system program at slot 4', async () => {
        const [user] = await loadFixedSigners();
        const ix = await buildMultiDelegatorInitInstruction({
            mint: USDC.mainnet!,
            tokenProgram: TOKEN_PROGRAM,
            user,
            userAta: '11111111111111111111111111111111',
        });
        expect(ix.programAddress).toBe(MULTI_DELEGATOR_PROGRAM_ID);
        expect(ix.accounts).toHaveLength(6);
        expect(ix.accounts[4]!.address).toBe('11111111111111111111111111111111');
        const data = new Uint8Array(ix.data);
        expect(data).toEqual(new Uint8Array([0x00]));
    });

    test('update: data = [0x01, nonce_le, amount_le, expiry_le] = 25 bytes', async () => {
        const [delegator] = await loadFixedSigners();
        const ix = await buildMultiDelegatorUpdateInstruction({
            amount: 1_000_000n,
            delegatee: '11111111111111111111111111111111',
            delegator,
            expiryTs: 0n,
            mint: USDC.mainnet!,
            nonce: 42n,
        });
        expect(ix.programAddress).toBe(MULTI_DELEGATOR_PROGRAM_ID);
        expect(ix.accounts).toHaveLength(5);
        const data = new Uint8Array(ix.data);
        expect(data.byteLength).toBe(25);
        expect(data[0]).toBe(0x01);
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        expect(view.getBigUint64(1, true)).toBe(42n);
        expect(view.getBigUint64(9, true)).toBe(1_000_000n);
        expect(view.getBigInt64(17, true)).toBe(0n);
    });
});

// ── verifyOpenTx ───────────────────────────────────────────────────────────

describe('verifyOpenTx', () => {
    async function buildClientOpen(payer: KeyPairSigner, payee: KeyPairSigner, authorizedSigner: KeyPairSigner) {
        const request: SessionRequest = {
            cap: '1000000',
            currency: USDC.mainnet!,
            decimals: 6,
            modes: ['pull'],
            network: 'localnet',
            operator: payer.address,
            pullVoucherStrategy: 'clientVoucher',
            recentBlockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as never,
            recipient: payee.address,
        };
        const open = await buildOpenPaymentChannelTransaction({
            authorizedSigner: authorizedSigner.address,
            deposit: 1_000_000n,
            gracePeriod: 900,
            programAddress: 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX',
            request,
            salt: 7n,
            signer: payer,
        });
        return { open, request };
    }

    test('accepts a freshly built open transaction', async () => {
        const [payer, , payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const result = await verifyOpenTx({
            expected: {
                authorizedSigner: authorizedSigner.address,
                currency: USDC.mainnet!,
                maxCap: 5_000_000n,
                network: 'localnet',
                operator: payer.address,
                programId: 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX',
                recipient: payee.address,
            },
            openPayload: {
                authorizedSigner: authorizedSigner.address,
                channelId: open.channelId,
                deposit: open.deposit,
                gracePeriod: open.gracePeriod,
                mint: open.mint,
                mode: 'pull',
                payee: open.payee,
                payer: open.payer,
                salt: open.salt,
                signature: '1'.repeat(88),
                transaction: open.transaction,
            },
        });
        expect(result.channelId).toBe(open.channelId);
        expect(result.deposit).toBe(1_000_000n);
        expect(result.gracePeriod).toBe(900);
        expect(result.salt).toBe(7n);
    });

    test('rejects an open transaction that uses address-lookup tables', async () => {
        const [payer, , payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        // Re-encode the open tx with a non-empty addressTableLookups entry so
        // the verifier sees a v0 message that resolves accounts via an ALT.
        const altTransaction = injectAddressTableLookup(open.transaction);
        await expect(
            verifyOpenTx({
                expected: {
                    authorizedSigner: authorizedSigner.address,
                    currency: USDC.mainnet!,
                    maxCap: 5_000_000n,
                    network: 'localnet',
                    operator: payer.address,
                    programId: 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX',
                    recipient: payee.address,
                },
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    channelId: open.channelId,
                    deposit: open.deposit,
                    gracePeriod: open.gracePeriod,
                    mint: open.mint,
                    mode: 'pull',
                    payee: open.payee,
                    payer: open.payer,
                    salt: open.salt,
                    signature: '1'.repeat(88),
                    transaction: altTransaction,
                },
            }),
        ).rejects.toThrow(/address-lookup tables are not permitted/);
    });

    test('rejects open whose deposit exceeds maxCap', async () => {
        const [payer, , payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        await expect(
            verifyOpenTx({
                expected: {
                    authorizedSigner: authorizedSigner.address,
                    currency: USDC.mainnet!,
                    maxCap: 500_000n,
                    network: 'localnet',
                    operator: payer.address,
                    programId: 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX',
                    recipient: payee.address,
                },
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    deposit: open.deposit,
                    gracePeriod: open.gracePeriod,
                    mint: open.mint,
                    mode: 'pull',
                    payee: open.payee,
                    payer: open.payer,
                    salt: open.salt,
                    signature: '1'.repeat(88),
                    transaction: open.transaction,
                },
            }),
        ).rejects.toThrow(/exceeds maxCap/);
    });

    test('rejects open with a mismatched payee', async () => {
        const [payer, , payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        await expect(
            verifyOpenTx({
                expected: {
                    authorizedSigner: authorizedSigner.address,
                    currency: USDC.mainnet!,
                    maxCap: 5_000_000n,
                    network: 'localnet',
                    operator: payer.address,
                    programId: 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX',
                    recipient: payer.address, // wrong: payer instead of payee
                },
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    deposit: open.deposit,
                    gracePeriod: open.gracePeriod,
                    mint: open.mint,
                    mode: 'pull',
                    payee: open.payee,
                    payer: open.payer,
                    salt: open.salt,
                    signature: '1'.repeat(88),
                    transaction: open.transaction,
                },
            }),
        ).rejects.toThrow(/payee/);
    });

    test('uses RPC to verify signature when one is supplied', async () => {
        const [payer, , payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);

        const calls: Signature[][] = [];
        const mockRpc = {
            getSignatureStatuses: (sigs: readonly Signature[]) => ({
                send: async () => {
                    calls.push([...sigs]);
                    return { value: [{ err: null }] };
                },
            }),
        };
        // The payload signature must be the transaction's own signature.
        const realSig = extractTxSignature(open.transaction);
        await verifyOpenTx({
            expected: {
                authorizedSigner: authorizedSigner.address,
                currency: USDC.mainnet!,
                maxCap: 5_000_000n,
                network: 'localnet',
                operator: payer.address,
                programId: 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX',
                recipient: payee.address,
            },
            openPayload: {
                authorizedSigner: authorizedSigner.address,
                deposit: open.deposit,
                gracePeriod: open.gracePeriod,
                mint: open.mint,
                mode: 'pull',
                payee: open.payee,
                payer: open.payer,
                salt: open.salt,
                signature: realSig,
                transaction: open.transaction,
            },
            rpc: mockRpc,
        });
        expect(calls).toHaveLength(1);
        expect(calls[0]).toEqual([realSig]);
    });

    test('surfaces RPC tx-failure as an error', async () => {
        const [payer, , payee, authorizedSigner] = await loadFixedSigners();
        const { open } = await buildClientOpen(payer, payee, authorizedSigner);
        const mockRpc = {
            getSignatureStatuses: () => ({
                send: async () => ({ value: [{ err: { InstructionError: [0, 'Custom'] } }] }),
            }),
        };
        const realSig = extractTxSignature(open.transaction);
        await expect(
            verifyOpenTx({
                expected: {
                    authorizedSigner: authorizedSigner.address,
                    currency: USDC.mainnet!,
                    maxCap: 5_000_000n,
                    network: 'localnet',
                    operator: payer.address,
                    programId: 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX',
                    recipient: payee.address,
                },
                openPayload: {
                    authorizedSigner: authorizedSigner.address,
                    deposit: open.deposit,
                    gracePeriod: open.gracePeriod,
                    mint: open.mint,
                    mode: 'pull',
                    payee: open.payee,
                    payer: open.payer,
                    salt: open.salt,
                    signature: realSig,
                    transaction: open.transaction,
                },
                rpc: mockRpc,
            }),
        ).rejects.toThrow(/failed on-chain/);
    });
});

// ── helpers ────────────────────────────────────────────────────────────────

/** Extract the first (fee-payer) signature of a base64-encoded transaction. */
function extractTxSignature(transactionBase64: string): Signature {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    return getSignatureFromTransaction(tx);
}

/**
 * Re-encode a base64 transaction with a synthetic, non-empty
 * `addressTableLookups` entry so `verifyOpenTx` exercises its ALT guard.
 * The lookup itself need not resolve to real accounts — the guard fires on
 * a non-empty lookup list, before any account resolution.
 */
function injectAddressTableLookup(transactionBase64: string): string {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    const message = getCompiledTransactionMessageDecoder().decode(tx.messageBytes) as Record<string, unknown>;
    const lookupTableAddress = '11111111111111111111111111111111';
    const withAlt = {
        ...message,
        // Force a v0 message and attach one lookup that pulls in a writable
        // and a readonly index from a (fake) table.
        version: 0,
        addressTableLookups: [
            {
                lookupTableAddress: address(lookupTableAddress),
                readonlyIndexes: [1],
                writableIndexes: [0],
            },
        ],
    };
    const messageBytes = new Uint8Array(getCompiledTransactionMessageEncoder().encode(withAlt as never));
    const rebuilt = getTransactionEncoder().encode({ ...tx, messageBytes } as never);
    return getBase64Codec().decode(new Uint8Array(rebuilt));
}

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
