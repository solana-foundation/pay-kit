import {
    AccountRole,
    createKeyPairSignerFromPrivateKeyBytes,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getTransactionDecoder,
} from '@solana/kit';
import { describe, expect, test } from 'vitest';

import {
    buildCreateFixedDelegationInstruction,
    buildInitMultiDelegateInstruction,
    buildInitMultiDelegateTx,
    buildUpdateDelegationTx,
    findFixedDelegationPda,
    findMultiDelegatePda,
    MULTI_DELEGATOR_PROGRAM,
} from '../client/MultiDelegate.js';
import { SYSTEM_PROGRAM, TOKEN_PROGRAM } from '../constants.js';

/**
 * Golden values produced by the Rust builders in
 * `rust/crates/mpp/src/program/multi_delegator.rs` for the fixed inputs below
 * (PDAs printed with `Pubkey::find_program_address` over the same seeds, data
 * from `build_create_fixed_delegation_ix`).
 */
const USER = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const OPERATOR = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY';
const USER_ATA = 'HQyfh1JGDB47A6Az4MD9KgF9LqcL3ESCkN8AT9Y8atGD';
const NONCE = 7n;
const AMOUNT = 5_000_000n;
const EXPIRY_TS = 1_893_456_000n;

const GOLDEN_MULTI_DELEGATE_PDA = '4Kec2toEvHUVe4cL2qfYWWF9kjZR2KQgVbqBsV6knN43';
const GOLDEN_DELEGATION_PDA = '5D87dmF88e48D9mugMedLo21BEBajd6JWyn1Q85gpTmB';
const GOLDEN_CREATE_DATA_HEX = '010700000000000000404b4c000000000080d8db7000000000';

const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';

describe('multi-delegate PDAs', () => {
    test('MultiDelegate PDA matches the Rust derivation', async () => {
        await expect(findMultiDelegatePda({ mint: MINT, user: USER })).resolves.toBe(GOLDEN_MULTI_DELEGATE_PDA);
    });

    test('FixedDelegation PDA matches the Rust derivation', async () => {
        await expect(
            findFixedDelegationPda({
                delegatee: OPERATOR,
                delegator: USER,
                multiDelegate: GOLDEN_MULTI_DELEGATE_PDA,
                nonce: NONCE,
            }),
        ).resolves.toBe(GOLDEN_DELEGATION_PDA);
    });
});

describe('multi-delegate instructions', () => {
    test('InitMultiDelegate matches the Rust builder byte-for-byte', async () => {
        const instruction = await buildInitMultiDelegateInstruction({
            mint: MINT,
            tokenProgram: TOKEN_PROGRAM,
            user: USER,
            userAta: USER_ATA,
        });

        expect(instruction.programAddress).toBe(MULTI_DELEGATOR_PROGRAM);
        expect(Buffer.from(instruction.data).toString('hex')).toBe('00');
        expect(instruction.accounts.map(account => [account.address, account.role])).toEqual([
            [USER, AccountRole.WRITABLE_SIGNER],
            [GOLDEN_MULTI_DELEGATE_PDA, AccountRole.WRITABLE],
            [MINT, AccountRole.READONLY],
            [USER_ATA, AccountRole.WRITABLE],
            [SYSTEM_PROGRAM, AccountRole.READONLY],
            [TOKEN_PROGRAM, AccountRole.READONLY],
        ]);
    });

    test('CreateFixedDelegation matches the Rust builder byte-for-byte', async () => {
        const instruction = await buildCreateFixedDelegationInstruction({
            amount: AMOUNT,
            delegatee: OPERATOR,
            delegator: USER,
            expiryTs: EXPIRY_TS,
            mint: MINT,
            nonce: NONCE,
        });

        expect(instruction.programAddress).toBe(MULTI_DELEGATOR_PROGRAM);
        expect(Buffer.from(instruction.data).toString('hex')).toBe(GOLDEN_CREATE_DATA_HEX);
        expect(instruction.accounts.map(account => [account.address, account.role])).toEqual([
            [USER, AccountRole.WRITABLE_SIGNER],
            [GOLDEN_MULTI_DELEGATE_PDA, AccountRole.READONLY],
            [GOLDEN_DELEGATION_PDA, AccountRole.WRITABLE],
            [OPERATOR, AccountRole.READONLY],
            [SYSTEM_PROGRAM, AccountRole.READONLY],
        ]);
    });
});

describe('multi-delegate transactions', () => {
    async function makeSigner() {
        const seed = new Uint8Array(32);
        seed.fill(0x2a);
        return await createKeyPairSignerFromPrivateKeyBytes(seed);
    }

    type TestCompiledMessage = {
        header: { numSignerAccounts: number };
        instructions: readonly { data?: Uint8Array }[];
        lifetimeToken: string;
        staticAccounts: readonly string[];
        version: number | 'legacy';
    };

    function decodeWireTransaction(wire: string) {
        const decoded = getTransactionDecoder().decode(getBase64Codec().encode(wire));
        const message = getCompiledTransactionMessageDecoder().decode(
            decoded.messageBytes,
        ) as unknown as TestCompiledMessage;
        return { message, signatures: decoded.signatures };
    }

    test('buildInitMultiDelegateTx signs a legacy user-fee-payer transaction with init + create', async () => {
        const signer = await makeSigner();
        const wire = await buildInitMultiDelegateTx({
            amount: AMOUNT,
            expiryTs: EXPIRY_TS,
            mint: MINT,
            nonce: NONCE,
            operator: OPERATOR,
            recentBlockhash: BLOCKHASH,
            signer,
            tokenProgram: TOKEN_PROGRAM,
            userAta: USER_ATA,
        });

        const { message, signatures } = decodeWireTransaction(wire);
        expect(message.version).toBe('legacy');
        expect(message.lifetimeToken).toBe(BLOCKHASH);
        expect(message.staticAccounts[0]).toBe(signer.address);
        expect(message.header.numSignerAccounts).toBe(1);
        expect(message.instructions).toHaveLength(2);
        expect(Buffer.from(message.instructions[0]!.data ?? new Uint8Array()).toString('hex')).toBe('00');
        const createData = message.instructions[1]!.data ?? new Uint8Array();
        expect(Buffer.from(createData).toString('hex')).toBe(GOLDEN_CREATE_DATA_HEX);
        expect(Object.keys(signatures)).toEqual([signer.address]);
        expect(signatures[signer.address]).not.toBeNull();
    });

    test('buildUpdateDelegationTx signs a single create-fixed-delegation transaction', async () => {
        const signer = await makeSigner();
        const wire = await buildUpdateDelegationTx({
            amount: AMOUNT,
            expiryTs: EXPIRY_TS,
            mint: MINT,
            nonce: NONCE,
            operator: OPERATOR,
            recentBlockhash: BLOCKHASH,
            signer,
            tokenProgram: TOKEN_PROGRAM,
        });

        const { message } = decodeWireTransaction(wire);
        expect(message.version).toBe('legacy');
        expect(message.instructions).toHaveLength(1);
        expect(Buffer.from(message.instructions[0]!.data ?? new Uint8Array()).toString('hex')).toBe(
            GOLDEN_CREATE_DATA_HEX,
        );
    });
});
