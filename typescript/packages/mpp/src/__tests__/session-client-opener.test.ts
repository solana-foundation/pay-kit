import {
    createKeyPairSignerFromPrivateKeyBytes,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getTransactionDecoder,
} from '@solana/kit';
import { describe, expect, test } from 'vitest';

import {
    createEphemeralSessionOpener,
    deriveDelegatedTokenAccount,
    PENDING_SERVER_SIGNATURE,
    type SessionChallenge,
} from '../client/index.js';
import { PYUSD, TOKEN_2022_PROGRAM, USDC } from '../constants.js';

const recipient = 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY';
const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';

function sessionChallenge(overrides: Partial<SessionChallenge['request']> = {}): SessionChallenge {
    return {
        id: 'opener-test',
        intent: 'session',
        method: 'solana',
        realm: 'test',
        request: {
            cap: '1000000',
            currency: 'USDC',
            decimals: 6,
            network: 'localnet',
            operator: recipient,
            recipient,
            ...overrides,
        },
    };
}

function openerParameters(challenge: SessionChallenge) {
    return {
        challenge,
        init: undefined,
        input: 'https://api.test/v1/work',
        response: new Response(null, { status: 402 }),
    };
}

async function makeWallet() {
    const seed = new Uint8Array(32);
    seed.fill(0x11);
    return await createKeyPairSignerFromPrivateKeyBytes(seed);
}

describe('createEphemeralSessionOpener mode selection', () => {
    test('downgrades an unsupported pull request to push', async () => {
        const opener = createEphemeralSessionOpener({ mode: 'pull' });
        const result = await opener(openerParameters(sessionChallenge({ modes: ['push'] })));
        expect(result.payload.mode).toBe('push');
        expect(result.payload.initMultiDelegateTx).toBeUndefined();
    });

    test('treats an empty modes array as push-only', async () => {
        const opener = createEphemeralSessionOpener({ mode: 'pull' });
        const result = await opener(openerParameters(sessionChallenge({ modes: [] })));
        expect(result.payload.mode).toBe('push');
    });

    test('keeps pull when the challenge advertises it', async () => {
        const opener = createEphemeralSessionOpener({ mode: 'pull' });
        const result = await opener(openerParameters(sessionChallenge({ modes: ['pull'] })));
        expect(result.payload.mode).toBe('pull');
    });
});

describe('createEphemeralSessionOpener delegated pull', () => {
    test('refuses delegated pull without a signer and recent blockhash', async () => {
        const opener = createEphemeralSessionOpener({ mode: 'pull' });
        const challenge = sessionChallenge({ modes: ['pull'], pullVoucherStrategy: 'operatedVoucher' });
        await expect(opener(openerParameters(challenge))).rejects.toThrow(
            'pull-mode session open requires a wallet signer and a recent blockhash',
        );
    });

    test('refuses delegated pull when only a signer is available', async () => {
        const wallet = await makeWallet();
        const opener = createEphemeralSessionOpener({ mode: 'pull', signer: wallet });
        const challenge = sessionChallenge({ modes: ['pull'], pullVoucherStrategy: 'operatedVoucher' });
        await expect(opener(openerParameters(challenge))).rejects.toThrow(
            'pull-mode session open requires a wallet signer and a recent blockhash',
        );
    });

    test('builds real pre-signed multi-delegate transactions from the challenge', async () => {
        const wallet = await makeWallet();
        const opener = createEphemeralSessionOpener({ mode: 'pull', signer: wallet });
        const challenge = sessionChallenge({
            modes: ['pull'],
            pullVoucherStrategy: 'operatedVoucher',
            recentBlockhash: BLOCKHASH,
        });
        const result = await opener(openerParameters(challenge));
        const expectedTokenAccount = await deriveDelegatedTokenAccount({
            mint: USDC.mainnet!,
            owner: wallet.address,
            tokenProgram: 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
        });

        expect(result.payload.mode).toBe('pull');
        expect(result.payload.owner).toBe(wallet.address);
        expect(result.payload.signature).toBe(PENDING_SERVER_SIGNATURE);
        expect(result.payload.approvedAmount).toBe('1000000');
        expect(result.payload.tokenAccount).toBe(expectedTokenAccount);
        // Vouchers bind to the delegated token account, mirroring the Rust client.
        expect(result.session.channelId).toBe(expectedTokenAccount);

        const initTx = decodeTx(result.payload.initMultiDelegateTx!);
        expect(initTx.version).toBe('legacy');
        expect(initTx.lifetimeToken).toBe(BLOCKHASH);
        expect(initTx.staticAccounts[0]).toBe(wallet.address);
        expect(initTx.instructions).toHaveLength(2);

        const updateTx = decodeTx(result.payload.updateDelegationTx!);
        expect(updateTx.instructions).toHaveLength(1);
    });

    test('uses Token-2022 token accounts for PYUSD challenges', async () => {
        const wallet = await makeWallet();
        const opener = createEphemeralSessionOpener({ mode: 'pull', signer: wallet });
        const challenge = sessionChallenge({
            currency: 'PYUSD',
            modes: ['pull'],
            network: 'mainnet',
            pullVoucherStrategy: 'operatedVoucher',
            recentBlockhash: BLOCKHASH,
        });
        const result = await opener(openerParameters(challenge));
        const expectedTokenAccount = await deriveDelegatedTokenAccount({
            mint: PYUSD.mainnet!,
            owner: wallet.address,
            tokenProgram: TOKEN_2022_PROGRAM,
        });
        expect(result.payload.tokenAccount).toBe(expectedTokenAccount);
        const initTx = decodeTx(result.payload.initMultiDelegateTx!);
        expect(initTx.staticAccounts).toContain(TOKEN_2022_PROGRAM);
    });
});

type TestCompiledMessage = {
    instructions: readonly { data?: Uint8Array }[];
    lifetimeToken: string;
    staticAccounts: readonly string[];
    version: number | 'legacy';
};

function decodeTx(wire: string): TestCompiledMessage {
    const decoded = getTransactionDecoder().decode(getBase64Codec().encode(wire));
    return getCompiledTransactionMessageDecoder().decode(decoded.messageBytes) as unknown as TestCompiledMessage;
}
