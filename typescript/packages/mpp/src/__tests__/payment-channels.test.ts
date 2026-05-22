import {
    generateKeyPairSigner,
    getBase64Codec,
    getCompiledTransactionMessageDecoder,
    getTransactionDecoder,
    type Blockhash,
} from '@solana/kit';
import { expect, test } from 'vitest';

import {
    buildOpenPaymentChannelTransaction,
    createPaymentChannelSessionOpener,
    createServerOpenedPaymentChannelSessionOpener,
    derivePaymentChannelOpen,
} from '../client/PaymentChannels.js';
import { TOKEN_PROGRAM, USDC } from '../constants.js';
import type { SessionChallenge, SessionRequest } from '../client/Session.js';

const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash;
const PAYMENT_CHANNELS_PROGRAM = 'GuoKrzaBiZnW5DvJ3yZVE7xHqbcBvaX9SH6P6Cn9gNvc';

type TestCompiledMessage = {
    instructions: readonly { data: Uint8Array; programAddressIndex: number }[];
    staticAccounts: readonly { toString(): string }[];
};

test('buildOpenPaymentChannelTransaction creates a single partially signed open transaction', async () => {
    const [payer, operator, payee, authorizedSigner, platform] = await Promise.all([
        generateKeyPairSigner(),
        generateKeyPairSigner(),
        generateKeyPairSigner(),
        generateKeyPairSigner(),
        generateKeyPairSigner(),
    ]);
    const request = sessionRequest({
        operator: operator.address,
        recipient: payee.address,
        splits: [{ bps: 10, recipient: platform.address }],
    });

    const open = await buildOpenPaymentChannelTransaction({
        authorizedSigner: authorizedSigner.address,
        gracePeriod: 900,
        request,
        salt: 42n,
        signer: payer,
    });

    expect(open.deposit).toBe(request.cap);
    expect(open.gracePeriod).toBe(900);
    expect(open.mint).toBe(USDC.mainnet);
    expect(open.payee).toBe(payee.address);
    expect(open.payer).toBe(payer.address);
    expect(open.salt).toBe('42');
    expect(open.channelId).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/);

    const decoded = getTransactionDecoder().decode(getBase64Codec().encode(open.transaction));
    expect(decoded.signatures[payer.address]).toBeTruthy();
    expect(decoded.signatures[operator.address]).toBeNull();

    const message = getCompiledTransactionMessageDecoder().decode(
        decoded.messageBytes,
    ) as unknown as TestCompiledMessage;
    expect(message.instructions).toHaveLength(1);
    expect(message.staticAccounts[message.instructions[0].programAddressIndex].toString()).toBe(
        PAYMENT_CHANNELS_PROGRAM,
    );
    expect(message.instructions[0].data[0]).toBe(1);
});

test('createPaymentChannelSessionOpener emits a pull client-voucher payment-channel open action', async () => {
    const [payer, operator, payee, platform] = await Promise.all([
        generateKeyPairSigner(),
        generateKeyPairSigner(),
        generateKeyPairSigner(),
        generateKeyPairSigner(),
    ]);
    const opener = createPaymentChannelSessionOpener({
        gracePeriod: 60,
        salt: 7n,
        signer: payer,
        source: 'demo-session',
    });

    const result = await opener({
        challenge: sessionChallenge(
            sessionRequest({
                operator: operator.address,
                recipient: payee.address,
                splits: [{ bps: 10, recipient: platform.address }],
            }),
        ),
        input: 'https://example.com/v1/stream',
        response: new Response(null, { status: 402 }),
    });

    expect(result.source).toBe('demo-session');
    expect(result.payload).toMatchObject({
        action: 'open',
        deposit: '1000000',
        gracePeriod: 60,
        mint: USDC.mainnet,
        mode: 'pull',
        payee: payee.address,
        payer: payer.address,
        salt: '7',
    });
    expect(result.payload.channelId).toBe(result.session.channelId);
    expect(result.payload.authorizedSigner).toBe(result.session.authorizedSigner);
    expect(result.payload.transaction).toEqual(expect.any(String));
    expect(result.payload.tokenAccount).toBeUndefined();
    expect(result.payload.approvedAmount).toBeUndefined();
});

test('createServerOpenedPaymentChannelSessionOpener emits channel fields without a transaction', async () => {
    const [operator, payee, sessionSigner] = await Promise.all([
        generateKeyPairSigner(),
        generateKeyPairSigner(),
        generateKeyPairSigner(),
    ]);
    const request = sessionRequest({
        operator: operator.address,
        recipient: payee.address,
    });
    const opener = createServerOpenedPaymentChannelSessionOpener({
        salt: 11n,
        sessionSigner,
        source: 'demo-session',
    });

    const result = await opener({
        challenge: sessionChallenge(request),
        input: 'https://example.com/v1/stream',
        response: new Response(null, { status: 402 }),
    });
    const open = await derivePaymentChannelOpen({
        authorizedSigner: sessionSigner.address,
        payer: operator.address,
        request,
        salt: 11n,
    });

    expect(result.source).toBe('demo-session');
    expect(result.payload).toMatchObject({
        action: 'open',
        channelId: open.channelId,
        deposit: request.cap,
        mint: USDC.mainnet,
        mode: 'pull',
        payee: payee.address,
        payer: operator.address,
        salt: '11',
    });
    expect(result.payload.channelId).toBe(result.session.channelId);
    expect(result.payload.authorizedSigner).toBe(sessionSigner.address);
    expect(result.payload.transaction).toBeUndefined();
    expect(result.payload.tokenAccount).toBeUndefined();
    expect(result.payload.approvedAmount).toBeUndefined();
});

test('createPaymentChannelSessionOpener rejects operated-voucher pull challenges', async () => {
    const [payer, operator, payee] = await Promise.all([
        generateKeyPairSigner(),
        generateKeyPairSigner(),
        generateKeyPairSigner(),
    ]);
    const opener = createPaymentChannelSessionOpener({ signer: payer });

    await expect(
        opener({
            challenge: sessionChallenge(
                sessionRequest({
                    operator: operator.address,
                    pullVoucherStrategy: 'operatedVoucher',
                    recipient: payee.address,
                }),
            ),
            input: 'https://example.com/v1/stream',
            response: new Response(null, { status: 402 }),
        }),
    ).rejects.toThrow('pullVoucherStrategy=clientVoucher');
});

function sessionRequest(
    overrides: Partial<SessionRequest> & Pick<SessionRequest, 'operator' | 'recipient'>,
): SessionRequest {
    return {
        cap: '1000000',
        currency: USDC.mainnet,
        decimals: 6,
        modes: ['pull'],
        network: 'localnet',
        pullVoucherStrategy: 'clientVoucher',
        recentBlockhash: BLOCKHASH,
        splits: [],
        ...overrides,
    };
}

function sessionChallenge(request: SessionRequest): SessionChallenge {
    return {
        id: 'challenge-id',
        intent: 'session',
        method: 'solana',
        realm: 'test',
        request,
    };
}
