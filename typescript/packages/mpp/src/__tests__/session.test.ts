import {
    generateKeyPairSigner,
    getBase58Encoder,
    signatureBytes,
    verifySignature,
    type KeyPairSigner,
} from '@solana/kit';
import { Credential } from 'mppx';

import {
    ActiveSession,
    DEFAULT_SESSION_EXPIRES_AT,
    serializeSessionCredential,
    session,
    type SessionAction,
    type SessionChallenge,
    type SessionRequest,
    voucherMessageBytes,
} from '../client/Session.js';

function request(overrides: Partial<SessionRequest> = {}): SessionRequest {
    return {
        cap: '1000000',
        currency: 'USDC',
        operator: 'operator111111111111111111111111111111111',
        recipient: 'recipient11111111111111111111111111111111',
        ...overrides,
    };
}

function challenge(overrides: Partial<SessionRequest> = {}): SessionChallenge {
    return {
        id: 'challenge-1',
        intent: 'session',
        method: 'solana',
        realm: 'api.test',
        request: request(overrides),
    };
}

async function makeSession(options: ActiveSession.Options = {}): Promise<{
    channel: KeyPairSigner;
    session: ActiveSession;
    signer: KeyPairSigner;
}> {
    const signer = await generateKeyPairSigner();
    const channel = await generateKeyPairSigner();
    return {
        channel,
        session: new ActiveSession({ channelId: channel.address, signer, ...options }),
        signer,
    };
}

describe('voucherMessageBytes', () => {
    test('uses the payment-channel voucher byte layout', async () => {
        const channel = await generateKeyPairSigner();
        const bytes = voucherMessageBytes({
            channelId: channel.address,
            cumulativeAmount: '513',
            expiresAt: '42',
        });

        expect(bytes.byteLength).toBe(48);
        expect(bytes.slice(0, 32)).toEqual(getBase58Encoder().encode(channel.address));
        expect(new DataView(bytes.buffer, bytes.byteOffset + 32, 8).getBigUint64(0, true)).toBe(513n);
        expect(new DataView(bytes.buffer, bytes.byteOffset + 40, 8).getBigInt64(0, true)).toBe(42n);
    });

    test('accepts the Rust cumulative alias and validates integer inputs', async () => {
        const channel = await generateKeyPairSigner();
        expect(
            voucherMessageBytes({
                channelId: channel.address,
                cumulative: 7n,
                expiresAt: DEFAULT_SESSION_EXPIRES_AT,
            }),
        ).toHaveLength(48);

        expect(() =>
            voucherMessageBytes({
                channelId: channel.address,
                cumulativeAmount: '1.5',
                expiresAt: DEFAULT_SESSION_EXPIRES_AT,
            }),
        ).toThrow('cumulativeAmount must be an integer string');
    });
});

describe('ActiveSession', () => {
    test('prepares a valid signature without advancing local state', async () => {
        const { session: activeSession, signer } = await makeSession({ expiresAt: 1234 });

        const voucher = await activeSession.prepareIncrement(25);

        expect(activeSession.cumulative).toBe(0n);
        expect(voucher.data).toMatchObject({
            channelId: activeSession.channelId,
            cumulativeAmount: '25',
            expiresAt: 1234,
            nonce: 1,
        });
        await expect(
            verifySignature(
                signer.keyPair.publicKey,
                signatureBytes(getBase58Encoder().encode(voucher.signature)),
                voucherMessageBytes(voucher.data),
            ),
        ).resolves.toBe(true);
    });

    test('records, signs, and rejects non-increasing vouchers', async () => {
        const { session: activeSession } = await makeSession();
        const prepared = await activeSession.prepareIncrement('75');

        activeSession.recordVoucher(prepared);
        expect(activeSession.cumulativeAmount).toBe('75');
        expect(activeSession.nonce).toBe(1);

        await expect(activeSession.signVoucher(75)).rejects.toThrow('must exceed current watermark');
        await expect(activeSession.signIncrement(25)).resolves.toMatchObject({
            data: { cumulativeAmount: '100', nonce: 2 },
        });
        expect(() => activeSession.recordVoucher(prepared)).toThrow('must exceed current watermark');
    });

    test('controls expiry and validates channel while recording', async () => {
        const { session: activeSession } = await makeSession({ expiresAt: 55 });
        expect((await activeSession.prepareIncrement(1)).data.expiresAt).toBe(55);

        activeSession.setExpiresAt(66);
        expect((await activeSession.prepareIncrement(1)).data.expiresAt).toBe(66);

        const other = await generateKeyPairSigner();
        const prepared = await activeSession.prepareIncrement(2);
        expect(() =>
            activeSession.recordVoucher({
                ...prepared,
                data: { ...prepared.data, channelId: other.address },
            }),
        ).toThrow('does not match active session');
    });

    test('builds all session action payloads', async () => {
        const { session: activeSession } = await makeSession();

        expect(activeSession.openAction(1_000_000, 'open-sig')).toMatchObject({
            action: 'open',
            channelId: activeSession.channelId,
            deposit: '1000000',
            mode: 'push',
            signature: 'open-sig',
        });

        expect(
            activeSession.openPaymentChannelAction({
                deposit: 9_000,
                gracePeriod: 60,
                mint: 'mint',
                payer: 'payer',
                payee: 'payee',
                salt: 42,
                signature: 'open-sig',
                transaction: 'tx-base64',
            }),
        ).toMatchObject({
            action: 'open',
            gracePeriod: 60,
            mint: 'mint',
            mode: 'push',
            payer: 'payer',
            payee: 'payee',
            salt: '42',
            transaction: 'tx-base64',
        });

        expect(
            activeSession.openAction(1_000_000, 'pending', { mode: 'pull', transaction: 'tx-base64' }),
        ).toMatchObject({
            action: 'open',
            channelId: activeSession.channelId,
            deposit: '1000000',
            mode: 'pull',
            transaction: 'tx-base64',
        });

        expect(
            activeSession.openPullAction({
                approvedAmount: '500',
                initMultiDelegateTx: 'init',
                owner: 'owner',
                signature: 'approve-sig',
                updateDelegationTx: 'update',
            }),
        ).toMatchObject({
            action: 'open',
            approvedAmount: '500',
            initMultiDelegateTx: 'init',
            mode: 'pull',
            owner: 'owner',
            tokenAccount: activeSession.channelId,
            updateDelegationTx: 'update',
        });

        expect(activeSession.topUpAction(2_000, 'topup-sig')).toMatchObject({
            action: 'topUp',
            newDeposit: '2000',
            signature: 'topup-sig',
        });
        await expect(activeSession.closeAction()).resolves.toEqual({
            action: 'close',
            channelId: activeSession.channelId,
        });
        await expect(activeSession.closeAction(3)).resolves.toMatchObject({
            action: 'close',
            voucher: { data: { cumulativeAmount: '3' } },
        });
    });

    test('constructor overload initializes from channel and signer', async () => {
        const signer = await generateKeyPairSigner();
        const channel = await generateKeyPairSigner();
        const activeSession = new ActiveSession(channel.address, signer, {
            cumulative: 10,
            expiresAt: 123,
            nonce: 4,
        });

        expect(activeSession.channelId).toBe(channel.address);
        expect(activeSession.signer).toBe(signer);
        expect(activeSession.authorizedSigner).toBe(signer.address);
        expect(activeSession.cumulativeAmount).toBe('10');
        expect(activeSession.expiresAt).toBe(123);
        expect(activeSession.nonce).toBe(4);
    });

    test('validates low-level integer bounds', async () => {
        const channel = await generateKeyPairSigner();
        await expect(makeSession({ expiresAt: Number.MAX_SAFE_INTEGER + 1 })).rejects.toThrow(
            'expiresAt must be a safe integer',
        );
        expect(() =>
            voucherMessageBytes({
                channelId: channel.address,
                expiresAt: DEFAULT_SESSION_EXPIRES_AT,
            }),
        ).toThrow('cumulativeAmount required');
        expect(() =>
            voucherMessageBytes({
                channelId: channel.address,
                cumulativeAmount: -1,
                expiresAt: DEFAULT_SESSION_EXPIRES_AT,
            }),
        ).toThrow('cumulativeAmount must be non-negative');
        expect(() =>
            voucherMessageBytes({
                channelId: channel.address,
                cumulativeAmount: 1n << 64n,
                expiresAt: DEFAULT_SESSION_EXPIRES_AT,
            }),
        ).toThrow('cumulativeAmount exceeds u64 max');
    });
});

describe('session client method', () => {
    test('serializes voucher credentials from context', async () => {
        const { session: activeSession } = await makeSession();
        const method = session({ session: activeSession, source: 'did:pkh:solana:test' });

        const credential = await method.createCredential({
            challenge: challenge(),
            context: { action: 'voucher', amount: 33 },
        });
        const decoded = Credential.deserialize<SessionAction>(credential);

        expect(decoded.source).toBe('did:pkh:solana:test');
        expect(decoded.payload).toMatchObject({
            action: 'voucher',
            voucher: { data: { cumulativeAmount: '33' } },
        });
    });

    test('serializes open, pull, commit, top-up, and close actions', async () => {
        const { session: activeSession } = await makeSession();
        const method = session({ session: activeSession });

        await expect(
            method.createCredential({
                challenge: challenge(),
                context: { action: 'open', deposit: 100, signature: 'open-sig' },
            }),
        ).resolves.toContain('Payment ');

        const pullCredential = await method.createCredential({
            challenge: challenge({ modes: ['pull'] }),
            context: { action: 'open', owner: 'owner', signature: 'approve-sig' },
        });
        expect(Credential.deserialize<SessionAction>(pullCredential).payload).toMatchObject({
            action: 'open',
            approvedAmount: '1000000',
            mode: 'pull',
        });

        const clientVoucherPullCredential = await method.createCredential({
            challenge: challenge({ modes: ['pull'], pullVoucherStrategy: 'clientVoucher' }),
            context: { action: 'open', signature: 'pending', transaction: 'tx-base64' },
        });
        expect(Credential.deserialize<SessionAction>(clientVoucherPullCredential).payload).toMatchObject({
            action: 'open',
            channelId: activeSession.channelId,
            deposit: '1000000',
            mode: 'pull',
            transaction: 'tx-base64',
        });

        const detailedOpen = Credential.deserialize<SessionAction>(
            await method.createCredential({
                challenge: challenge(),
                context: {
                    action: 'open',
                    deposit: 100,
                    gracePeriod: 60,
                    mint: 'mint',
                    payee: 'payee',
                    payer: 'payer',
                    salt: (1n << 64n) - 7n,
                    signature: 'open-sig',
                },
            }),
        ).payload;
        expect(detailedOpen).toMatchObject({
            action: 'open',
            salt: '18446744073709551609',
        });

        const commitCredential = await method.createCredential({
            challenge: challenge(),
            context: {
                action: 'commit',
                directive: {
                    amount: '44',
                    currency: 'USDC',
                    deliveryId: 'delivery-1',
                    expiresAt: DEFAULT_SESSION_EXPIRES_AT,
                    sequence: 1,
                    sessionId: activeSession.channelId,
                },
            },
        });
        expect(Credential.deserialize<SessionAction>(commitCredential).payload).toMatchObject({
            action: 'commit',
            deliveryId: 'delivery-1',
            voucher: { data: { cumulativeAmount: '44' } },
        });

        const topUp = Credential.deserialize<SessionAction>(
            await method.createCredential({
                challenge: challenge(),
                context: { action: 'topUp', newDeposit: '9000', signature: 'topup-sig' },
            }),
        ).payload;
        expect(topUp).toMatchObject({ action: 'topUp', newDeposit: '9000' });

        const close = Credential.deserialize<SessionAction>(
            await method.createCredential({
                challenge: challenge(),
                context: { action: 'close', finalIncrement: 1 },
            }),
        ).payload;
        expect(close).toMatchObject({ action: 'close', voucher: { data: { cumulativeAmount: '45' } } });
    });

    test('supports parameter-created sessions and voucher context variants', async () => {
        const signer = await generateKeyPairSigner();
        const channel = await generateKeyPairSigner();
        const method = session({ channelId: channel.address, signer });

        const absolute = Credential.deserialize<SessionAction>(
            await method.createCredential({
                challenge: challenge(),
                context: { action: 'voucher', cumulativeAmount: 20 },
            }),
        ).payload;
        expect(absolute).toMatchObject({ action: 'voucher', voucher: { data: { cumulativeAmount: '20' } } });
        if (absolute.action !== 'voucher') throw new Error('expected voucher action');

        const replay = Credential.deserialize<SessionAction>(
            await method.createCredential({
                challenge: challenge(),
                context: { action: 'voucher', voucher: absolute.voucher },
            }),
        ).payload;
        expect(replay).toEqual({ action: 'voucher', voucher: absolute.voucher });
    });

    test('supports custom action creation and direct serialization helper', async () => {
        const { channel } = await makeSession();
        const method = session({
            createAction: () => ({ action: 'close', channelId: channel.address }),
        });

        const credential = await method.createCredential({ challenge: challenge(), context: {} });
        expect(Credential.deserialize<SessionAction>(credential).payload).toEqual({
            action: 'close',
            channelId: channel.address,
        });

        expect(
            Credential.deserialize<SessionAction>(
                serializeSessionCredential({
                    challenge: challenge(),
                    payload: { action: 'close', channelId: channel.address },
                }),
            ).payload,
        ).toEqual({ action: 'close', channelId: channel.address });
    });

    test('throws helpful errors when context is incomplete', async () => {
        const { session: activeSession } = await makeSession();
        const method = session({ session: activeSession });

        await expect(method.createCredential({ challenge: challenge(), context: {} })).rejects.toThrow(
            'No session action provided',
        );
        await expect(
            method.createCredential({
                challenge: challenge(),
                context: { action: 'commit' },
            }),
        ).rejects.toThrow('deliveryId required');
        await expect(
            method.createCredential({
                challenge: challenge(),
                context: { action: 'open', payer: 'payer', signature: 'sig' },
            }),
        ).rejects.toThrow('gracePeriod required');

        await expect(
            session().createCredential({
                challenge: challenge(),
                context: { action: 'voucher', amount: 1 },
            }),
        ).rejects.toThrow('session action requires an ActiveSession');
    });
});
