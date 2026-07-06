/**
 * Branch-coverage tests for the payment-channels client builders
 * (client/PaymentChannels.ts).
 *
 * payment-channels.test.ts covers the mainline builds. This suite fills the
 * remaining branches:
 *   - the two openers' modes / pullVoucherStrategy rejections
 *   - the server-opened opener's payer fallback (parameters.payer vs
 *     challenge.request.operator)
 *   - preparePaymentChannelOpen's non-SPL-currency error and network default
 *   - the parseU64 amount-parsing branches (number, unsafe integer,
 *     malformed string) via the `deposit`/`salt` inputs
 *   - randomU64 (default salt) via derivePaymentChannelOpen without a salt
 */
import { generateKeyPairSigner, type Blockhash } from '@solana/kit';
import { describe, expect, test } from 'vitest';

import {
    buildOpenPaymentChannelTransaction,
    createPaymentChannelSessionOpener,
    createServerOpenedPaymentChannelSessionOpener,
    derivePaymentChannelOpen,
} from '../client/PaymentChannels.js';
import type { SessionChallenge, SessionRequest } from '../client/Session.js';
import { USDC } from '../constants.js';

const BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash;

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

// ── createPaymentChannelSessionOpener rejections ─────────────────────────

describe('createPaymentChannelSessionOpener', () => {
    test('rejects a challenge that does not advertise pull mode', async () => {
        const [payer, operator, payee] = await Promise.all([
            generateKeyPairSigner(),
            generateKeyPairSigner(),
            generateKeyPairSigner(),
        ]);
        const opener = createPaymentChannelSessionOpener({ signer: payer });
        await expect(
            opener({
                challenge: sessionChallenge(
                    sessionRequest({ modes: ['push'], operator: operator.address, recipient: payee.address }),
                ),
                input: 'https://example.com/v1/stream',
                response: new Response(null, { status: 402 }),
            }),
        ).rejects.toThrow(/requires a pull-mode session challenge/);
    });
});

// ── createServerOpenedPaymentChannelSessionOpener rejections + payer ──────

describe('createServerOpenedPaymentChannelSessionOpener', () => {
    test('rejects a challenge that does not advertise pull mode', async () => {
        const [operator, payee] = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner()]);
        const opener = createServerOpenedPaymentChannelSessionOpener();
        await expect(
            opener({
                challenge: sessionChallenge(
                    sessionRequest({ modes: ['push'], operator: operator.address, recipient: payee.address }),
                ),
                input: 'https://example.com/v1/stream',
                response: new Response(null, { status: 402 }),
            }),
        ).rejects.toThrow(/requires a pull-mode session challenge/);
    });

    test('rejects a non-clientVoucher pull strategy', async () => {
        const [operator, payee] = await Promise.all([generateKeyPairSigner(), generateKeyPairSigner()]);
        const opener = createServerOpenedPaymentChannelSessionOpener();
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
        ).rejects.toThrow(/pullVoucherStrategy=clientVoucher/);
    });

    test('falls back to an explicit payer parameter over the challenge operator', async () => {
        const [operator, payee, sessionSigner, explicitPayer] = await Promise.all([
            generateKeyPairSigner(),
            generateKeyPairSigner(),
            generateKeyPairSigner(),
            generateKeyPairSigner(),
        ]);
        const request = sessionRequest({ operator: operator.address, recipient: payee.address });
        const opener = createServerOpenedPaymentChannelSessionOpener({
            payer: explicitPayer.address,
            salt: 5n,
            sessionSigner,
        });
        const result = await opener({
            challenge: sessionChallenge(request),
            input: 'https://example.com/v1/stream',
            response: new Response(null, { status: 402 }),
        });
        expect(result.payload.payer).toBe(explicitPayer.address);

        // The channel PDA must match one derived with the explicit payer.
        const derived = await derivePaymentChannelOpen({
            authorizedSigner: sessionSigner.address,
            payer: explicitPayer.address,
            request,
            salt: 5n,
        });
        expect(result.payload.channelId).toBe(derived.channelId);
    });
});

// ── preparePaymentChannelOpen error / default branches ───────────────────

describe('derivePaymentChannelOpen', () => {
    test('rejects a non-SPL currency (no resolvable mint)', async () => {
        const [operator, payee, authorizedSigner] = await Promise.all([
            generateKeyPairSigner(),
            generateKeyPairSigner(),
            generateKeyPairSigner(),
        ]);
        const request = sessionRequest({
            currency: 'SOL',
            operator: operator.address,
            recipient: payee.address,
        });
        await expect(
            derivePaymentChannelOpen({
                authorizedSigner: authorizedSigner.address,
                payer: operator.address,
                request,
                salt: 1n,
            }),
        ).rejects.toThrow(/require an SPL token currency/);
    });

    test('defaults the network to mainnet when the request omits it', async () => {
        const [operator, payee, authorizedSigner] = await Promise.all([
            generateKeyPairSigner(),
            generateKeyPairSigner(),
            generateKeyPairSigner(),
        ]);
        const request = sessionRequest({ operator: operator.address, recipient: payee.address });
        // Drop `network` to exercise the `request.network ?? 'mainnet'` default.
        const { network: _drop, ...withoutNetwork } = request;
        void _drop;
        const open = await derivePaymentChannelOpen({
            authorizedSigner: authorizedSigner.address,
            payer: operator.address,
            request: withoutNetwork as SessionRequest,
            salt: 1n,
        });
        // USDC on mainnet is the default mint.
        expect(open.mint).toBe(USDC.mainnet);
    });

    test('generates a random salt when none is supplied', async () => {
        const [operator, payee, authorizedSigner] = await Promise.all([
            generateKeyPairSigner(),
            generateKeyPairSigner(),
            generateKeyPairSigner(),
        ]);
        const request = sessionRequest({ operator: operator.address, recipient: payee.address });
        const open = await derivePaymentChannelOpen({
            authorizedSigner: authorizedSigner.address,
            payer: operator.address,
            request,
        });
        // A u64 salt string is produced.
        expect(open.salt).toMatch(/^\d+$/);
    });

    test('accepts a numeric deposit (parseU64 number branch)', async () => {
        const [operator, payee, authorizedSigner] = await Promise.all([
            generateKeyPairSigner(),
            generateKeyPairSigner(),
            generateKeyPairSigner(),
        ]);
        const request = sessionRequest({ operator: operator.address, recipient: payee.address });
        const open = await derivePaymentChannelOpen({
            authorizedSigner: authorizedSigner.address,
            deposit: 250_000,
            payer: operator.address,
            request,
            salt: 3n,
        });
        expect(open.deposit).toBe('250000');
    });

    test('rejects an unsafe-integer deposit', async () => {
        const [operator, payee, authorizedSigner] = await Promise.all([
            generateKeyPairSigner(),
            generateKeyPairSigner(),
            generateKeyPairSigner(),
        ]);
        const request = sessionRequest({ operator: operator.address, recipient: payee.address });
        await expect(
            derivePaymentChannelOpen({
                authorizedSigner: authorizedSigner.address,
                deposit: Number.MAX_SAFE_INTEGER + 2,
                payer: operator.address,
                request,
                salt: 3n,
            }),
        ).rejects.toThrow(/safe integer/);
    });

    test('rejects a malformed string deposit', async () => {
        const [operator, payee, authorizedSigner] = await Promise.all([
            generateKeyPairSigner(),
            generateKeyPairSigner(),
            generateKeyPairSigner(),
        ]);
        const request = sessionRequest({ operator: operator.address, recipient: payee.address });
        await expect(
            derivePaymentChannelOpen({
                authorizedSigner: authorizedSigner.address,
                deposit: 'not-a-number',
                payer: operator.address,
                request,
                salt: 3n,
            }),
        ).rejects.toThrow(/must be an unsigned integer/);
    });

    test('prefers explicit recipients over the challenge splits', async () => {
        const [operator, payee, authorizedSigner, platform] = await Promise.all([
            generateKeyPairSigner(),
            generateKeyPairSigner(),
            generateKeyPairSigner(),
            generateKeyPairSigner(),
        ]);
        const request = sessionRequest({
            operator: operator.address,
            recipient: payee.address,
            splits: [{ bps: 100, recipient: payee.address }],
        });
        // Supplying `recipients` takes the parameters branch instead of
        // falling back to request.splits.
        const open = await derivePaymentChannelOpen({
            authorizedSigner: authorizedSigner.address,
            payer: operator.address,
            recipients: [{ bps: 250, recipient: platform.address }],
            request,
            salt: 4n,
        });
        expect(open.channelId).toMatch(/^[1-9A-HJ-NP-Za-km-z]{32,44}$/);
    });

    test('rejects a deposit above the u64 maximum', async () => {
        const [operator, payee, authorizedSigner] = await Promise.all([
            generateKeyPairSigner(),
            generateKeyPairSigner(),
            generateKeyPairSigner(),
        ]);
        const request = sessionRequest({ operator: operator.address, recipient: payee.address });
        await expect(
            derivePaymentChannelOpen({
                authorizedSigner: authorizedSigner.address,
                deposit: (1n << 64n).toString(),
                payer: operator.address,
                request,
                salt: 3n,
            }),
        ).rejects.toThrow(/must fit in u64/);
    });
});

// ── buildOpenPaymentChannelTransaction branches ──────────────────────────

describe('buildOpenPaymentChannelTransaction', () => {
    test('reuses the payer signer when the operator is the payer', async () => {
        // feePayer === signer.address exercises the `rentPayerSigner = signer`
        // branch (kit rejects two distinct signer objects for one address).
        const [operator, payee, authorizedSigner] = await Promise.all([
            generateKeyPairSigner(),
            generateKeyPairSigner(),
            generateKeyPairSigner(),
        ]);
        const request = sessionRequest({ operator: operator.address, recipient: payee.address });
        const open = await buildOpenPaymentChannelTransaction({
            authorizedSigner: authorizedSigner.address,
            gracePeriod: 900,
            request,
            salt: 42n,
            signer: operator,
        });
        expect(open.payer).toBe(operator.address);
        expect(open.transaction).toEqual(expect.any(String));
    });

    test('defaults the network to mainnet when the request omits it', async () => {
        // Exercises `normalizeNetwork(request.network ?? 'mainnet')` in
        // buildOpenPaymentChannelTransaction. A recentBlockhash is supplied so
        // no RPC round-trip is needed.
        const [operator, payee, authorizedSigner] = await Promise.all([
            generateKeyPairSigner(),
            generateKeyPairSigner(),
            generateKeyPairSigner(),
        ]);
        const request = sessionRequest({ operator: operator.address, recipient: payee.address });
        const { network: _drop, ...withoutNetwork } = request;
        void _drop;
        const open = await buildOpenPaymentChannelTransaction({
            authorizedSigner: authorizedSigner.address,
            gracePeriod: 900,
            request: withoutNetwork as SessionRequest,
            salt: 42n,
            signer: operator,
        });
        expect(open.mint).toBe(USDC.mainnet);
        expect(open.transaction).toEqual(expect.any(String));
    });
});
