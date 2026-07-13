import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { InvalidProofError } from '../errors.js';

// --- Boundary mocks -------------------------------------------------------
// The x402 exact adapter settles through an in-process @x402/core facilitator
// (which needs a live RPC + real signatures) and reads a recent blockhash from
// @solana/kit. Both are stubbed so the adapter's own wiring (challenge
// building, header parsing, verify/settle branching) is exercised offline.

type VerifyResult = {
    invalidMessage?: string;
    invalidReason?: string;
    isValid: boolean;
    payer?: string;
};
type SettleResult = {
    errorMessage?: string;
    errorReason?: string;
    payer?: string;
    success: boolean;
    transaction?: string;
};

const facilitatorControl: {
    settle: () => Promise<SettleResult>;
    verify: () => Promise<VerifyResult>;
} = {
    settle: () => Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' }),
    verify: () => Promise.resolve({ isValid: true, payer: 'VerifyPayer' }),
};

const blockhashControl: { impl: () => Promise<{ context: { slot: bigint }; value: unknown }> } = {
    impl: () =>
        Promise.resolve({
            context: { slot: 314n },
            value: { blockhash: 'BlockHash111', lastValidBlockHeight: 4242n },
        }),
};

// Counts every getLatestBlockhash().send() invocation, and an optional gate the
// test releases once all concurrent challenges are in flight, before a
// non-single-flight cache would already have fired N RPCs.
const rpcMeter: { calls: number; gate?: Promise<void>; release?: () => void } = { calls: 0 };

const decodeControl: { impl: (header: string) => unknown } = {
    impl: () => ({ accepted: { network: 'solana:test' }, payload: {} }),
};

vi.mock('@x402/core/facilitator', () => {
    class FakeFacilitator {
        register(): this {
            return this;
        }
        verify(): Promise<VerifyResult> {
            return facilitatorControl.verify();
        }
        settle(): Promise<SettleResult> {
            return facilitatorControl.settle();
        }
    }
    return { x402Facilitator: FakeFacilitator };
});

vi.mock('@x402/svm', async () => {
    const actual = await vi.importActual<typeof import('@x402/svm')>('@x402/svm');
    return { ...actual, toFacilitatorSvmSigner: () => ({}) };
});

vi.mock('@x402/svm/exact/facilitator', () => ({ ExactSvmScheme: class {} }));

vi.mock('@x402/core/http', () => ({
    decodePaymentSignatureHeader: (header: string) => decodeControl.impl(header),
    encodePaymentRequiredHeader: () => 'ENCODED_PAYMENT_REQUIRED',
    encodePaymentResponseHeader: () => 'ENCODED_PAYMENT_RESPONSE',
}));

vi.mock('@solana/kit', async () => {
    const actual = await vi.importActual<typeof import('@solana/kit')>('@solana/kit');
    return {
        ...actual,
        createSolanaRpc: () => ({
            getLatestBlockhash: () => ({
                send: async () => {
                    rpcMeter.calls += 1;
                    if (rpcMeter.gate) await rpcMeter.gate;
                    return blockhashControl.impl();
                },
            }),
        }),
    };
});

const { createX402ExactAdapter } = await import('../adapters/x402.js');
const { configure } = await import('../config.js');
const { Gate } = await import('../gate.js');
const { usd } = await import('../price.js');
const { gateDefaults } = await import('../pricing.js');
const { createMemoryReplayStore } = await import('../replay-store.js');

async function setup() {
    const config = await configure({
        mpp: { challengeBindingSecret: 'x402-adapter-secret' },
        network: 'solana_localnet',
        replayStore: createMemoryReplayStore(),
    });
    return { adapter: createX402ExactAdapter(config), config };
}

function paidRequest(header = 'PAYMENT_CRED'): Request {
    return new Request('http://localhost/report', { headers: { 'x-payment': header } });
}

async function gateFor(amount = usd('0.10')) {
    const config = await configure({
        mpp: { challengeBindingSecret: 'x402-adapter-secret' },
        network: 'solana_localnet',
    });
    return Gate.create({ amount, name: 'report' }, gateDefaults(config));
}

describe('createX402ExactAdapter', () => {
    beforeEach(() => {
        facilitatorControl.verify = () => Promise.resolve({ isValid: true, payer: 'VerifyPayer' });
        facilitatorControl.settle = () =>
            Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' });
        blockhashControl.impl = () =>
            Promise.resolve({
                context: { slot: 314n },
                value: { blockhash: 'BlockHash111', lastValidBlockHeight: 4242n },
            });
        decodeControl.impl = () => ({ accepted: { network: 'solana:test' }, payload: {} });
        rpcMeter.calls = 0;
        rpcMeter.gate = undefined;
        rpcMeter.release = undefined;
    });

    afterEach(() => {
        vi.clearAllMocks();
    });

    it('exposes protocol/scheme metadata', async () => {
        const { adapter } = await setup();
        expect(adapter.protocol).toBe('x402');
        expect(adapter.scheme).toBe('exact');
    });

    it('embeds a server-fetched blockhash in the challenge requirements', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();
        const headers = await adapter.challengeHeaders(gate, new Request('http://localhost/report'));
        expect(headers['payment-required']).toBe('ENCODED_PAYMENT_REQUIRED');
    });

    it('falls back to bare requirements when the blockhash fetch fails', async () => {
        blockhashControl.impl = () => Promise.reject(new Error('rpc down'));
        const { adapter } = await setup();
        const gate = await gateFor();
        // Still produces a challenge; the catch branch swallows the RPC error.
        const headers = await adapter.challengeHeaders(gate, new Request('http://localhost/report'));
        expect(headers['payment-required']).toBe('ENCODED_PAYMENT_REQUIRED');
    });

    it('collapses a concurrent challenge burst to a single getLatestBlockhash RPC', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();

        // Latch the RPC so every concurrent challenge enters challengeRequirements
        // before the first fetch resolves; without single-flight this fires N RPCs.
        rpcMeter.gate = new Promise<void>(resolve => {
            rpcMeter.release = resolve;
        });
        const bursts = Array.from({ length: 20 }, () =>
            adapter.challengeHeaders(gate, new Request('http://localhost/report')),
        );
        // Give the microtask queue a chance to line every request up at the gate.
        await Promise.resolve();
        rpcMeter.release?.();
        await Promise.all(bursts);

        expect(rpcMeter.calls).toBe(1);
    });

    it('reuses the cached blockhash for a second challenge within the TTL (no extra RPC)', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();
        await adapter.challengeHeaders(gate, new Request('http://localhost/report'));
        await adapter.challengeHeaders(gate, new Request('http://localhost/report'));
        expect(rpcMeter.calls).toBe(1);
    });

    it('rejects a request with no payment header', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();
        await expect(adapter.verifyAndSettle(gate, new Request('http://localhost/report'))).rejects.toMatchObject({
            code: 'missing_x402_payment_header',
        });
    });

    it('rejects an undecodable payment header', async () => {
        decodeControl.impl = () => {
            throw new Error('bad base64');
        };
        const { adapter } = await setup();
        const gate = await gateFor();
        await expect(adapter.verifyAndSettle(gate, paidRequest())).rejects.toMatchObject({
            code: 'invalid_x402_payment_header',
        });
    });

    it('rejects when verification fails, surfacing the invalid reason', async () => {
        facilitatorControl.verify = () =>
            Promise.resolve({ invalidMessage: 'nope', invalidReason: 'signature_consumed', isValid: false });
        const { adapter } = await setup();
        const gate = await gateFor();
        await expect(adapter.verifyAndSettle(gate, paidRequest())).rejects.toMatchObject({
            code: 'signature_consumed',
        });
    });

    it('defaults the invalid reason when verification omits one', async () => {
        facilitatorControl.verify = () => Promise.resolve({ isValid: false });
        const { adapter } = await setup();
        const gate = await gateFor();
        await expect(adapter.verifyAndSettle(gate, paidRequest())).rejects.toMatchObject({ code: 'invalid_proof' });
    });

    it('rejects when settlement fails, surfacing the error reason', async () => {
        facilitatorControl.settle = () =>
            Promise.resolve({ errorMessage: 'rpc down', errorReason: 'settlement_failed', success: false });
        const { adapter } = await setup();
        const gate = await gateFor();
        await expect(adapter.verifyAndSettle(gate, paidRequest())).rejects.toMatchObject({
            code: 'settlement_failed',
        });
    });

    it('defaults the error reason when settlement omits one', async () => {
        facilitatorControl.settle = () => Promise.resolve({ success: false });
        const { adapter } = await setup();
        const gate = await gateFor();
        await expect(adapter.verifyAndSettle(gate, paidRequest())).rejects.toMatchObject({
            code: 'settlement_failed',
        });
    });

    it('settles a valid payment and returns the payment record', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();
        const payment = await adapter.verifyAndSettle(gate, paidRequest('CRED123'));
        expect(payment).toMatchObject({
            gateName: 'report',
            payer: 'SettlePayer',
            protocol: 'x402',
            raw: 'CRED123',
            scheme: 'exact',
            transaction: 'TxSig',
        });
        expect(payment.settlementHeaders['x-payment-response']).toBe('ENCODED_PAYMENT_RESPONSE');
    });

    it('falls back to the verify payer when settlement omits one', async () => {
        facilitatorControl.settle = () => Promise.resolve({ success: true, transaction: 'TxSig' });
        const { adapter } = await setup();
        const gate = await gateFor();
        const payment = await adapter.verifyAndSettle(gate, paidRequest());
        expect(payment.payer).toBe('VerifyPayer');
    });

    it('reads the credential from the payment-signature header', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();
        const request = new Request('http://localhost/report', { headers: { 'payment-signature': 'SIG' } });
        const payment = await adapter.verifyAndSettle(gate, request);
        expect(payment.raw).toBe('SIG');
    });

    it('surfaces an InvalidProofError instance on missing header', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();
        await expect(adapter.verifyAndSettle(gate, new Request('http://localhost/report'))).rejects.toBeInstanceOf(
            InvalidProofError,
        );
    });

    // ── replay / in-flight dedup ────────────────────────────────────────────

    it('rejects a sequential replay of the same payment payload', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();

        const first = await adapter.verifyAndSettle(gate, paidRequest('REPLAY_CRED'));
        expect(first.transaction).toBe('TxSig');

        await expect(adapter.verifyAndSettle(gate, paidRequest('REPLAY_CRED'))).rejects.toMatchObject({
            code: 'x402_payment_replayed',
        });
    });

    it('rejects a concurrent duplicate payload while the first settles', async () => {
        let settleCalls = 0;
        facilitatorControl.settle = () => {
            settleCalls += 1;
            return new Promise(resolve =>
                setTimeout(() => resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' }), 20),
            );
        };
        const { adapter } = await setup();
        const gate = await gateFor();

        const results = await Promise.allSettled([
            adapter.verifyAndSettle(gate, paidRequest('RACE_CRED')),
            adapter.verifyAndSettle(gate, paidRequest('RACE_CRED')),
        ]);
        const fulfilled = results.filter(result => result.status === 'fulfilled');
        const rejected = results.filter((result): result is PromiseRejectedResult => result.status === 'rejected');
        expect(fulfilled).toHaveLength(1);
        expect(rejected).toHaveLength(1);
        expect(rejected[0]!.reason).toMatchObject({ code: 'x402_payment_replayed' });
        expect(settleCalls).toBe(1);
    });

    it('rejects facilitator-slot mutations without collapsing distinct transaction messages', async () => {
        const kit = await vi.importActual<typeof import('@solana/kit')>('@solana/kit');
        const facilitator = await kit.generateKeyPairSigner();
        const client = await kit.generateKeyPairSigner();
        const message = kit.pipe(
            kit.createTransactionMessage({ version: 0 }),
            msg => kit.setTransactionMessageFeePayerSigner(facilitator, msg),
            msg =>
                kit.appendTransactionMessageInstructions(
                    [
                        {
                            accounts: [{ address: client.address, role: kit.AccountRole.READONLY_SIGNER }],
                            data: new Uint8Array(),
                            programAddress: kit.address('11111111111111111111111111111111'),
                        },
                    ],
                    msg,
                ),
            msg =>
                kit.setTransactionMessageLifetimeUsingBlockhash(
                    {
                        blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as never,
                        lastValidBlockHeight: 0n,
                    },
                    msg,
                ),
        );
        const compiled = kit.compileTransaction(message);
        const unsignedFacilitator = {
            ...compiled,
            signatures: {
                ...compiled.signatures,
                [client.address]: new Uint8Array(64).fill(2),
                [facilitator.address]: null,
            },
        };
        const unsignedFacilitatorWire = kit.getBase64EncodedWireTransaction(unsignedFacilitator) as string;
        const facilitatorSlotMutationWire = kit.getBase64EncodedWireTransaction({
            ...unsignedFacilitator,
            signatures: {
                ...unsignedFacilitator.signatures,
                [facilitator.address]: new Uint8Array(64).fill(1),
            },
        }) as string;
        const distinct = kit.compileTransaction(
            kit.appendTransactionMessageInstructions(
                [
                    {
                        accounts: [{ address: client.address, role: kit.AccountRole.READONLY_SIGNER }],
                        data: new Uint8Array([1]),
                        programAddress: kit.address('11111111111111111111111111111111'),
                    },
                ],
                message,
            ),
        );
        const distinctWire = kit.getBase64EncodedWireTransaction({
            ...distinct,
            signatures: {
                ...distinct.signatures,
                [client.address]: new Uint8Array(64).fill(2),
                [facilitator.address]: null,
            },
        }) as string;

        const unsigned = kit.getTransactionDecoder().decode(kit.getBase64Codec().encode(unsignedFacilitatorWire));
        const mutated = kit.getTransactionDecoder().decode(kit.getBase64Codec().encode(facilitatorSlotMutationWire));
        const distinctMessage = kit.getTransactionDecoder().decode(kit.getBase64Codec().encode(distinctWire));
        expect(mutated.messageBytes).toEqual(unsigned.messageBytes);
        expect(mutated.signatures[facilitator.address]).not.toEqual(unsigned.signatures[facilitator.address]);
        expect(distinctMessage.messageBytes).not.toEqual(unsigned.messageBytes);

        let settleCalls = 0;
        facilitatorControl.settle = () => {
            settleCalls += 1;
            return Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' });
        };
        decodeControl.impl = header => ({
            accepted: { network: 'solana:test' },
            payload: {
                transaction:
                    header === 'UNSIGNED_FACILITATOR'
                        ? unsignedFacilitatorWire
                        : header === 'FACILITATOR_SLOT_MUTATION'
                          ? facilitatorSlotMutationWire
                          : distinctWire,
            },
        });

        const { adapter } = await setup();
        const gate = await gateFor();

        await adapter.verifyAndSettle(gate, paidRequest('UNSIGNED_FACILITATOR'));
        await expect(adapter.verifyAndSettle(gate, paidRequest('FACILITATOR_SLOT_MUTATION'))).rejects.toMatchObject({
            code: 'x402_payment_replayed',
        });
        await adapter.verifyAndSettle(gate, paidRequest('DISTINCT_TRANSACTION'));
        expect(settleCalls).toBe(2);
    });

    it('releases the payload key on a pre-broadcast settle failure so a retry can proceed', async () => {
        // A verification-class errorReason proves the transaction never
        // broadcast, so the reservation is released for an honest retry.
        facilitatorControl.settle = () =>
            Promise.resolve({ errorMessage: 're-verify failed', errorReason: 'verification_failed', success: false });
        const { adapter } = await setup();
        const gate = await gateFor();

        await expect(adapter.verifyAndSettle(gate, paidRequest('RETRY_CRED'))).rejects.toMatchObject({
            code: 'verification_failed',
        });

        facilitatorControl.settle = () =>
            Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' });
        const retried = await adapter.verifyAndSettle(gate, paidRequest('RETRY_CRED'));
        expect(retried.transaction).toBe('TxSig');
    });

    it('keeps the payload key on a landed-but-unconfirmed settle failure (transaction_failed)', async () => {
        // `@x402/svm` collapses a confirmation-poll timeout on a tx that may
        // have landed into {success:false, errorReason:'transaction_failed'}.
        // Releasing the reservation here would let another replica re-serve the
        // same landed payment, so the key must stay claimed.
        facilitatorControl.settle = () =>
            Promise.resolve({ errorMessage: 'confirm timeout', errorReason: 'transaction_failed', success: false });
        const { adapter } = await setup();
        const gate = await gateFor();

        await expect(adapter.verifyAndSettle(gate, paidRequest('LANDED_CRED'))).rejects.toMatchObject({
            code: 'transaction_failed',
        });

        // A second attempt with the same payload is rejected as a replay: the
        // reservation was NOT released, so the landed tx cannot be re-served
        // even if the next call would have settled successfully.
        facilitatorControl.settle = () =>
            Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' });
        await expect(adapter.verifyAndSettle(gate, paidRequest('LANDED_CRED'))).rejects.toMatchObject({
            code: 'x402_payment_replayed',
        });
    });

    it('keeps the payload key on an unknown settle failure reason (fail closed)', async () => {
        // Any reason outside the enumerated release-safe set defaults to KEEP.
        facilitatorControl.settle = () => Promise.resolve({ errorReason: 'some_new_unmapped_reason', success: false });
        const { adapter } = await setup();
        const gate = await gateFor();

        await expect(adapter.verifyAndSettle(gate, paidRequest('UNKNOWN_CRED'))).rejects.toMatchObject({
            code: 'some_new_unmapped_reason',
        });

        facilitatorControl.settle = () =>
            Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' });
        await expect(adapter.verifyAndSettle(gate, paidRequest('UNKNOWN_CRED'))).rejects.toMatchObject({
            code: 'x402_payment_replayed',
        });
    });

    it('keeps the payload key when settlement throws so an ambiguous result cannot replay', async () => {
        // Facilitator hooks and implementations can throw after a broadcast but
        // before confirmation is returned. Without a typed, pre-broadcast-only
        // failure signal, retaining the reservation is the safe outcome.
        facilitatorControl.settle = () => Promise.reject(new Error('cosign failed'));
        const { adapter } = await setup();
        const gate = await gateFor();

        await expect(adapter.verifyAndSettle(gate, paidRequest('THROW_CRED'))).rejects.toThrow(/cosign failed/);

        facilitatorControl.settle = () =>
            Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' });
        await expect(adapter.verifyAndSettle(gate, paidRequest('THROW_CRED'))).rejects.toMatchObject({
            code: 'x402_payment_replayed',
        });
    });

    it('surfaces the original error type when settlement throws pre-broadcast', async () => {
        // The thrown value is wrapped as an InvalidProofError with a stable code
        // so callers get the canonical taxonomy, not the raw internal error.
        facilitatorControl.settle = () => Promise.reject(new Error('cosign boom'));
        const { adapter } = await setup();
        const gate = await gateFor();

        await expect(adapter.verifyAndSettle(gate, paidRequest('THROW_CODE_CRED'))).rejects.toBeInstanceOf(
            InvalidProofError,
        );
    });

    it('lets distinct payloads settle independently', async () => {
        const { adapter } = await setup();
        const gate = await gateFor();

        const first = await adapter.verifyAndSettle(gate, paidRequest('CRED_ONE'));
        const second = await adapter.verifyAndSettle(gate, paidRequest('CRED_TWO'));
        expect(first.transaction).toBe('TxSig');
        expect(second.transaction).toBe('TxSig');
    });

    it('expires consumed entries after the completion window', async () => {
        vi.useFakeTimers();
        try {
            const { adapter } = await setup();
            const gate = await gateFor();

            await adapter.verifyAndSettle(gate, paidRequest('WINDOW_CRED'));
            // Within the 300s window the replay is still rejected.
            vi.setSystemTime(Date.now() + 299_000);
            await expect(adapter.verifyAndSettle(gate, paidRequest('WINDOW_CRED'))).rejects.toMatchObject({
                code: 'x402_payment_replayed',
            });
            // Past the window the blockhash has expired on-chain; the local
            // entry is pruned and the ledger owns dedup from here.
            vi.setSystemTime(Date.now() + 302_000);
            const late = await adapter.verifyAndSettle(gate, paidRequest('WINDOW_CRED'));
            expect(late.transaction).toBe('TxSig');
        } finally {
            vi.useRealTimers();
        }
    });

    // ── cross-process dedup via a reserving replay store ────────────────────

    /** A reserving Store double: `reserve` is an atomic check-and-set. */
    function reservingStore() {
        const map = new Map<string, unknown>();
        const calls: { reserve: Array<{ key: string; ttlSeconds?: number }>; deletes: string[] } = {
            reserve: [],
            deletes: [],
        };
        return {
            calls,
            store: {
                get: (key: string) => Promise.resolve(map.get(key) ?? null),
                put: (key: string, value: unknown) => {
                    map.set(key, value);
                    return Promise.resolve();
                },
                delete: (key: string) => {
                    calls.deletes.push(key);
                    map.delete(key);
                    return Promise.resolve();
                },
                reserve: (key: string, value: unknown = true, ttlSeconds?: number) => {
                    calls.reserve.push({ key, ttlSeconds });
                    if (map.has(key)) return Promise.resolve(false);
                    map.set(key, value);
                    return Promise.resolve(true);
                },
            },
        };
    }

    async function setupWithStore(store: unknown) {
        const config = await configure({
            mpp: { challengeBindingSecret: 'x402-adapter-secret' },
            network: 'solana_localnet',
            replayStore: store as never,
        });
        return { adapter: createX402ExactAdapter(config) };
    }

    it('claims through the reserving store (with a TTL) when one is configured', async () => {
        const reserving = reservingStore();
        const { adapter } = await setupWithStore(reserving.store);
        const gate = await gateFor();

        await adapter.verifyAndSettle(gate, paidRequest('STORE_CRED'));
        expect(reserving.calls.reserve).toHaveLength(1);
        expect(reserving.calls.reserve[0]!.key.startsWith('x402-svm-exact:consumed:')).toBe(true);
        expect(reserving.calls.reserve[0]!.ttlSeconds).toBe(300);
    });

    it('rejects a sequential replay via the reserving store', async () => {
        const reserving = reservingStore();
        const { adapter } = await setupWithStore(reserving.store);
        const gate = await gateFor();

        await adapter.verifyAndSettle(gate, paidRequest('DUP_CRED'));
        await expect(adapter.verifyAndSettle(gate, paidRequest('DUP_CRED'))).rejects.toMatchObject({
            code: 'x402_payment_replayed',
        });
    });

    it('rejects a concurrent duplicate via the reserving store', async () => {
        let settleCalls = 0;
        facilitatorControl.settle = () => {
            settleCalls += 1;
            return new Promise(resolve =>
                setTimeout(() => resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' }), 20),
            );
        };
        const reserving = reservingStore();
        const { adapter } = await setupWithStore(reserving.store);
        const gate = await gateFor();

        const results = await Promise.allSettled([
            adapter.verifyAndSettle(gate, paidRequest('RACE_STORE')),
            adapter.verifyAndSettle(gate, paidRequest('RACE_STORE')),
        ]);
        expect(results.filter(r => r.status === 'fulfilled')).toHaveLength(1);
        expect(results.filter(r => r.status === 'rejected')).toHaveLength(1);
        expect(settleCalls).toBe(1);
    });

    it('rejects replay across independent adapters sharing the atomic memory store', async () => {
        const shared = createMemoryReplayStore();
        const [{ adapter: replicaA }, { adapter: replicaB }] = await Promise.all([
            setupWithStore(shared),
            setupWithStore(shared),
        ]);
        const gate = await gateFor();

        await replicaA.verifyAndSettle(gate, paidRequest('CROSS_INSTANCE_CRED'));
        await expect(replicaB.verifyAndSettle(gate, paidRequest('CROSS_INSTANCE_CRED'))).rejects.toMatchObject({
            code: 'x402_payment_replayed',
        });
    });

    it('releases the reserving-store key on a pre-broadcast settle failure', async () => {
        facilitatorControl.settle = () =>
            Promise.resolve({ errorMessage: 're-verify failed', errorReason: 'verification_failed', success: false });
        const reserving = reservingStore();
        const { adapter } = await setupWithStore(reserving.store);
        const gate = await gateFor();

        await expect(adapter.verifyAndSettle(gate, paidRequest('REL_CRED'))).rejects.toMatchObject({
            code: 'verification_failed',
        });
        expect(reserving.calls.deletes).toHaveLength(1);

        // The released key can be reclaimed by a retry.
        facilitatorControl.settle = () =>
            Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' });
        const retried = await adapter.verifyAndSettle(gate, paidRequest('REL_CRED'));
        expect(retried.transaction).toBe('TxSig');
    });

    it('keeps the reserving-store key on a landed-but-unconfirmed settle failure', async () => {
        // The cross-process invariant: a `transaction_failed` (confirm-timeout)
        // must not delete the shared reservation, so a second replica reading
        // the same store still rejects the payload as a replay.
        facilitatorControl.settle = () =>
            Promise.resolve({ errorMessage: 'confirm timeout', errorReason: 'transaction_failed', success: false });
        const reserving = reservingStore();
        const { adapter } = await setupWithStore(reserving.store);
        const gate = await gateFor();

        await expect(adapter.verifyAndSettle(gate, paidRequest('KEEP_CRED'))).rejects.toMatchObject({
            code: 'transaction_failed',
        });
        expect(reserving.calls.deletes).toHaveLength(0);

        // A second replica sharing the store still rejects the payload: the
        // reservation was never released.
        const { adapter: replica } = await setupWithStore(reserving.store);
        facilitatorControl.settle = () =>
            Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' });
        await expect(replica.verifyAndSettle(gate, paidRequest('KEEP_CRED'))).rejects.toMatchObject({
            code: 'x402_payment_replayed',
        });
    });

    it('keeps the reserving-store key when settlement throws', async () => {
        facilitatorControl.settle = () => Promise.reject(new Error('cosign failed'));
        const reserving = reservingStore();
        const { adapter } = await setupWithStore(reserving.store);
        const gate = await gateFor();

        await expect(adapter.verifyAndSettle(gate, paidRequest('THROW_STORE'))).rejects.toThrow(/cosign failed/);
        expect(reserving.calls.deletes).toHaveLength(0);

        // Another replica sharing the store cannot reclaim an ambiguous payment.
        facilitatorControl.settle = () =>
            Promise.resolve({ payer: 'SettlePayer', success: true, transaction: 'TxSig' });
        await expect(adapter.verifyAndSettle(gate, paidRequest('THROW_STORE'))).rejects.toMatchObject({
            code: 'x402_payment_replayed',
        });
    });
});
