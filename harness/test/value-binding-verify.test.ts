// VALUE-BINDING radar for the session OPEN + TOP-UP verifiers.
//
// The audit found the verifiers are never fuzzed on value-binding: a mock (or
// production) RPC's getSignatureStatuses only answers "did this signature
// confirm?", so "the signature is confirmed" gets conflated with "the signature
// proves THIS channel/deposit". That conflation is exactly why the CRITICAL
// top-up and HIGH push-open fabricated-deposit findings are invisible — no test
// pairs a *confirmed but unrelated* signature with an inflated claim and asserts
// rejection.
//
// This suite drives the REAL TS verifiers through their public entrypoint, the
// session server (`@solana/mpp/server`'s `session().verify(...)`), which calls
// the on-chain open verifier (verifyOpenTx, via handleOpen) and the top-up
// verifier (handleTopUp). verifyOpenTx itself is not on the public surface, so
// exercising it end-to-end through session() is both the only reachable path
// from the harness and the more faithful one. Adversarial vectors are mirrored
// in harness/vectors/value-binding/*.json, each asserting REJECTION.
//
// The mock RPCs model "confirmed but unrelated": a FIXED set of real, landed
// signatures confirm, everything else is not-found — the same shape a production
// RPC has. Registering a signature means "this transaction really landed
// on-chain", NOT "it is a top-up/open of this channel for this delta". Two
// shapes are used:
//   - makeUnrelatedConfirmRpc: status-only (`getSignatureStatuses`), for the
//     paths that bind through the signature<->tx / not-found route.
//   - makeBoundTxRpc: also exposes `getTransaction`, returning the ADVERSARIAL
//     wire bytes each confirmed signature maps to (never bytes that prove the
//     claimed channel/delta). This is what engages the top-up delta-binding
//     verifier — a status-only mock never reaches it, which is exactly why the
//     CRITICAL top-up finding was previously invisible.
//
// topUp (a)/(c) go GREEN once the top-up delta-binding fix is present in the
// resolved @solana/mpp dist (handleTopUp fetches the referenced tx via
// getTransaction and requires a top_up of THIS channel whose amount equals
// newDeposit-oldDeposit). If the dist is behind src they are
// RED-EXPECTED-PENDING-TS-DIST-REBUILD until `pnpm --filter @solana/mpp build`.
// Fleet-wide the same delta-binding is required of Go NewTopUpTxVerifier /
// Python new_top_up_tx_verifier.
//
// open (d) goes GREEN once the open distribution-binding fix is present in the
// resolved dist (verifyOpenTx parses the open instruction's recipients[] and
// rejects any divergence from the configured merchant splits). If the dist is
// behind src it is RED-EXPECTED-PENDING-OPEN-DISTRIBUTION-BINDING until handleOpen
// threads the splits into verifyOpenTx.
// GREEN CASES (binding the verifier already enforces — regression guards):
//   - open  (a): signature<->transaction binding.
//   - open  (b): the C1 placeholder-open guard.
//   - topUp (b): a placeholder is fed to getSignatureStatuses and rejected as
//     not-found. GREEN, but the rejection is incidental — a dedicated
//     placeholder guard (like open's C1) would make the intent explicit.
//
// NOTE (resolution): the harness resolves @solana/mpp to its precompiled dist.
// If that dist is behind src the results here reflect dist, not src — rebuild
// the package (pnpm --filter @solana/mpp build) before running so the radar
// reflects current source.

import {
    AccountRole,
    address,
    appendTransactionMessageInstruction,
    type Blockhash,
    createKeyPairSignerFromPrivateKeyBytes,
    createTransactionMessage,
    getBase64Codec,
    getBase64EncodedWireTransaction,
    getSignatureFromTransaction,
    getTransactionDecoder,
    type KeyPairSigner,
    partiallySignTransactionMessageWithSigners,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    type Signature,
} from '@solana/kit';
import {
    buildOpenPaymentChannelTransaction,
    type SessionRequest,
    type SessionSplit,
    USDC,
} from '@solana/mpp/client';
import { createMemorySessionStore, session, type SessionStore } from '@solana/mpp/server';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { beforeAll, describe, expect, it } from 'vitest';

// ── fixtures ────────────────────────────────────────────────────────────

const USDC_MAINNET = USDC.mainnet as string;
const RECENT_BLOCKHASH = 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N';
const PLACEHOLDER_SIG = '1'.repeat(88);
// A base58 channel id for the store-seeded top-up cases. The top-up binding
// verifier parses the fetched transaction and requires its `top_up` instruction
// to name THIS channel, so it must be a real base58 address.
const SEED_CHANNEL = 'HpQ2u1nBoQ2zt6f2n9tqf7cXrJ8pM9cVYh6ZkQmA1B2C';

// payment-channels program id + `top_up` discriminator (mirrors the SDK's
// generated topUp.ts / server on-chain verifier). Used to synthesize the
// adversarial on-chain top-up bytes the mock RPC hands back.
const PAYMENT_CHANNELS_PROGRAM_ADDRESS = 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX';
const TOP_UP_DISCRIMINATOR = 3;

function makeSeed(byte: number): Uint8Array {
    const seed = new Uint8Array(32);
    seed.fill(byte);
    return seed;
}

let payer: KeyPairSigner;
let payee: KeyPairSigner;
let authorizedSigner: KeyPairSigner;
let attacker: KeyPairSigner;

beforeAll(async () => {
    [payer, payee, authorizedSigner, attacker] = await Promise.all([
        createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x21)),
        createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x22)),
        createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x23)),
        createKeyPairSignerFromPrivateKeyBytes(makeSeed(0x24)),
    ]);
});

/** The challenge the client opens against; operator == payer so the payer's own
 *  signature is the fee-payer signature (lets us produce a real, bindable open
 *  signature the mock RPC can then confirm). */
function openRequest(recipient?: string): SessionRequest {
    return {
        cap: '5000000',
        currency: USDC_MAINNET,
        decimals: 6,
        network: 'localnet',
        operator: payer.address,
        recentBlockhash: RECENT_BLOCKHASH as never,
        // The epoch-addressed channel PDA seeds include open_slot, so the
        // server challenge now pre-fetches recentSlot alongside recentBlockhash.
        recentSlot: '42',
        recipient: recipient ?? payee.address,
    };
}

async function buildOpen(opts: {
    readonly deposit?: bigint;
    readonly salt?: bigint;
    readonly recipients?: readonly { readonly bps: number; readonly recipient: string }[];
    /** Override the on-chain payee (account slot 2). Defaults to the merchant
     *  recipient; set to an attacker address to build a divergent-payee open. */
    readonly recipient?: string;
}) {
    return await buildOpenPaymentChannelTransaction({
        authorizedSigner: authorizedSigner.address,
        deposit: opts.deposit ?? 1_000_000n,
        gracePeriod: 900,
        ...(opts.recipients ? { recipients: opts.recipients } : {}),
        request: openRequest(opts.recipient),
        salt: opts.salt ?? 7n,
        signer: payer,
    });
}

function txSignature(transactionBase64: string): string {
    const tx = getTransactionDecoder().decode(getBase64Codec().encode(transactionBase64));
    return getSignatureFromTransaction(tx);
}

interface MockStatus {
    confirmationStatus?: string;
    err: unknown;
}

/** "Confirmed but unrelated" RPC — reports ONLY `confirmed` signatures as
 *  landed, everything else as not-found. No channel/delta awareness. */
function makeUnrelatedConfirmRpc(confirmed: readonly string[]) {
    const set = new Set(confirmed);
    return {
        getSignatureStatuses: (sigs: readonly Signature[]) => ({
            send: async () => ({
                value: sigs.map((s): MockStatus | null =>
                    set.has(s as string) ? { confirmationStatus: 'confirmed', err: null } : null,
                ),
            }),
        }),
        sendTransaction: (_wire: string) => ({
            send: async () => 'SendSig1111111111111111111111111111111111111111111111111111111' as Signature,
        }),
    };
}

/** Encode `top_up` instruction data: [discriminator u8][amount u64 LE]. */
function topUpInstructionData(amount: bigint): Uint8Array {
    const data = new Uint8Array(1 + 8);
    data[0] = TOP_UP_DISCRIMINATOR;
    new DataView(data.buffer).setBigUint64(1, amount, true);
    return data;
}

/** Build a REAL, decodable payment-channels `top_up` transaction whose on-chain
 *  amount is `amount` and whose channel account (instruction slot 1) is
 *  `channelId`. Models a confirmed top-up that truly landed but proves a
 *  DIFFERENT delta than the one the payload claims — the exact adversarial shape
 *  the binding verifier must reject. Account order mirrors the program layout:
 *  slot 0 payer, slot 1 channel. */
async function buildTopUpTx(channelId: string, amount: bigint): Promise<string> {
    const instruction = {
        accounts: [
            { address: payer.address, role: AccountRole.WRITABLE },
            { address: address(channelId), role: AccountRole.WRITABLE },
        ],
        data: topUpInstructionData(amount),
        programAddress: address(PAYMENT_CHANNELS_PROGRAM_ADDRESS),
    };
    const txMessage = pipe(
        createTransactionMessage({ version: 0 }),
        msg => setTransactionMessageFeePayerSigner(payer, msg),
        msg =>
            setTransactionMessageLifetimeUsingBlockhash(
                { blockhash: RECENT_BLOCKHASH as Blockhash, lastValidBlockHeight: 0n },
                msg,
            ),
        msg => appendTransactionMessageInstruction(instruction, msg),
    );
    const signed = await partiallySignTransactionMessageWithSigners(txMessage);
    return getBase64EncodedWireTransaction(signed);
}

/** One entry of a `getTransaction` response (the subset the verifier reads). */
interface FetchedTx {
    meta: { err: unknown } | null;
    transaction: readonly [string, string];
}

/** "Confirmed but unrelated, and here is what actually landed" RPC. Like
 *  {@link makeUnrelatedConfirmRpc} it confirms only the registered signatures,
 *  but it ALSO exposes `getTransaction` so the top-up binding verifier engages:
 *  each registered signature fetches back the ADVERSARIAL wire bytes it maps to
 *  (never bytes that prove the claimed channel/delta), everything else is
 *  not-found. This models a real RPC — the signature landed on-chain and the
 *  fetched tx is genuine; it simply does not prove THIS channel/deposit. */
function makeBoundTxRpc(txBySignature: Readonly<Record<string, string>>) {
    const confirmed = new Set(Object.keys(txBySignature));
    return {
        getSignatureStatuses: (sigs: readonly Signature[]) => ({
            send: async () => ({
                value: sigs.map((s): MockStatus | null =>
                    confirmed.has(s as string) ? { confirmationStatus: 'confirmed', err: null } : null,
                ),
            }),
        }),
        getTransaction: (signature: Signature) => ({
            send: async (): Promise<FetchedTx | null> => {
                const wire = txBySignature[signature as string];
                return wire ? { meta: { err: null }, transaction: [wire, 'base64'] } : null;
            },
        }),
        sendTransaction: (_wire: string) => ({
            send: async () => 'SendSig1111111111111111111111111111111111111111111111111111111' as Signature,
        }),
    };
}

/** Robust rejection detector: the verifier rejects if it throws OR returns a
 *  non-success receipt. */
async function outcome(fn: () => Promise<unknown>): Promise<'accepted' | 'rejected'> {
    try {
        const r = (await fn()) as { status?: string } | undefined;
        if (r && typeof r === 'object' && 'status' in r && r.status !== 'success') return 'rejected';
        return 'accepted';
    } catch {
        return 'rejected';
    }
}

// ── OPEN (client-submit) through session().verify ───────────────────────

function openSession(store: SessionStore, rpc: unknown, splits?: readonly SessionSplit[]) {
    return session({
        cap: 5_000_000n,
        currency: USDC_MAINNET,
        decimals: 6,
        network: 'localnet',
        openTxSubmitter: 'client',
        operator: payer.address,
        pricing: {},
        recipient: payee.address,
        rpc: rpc as never,
        ...(splits ? { splits: [...splits] } : {}),
        store,
    });
}

function openCredential(transaction: string, signature: string) {
    return {
        challenge: {
            id: 'vb-open',
            intent: 'session',
            method: 'solana',
            realm: 'api.test',
            request: {
                cap: '5000000',
                currency: USDC_MAINNET,
                operator: payer.address,
                recipient: payee.address,
            },
        },
        payload: { action: 'open', authorizedSigner: authorizedSigner.address, mode: 'push', signature, transaction },
    } as unknown as Parameters<NonNullable<ReturnType<typeof session>['verify']>>[0]['credential'];
}

async function runOpen(
    rpc: unknown,
    transaction: string,
    signature: string,
    splits?: readonly SessionSplit[],
): Promise<'accepted' | 'rejected'> {
    const store = createMemorySessionStore();
    const method = openSession(store, rpc, splits);
    return await outcome(() => method.verify({ credential: openCredential(transaction, signature), request: {} as never }));
}

describe('value-binding: session OPEN verifier (verifyOpenTx via session)', () => {
    // (a) GREEN control: a real, confirmed signature that belongs to a DIFFERENT
    // open must be rejected by the signature<->transaction binding.
    it('(a) rejects a confirmed-but-unrelated signature paired with a different open tx [expect GREEN]', async () => {
        const open = await buildOpen({ deposit: 1_000_000n, salt: 7n });
        const otherOpen = await buildOpen({ deposit: 500_000n, salt: 8n });
        const otherSig = txSignature(otherOpen.transaction);
        const rpc = makeUnrelatedConfirmRpc([otherSig]);

        expect(await runOpen(rpc, open.transaction, otherSig)).toBe('rejected');
    });

    // (b) C1 shape: a placeholder/empty open signature WITH an RPC configured
    // must be rejected fleet-wide (no proof the deposit landed).
    it('(b) rejects a placeholder open signature when an RPC is configured (C1) [expect GREEN on current src]', async () => {
        const open = await buildOpen({ deposit: 1_000_000n });
        const rpc = makeUnrelatedConfirmRpc([]);

        expect(await runOpen(rpc, open.transaction, PLACEHOLDER_SIG)).toBe('rejected');
    });

    // (d) RED: the open commits a distribution (recipients[]) that diverges from
    // the merchant's configured splits, but verifyOpenTx never parses
    // recipients[] and handleOpen never passes the splits down. Everything else
    // (payee, deposit, PDA, a real bound+confirmed signature) is valid, so the
    // channel opens with an attacker distribution and settles to the attacker.
    it('(d) rejects an open whose recipients[] diverge from the configured splits [expect GREEN once open distribution-binding lands]', async () => {
        const open = await buildOpen({
            deposit: 1_000_000n,
            recipients: [{ bps: 10_000, recipient: attacker.address }], // 100% to attacker
        });
        const sig = txSignature(open.transaction);
        const rpc = makeUnrelatedConfirmRpc([sig]);
        // Merchant intends 100% to the payee; the open diverges from it.
        const merchantSplits: SessionSplit[] = [{ bps: 10_000, recipient: payee.address }];

        expect(await runOpen(rpc, open.transaction, sig, merchantSplits)).toBe('rejected');
    });

    // (e) GREEN: the open's on-chain payee (account slot 2) is the ATTACKER
    // instead of the merchant's configured recipient. Everything else — deposit
    // <= cap, mint, authorizedSigner, rentPayer==operator, and a real
    // bound+confirmed signature — is valid, isolating the payee<->recipient
    // binding. verifyOpenTx pins the payee to the challenge recipient
    // (on-chain.ts:618 `payeeAddr !== expected.recipient`; Go
    // session_onchain.go:230), so the divergence must be rejected and the
    // channel must never open with settlement routed to the attacker payee.
    // Pins the primary value-binding check every SDK's open verifier enforces.
    it('(e) rejects an open whose payee diverges from the configured recipient [expect GREEN]', async () => {
        const open = await buildOpen({ deposit: 1_000_000n, recipient: attacker.address });
        const sig = txSignature(open.transaction);
        const rpc = makeUnrelatedConfirmRpc([sig]);
        // Session expects payee.address; the open's payee is the attacker.
        expect(await runOpen(rpc, open.transaction, sig)).toBe('rejected');
    });
});

// ── TOP-UP through session().verify ─────────────────────────────────────

async function seedChannel(store: SessionStore, channelId: string, deposit: bigint): Promise<void> {
    await store.updateChannel(channelId, () => ({
        authorizedSigner: authorizedSigner.address,
        channelId,
        committedDeliveries: [],
        cumulative: 0n,
        deposit,
        sealed: false,
        nextDeliverySequence: 0n,
        pendingDeliveries: [],
    }));
}

function topUpSession(store: SessionStore, rpc: unknown) {
    return session({
        cap: 5_000_000n,
        currency: USDC_MAINNET,
        decimals: 6,
        network: 'localnet',
        operator: payer.address,
        pricing: {},
        recipient: payee.address,
        rpc: rpc as never,
        store,
    });
}

function topUpCredential(channelId: string, newDeposit: string, signature: string) {
    return {
        challenge: {
            id: 'vb-topup',
            intent: 'session',
            method: 'solana',
            realm: 'api.test',
            request: {
                cap: '5000000',
                currency: USDC_MAINNET,
                operator: payer.address,
                recipient: payee.address,
            },
        },
        payload: { action: 'topUp', channelId, newDeposit, signature },
    } as unknown as Parameters<NonNullable<ReturnType<typeof session>['verify']>>[0]['credential'];
}

async function runTopUp(
    store: SessionStore,
    rpc: unknown,
    channelId: string,
    newDeposit: string,
    signature: string,
): Promise<'accepted' | 'rejected'> {
    const method = topUpSession(store, rpc);
    return await outcome(() =>
        method.verify({ credential: topUpCredential(channelId, newDeposit, signature), request: {} as never }),
    );
}

describe('value-binding: session TOP-UP verifier (handleTopUp)', () => {
    // (a) a confirmed but UNRELATED signature paired with an inflated newDeposit
    // (<= cap). The signature confirms AND fetches back to a real transaction —
    // but that transaction carries NO payment-channels top_up instruction (here,
    // an unrelated open), so it proves nothing about raising this deposit. The
    // binding verifier must reject rather than raise 1_000_000 -> 5_000_000 on a
    // confirmed-but-unrelated signature.
    it('(a) rejects an unrelated confirmed signature (fetched tx has no top_up ix) paired with an inflated newDeposit [expect GREEN once top-up delta-binding lands]', async () => {
        const store = createMemorySessionStore();
        await seedChannel(store, SEED_CHANNEL, 1_000_000n);
        // A genuine, landed transaction that is not a top_up of this channel.
        const unrelated = await buildOpen({ deposit: 500_000n, salt: 9n });
        const rpc = makeBoundTxRpc({ UNRELATED_CONFIRMED_SIG: unrelated.transaction });

        expect(await runTopUp(store, rpc, SEED_CHANNEL, '5000000', 'UNRELATED_CONFIRMED_SIG')).toBe('rejected');
        // Effect assertion: the deposit must NOT have been raised.
        expect((await store.getChannel(SEED_CHANNEL))?.deposit).toBe(1_000_000n);
    });

    // (c) a REAL, confirmed top-up of THIS channel whose on-chain amount is +1
    // while the payload claims newDeposit-oldDeposit == +3_999_999. The signature
    // confirms and the fetched tx really is a top_up of SEED_CHANNEL, but its
    // committed delta contradicts the claim, so the binding verifier must reject
    // (an on-chain +1 must not license a +3_999_999 deposit bump).
    it('(c) rejects a top-up whose on-chain delta != newDeposit-oldDeposit [expect GREEN once top-up delta-binding lands]', async () => {
        const store = createMemorySessionStore();
        await seedChannel(store, SEED_CHANNEL, 1_000_000n);
        // Real top_up of SEED_CHANNEL, but only +1 on-chain.
        const realTopUp = await buildTopUpTx(SEED_CHANNEL, 1n);
        const rpc = makeBoundTxRpc({ REAL_TOPUP_DELTA_1: realTopUp });

        expect(await runTopUp(store, rpc, SEED_CHANNEL, '4999999', 'REAL_TOPUP_DELTA_1')).toBe('rejected');
        expect((await store.getChannel(SEED_CHANNEL))?.deposit).toBe(1_000_000n);
    });

    // (b) GREEN (via not-found): a placeholder signature WITH an RPC configured.
    // The open path rejects this with an explicit C1 guard; the top-up path has
    // no dedicated guard but still rejects because the placeholder is fed to
    // getSignatureStatuses and comes back not-found. Kept as a regression guard.
    it('(b) rejects a placeholder top-up signature when an RPC is configured [expect GREEN via not-found]', async () => {
        const store = createMemorySessionStore();
        await seedChannel(store, SEED_CHANNEL, 1_000_000n);
        const rpc = makeUnrelatedConfirmRpc([]);

        expect(await runTopUp(store, rpc, SEED_CHANNEL, '2000000', PLACEHOLDER_SIG)).toBe('rejected');
        expect((await store.getChannel(SEED_CHANNEL))?.deposit).toBe(1_000_000n);
    });
});

// ── JSON vector spec-mirror cross-check ─────────────────────────────────
// The executed teeth above are the inline (a)/(b)/(d)/(e) cases. The authored
// vectors under harness/vectors/value-binding/*.json mirror them as a cross-SDK
// spec (each lists the TS/Go/Python entrypoint). Nothing DROVE those JSON files,
// so a silent edit — deleting a case, or flipping `expect` to "accept" — would
// not be caught: the file looks like coverage but guards nothing, exactly the
// false-green class this suite exists to kill. This block reads them and pins
// their invariants to the executed roster: every value-binding case MUST assert
// rejection, and the id set is fixed, so a dropped / renamed / flipped case
// turns this RED. Refreshing the vectors means updating this roster (and the
// executed case above) in lockstep.
const vbHere = dirname(fileURLToPath(import.meta.url));
const vbDir = join(vbHere, '..', 'vectors', 'value-binding');

const VALUE_BINDING_ROSTER: Record<string, { verifier: string; ids: string[] }> = {
    'open.json': {
        verifier: 'session-open',
        ids: [
            'open-a-unrelated-confirmed-signature-binding-control',
            'open-b-placeholder-signature-with-rpc-c1',
            'open-d-distribution-diverges-from-splits',
            'open-e-payee-diverges-from-recipient',
        ],
    },
    'topup.json': {
        verifier: 'session-topup',
        ids: [
            'topup-a-unrelated-confirmed-inflated-deposit',
            'topup-b-placeholder-signature-with-rpc',
            'topup-c-onchain-delta-mismatch',
        ],
    },
};

describe('value-binding: authored JSON vectors are consumed (spec-mirror cross-check)', () => {
    for (const [file, expected] of Object.entries(VALUE_BINDING_ROSTER)) {
        describe(file, () => {
            const doc = JSON.parse(readFileSync(join(vbDir, file), 'utf8')) as {
                schema: string;
                verifier: string;
                cases: { id: string; expect: string }[];
            };

            it('declares the canonical value-binding schema + verifier', () => {
                expect(doc.schema).toBe('value-binding/v1');
                expect(doc.verifier).toBe(expected.verifier);
            });

            it('every case asserts REJECTION (no case may be flipped to accept)', () => {
                expect(doc.cases.length).toBeGreaterThan(0);
                for (const c of doc.cases) {
                    expect(c.expect, `${file} case ${c.id} must expect reject`).toBe('reject');
                }
            });

            it('case-id roster matches the executed inline cases (no silent add/drop/rename)', () => {
                const got = doc.cases.map((c) => c.id).sort();
                expect(got).toEqual([...expected.ids].sort());
            });
        });
    }
});
