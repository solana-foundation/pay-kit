// V2 lifecycle-hook ABI (payment-channels#102), pinned against the Rust kit's
// fixtures in `rust/crates/kit/src/core/payment_channel/v2.rs`: the fixed
// 824-byte descriptor layout and its golden SHA-256 commitment, the compact
// open suffix, the callback authority PDA seeds, the hooked discriminators
// and the deployment binding (program, version, hooks, network).

import { AccountRole, address, getAddressDecoder, getBase58Decoder } from '@solana/kit';
import { describe, expect, test } from 'vitest';

import {
    CANARY_PAYMENT_CHANNELS_PROGRAM,
    type ChannelHooks,
    decodeChannelHooks,
    DISTRIBUTE_WITH_HOOKS_DISCRIMINATOR,
    encodeFixedHookDescriptors,
    encodeOpenHookSuffix,
    findCallbackAuthorityPda,
    hookConfigHash,
    OPEN_WITH_HOOKS_DISCRIMINATOR,
    resolveChannelDeployment,
    sameChannelHooks,
    TOP_UP_WITH_HOOKS_DISCRIMINATOR,
    validateChannelHooks,
    WITHDRAW_PAYER_WITH_HOOKS_DISCRIMINATOR,
    withLifecycleHooks,
} from '../shared/channel-hooks.js';

const CHANNEL_PROGRAM = 'CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX';

function key(byte: number): string {
    return getBase58Decoder().decode(new Uint8Array(32).fill(byte));
}

/** The Rust `tests::hooks()` fixture: one preFund descriptor. */
function fixture(): ChannelHooks {
    return {
        preFund: {
            accounts: [{ address: key(9), writable: true }],
            entrypoint: Array.from(new TextEncoder().encode('prefund!')),
            programId: key(8),
            staticData: [4, 5],
        },
    };
}

describe('channel hooks ABI', () => {
    test('fixed descriptors and the golden commitment match the Rust kit', async () => {
        const hooks = fixture();
        const bytes = encodeFixedHookDescriptors(hooks);
        expect(bytes.length).toBe(824);
        expect(Array.from(bytes.slice(0, 32))).toEqual(new Array(32).fill(8));
        expect(new TextDecoder().decode(bytes.slice(32, 40))).toBe('prefund!');
        expect(Array.from(bytes.slice(40, 44))).toEqual([1, 2, 4, 5]);
        expect(bytes[106]).toBe(1);
        expect(bytes.slice(107).every(byte => byte === 0)).toBe(true);
        // Independent golden digest of the same fixture (v2.rs `fixed_and_compact_layouts`).
        const digest = await hookConfigHash(hooks);
        expect(Buffer.from(digest).toString('hex')).toBe(
            '2d8ebd54efccdcf0deceea66a270ba45bab8d6c0a6d8eab1f21a0d81f4c9cf4d',
        );
    });

    test('the compact open suffix encodes enabled slots only', () => {
        const compact = encodeOpenHookSuffix(fixture());
        expect(compact.length).toBe(1 + 42 + 2 + 33 + 3);
        expect(compact[0]).toBe(1);
        expect(Array.from(compact.slice(43, 45))).toEqual([4, 5]);
        expect(Array.from(compact.slice(compact.length - 3))).toEqual([0, 0, 0]);
        expect(Array.from(encodeOpenHookSuffix({}))).toEqual([0, 0, 0, 0]);
    });

    test('a stored V2 account round-trips through the decoder', async () => {
        const hooks = fixture();
        const data = new Uint8Array(1121);
        data[0] = 1;
        data[1] = 2;
        data.set(await hookConfigHash(hooks), 265);
        data.set(encodeFixedHookDescriptors(hooks), 297);
        const decoded = await decodeChannelHooks(data);
        expect(decoded.hooks).toEqual(hooks);
        expect(decoded.operationSequence).toBe(0n);
        expect(sameChannelHooks(decoded.hooks, hooks)).toBe(true);
        // A byte flipped anywhere in the commitment or descriptors is refused.
        for (const offset of [1, 256, 265, 297 + 44, 297 + 206 + 32]) {
            const bad = Uint8Array.from(data);
            bad[offset] = 255;
            await expect(decodeChannelHooks(bad)).rejects.toThrow();
        }
        await expect(decodeChannelHooks(data.slice(0, 256))).rejects.toThrow(/length/);
    });

    test('decoding validates targets against the selected owner', async () => {
        for (const [owner, other] of [
            [CHANNEL_PROGRAM, CANARY_PAYMENT_CHANNELS_PROGRAM],
            [CANARY_PAYMENT_CHANNELS_PROGRAM, CHANNEL_PROGRAM],
        ]) {
            for (const target of [owner!, other!]) {
                const hooks = { postDistribute: { ...fixture().preFund!, programId: target } };
                const data = new Uint8Array(1121);
                data[0] = 1;
                data[1] = 2;
                data.set(await hookConfigHash(hooks), 265);
                data.set(encodeFixedHookDescriptors(hooks), 297);
                if (target === owner) {
                    await expect(decodeChannelHooks(data, owner)).rejects.toThrow(/self target/);
                } else {
                    expect((await decodeChannelHooks(data, owner)).hooks).toEqual(hooks);
                }
            }
        }
    });

    test('hooked instructions get their own tag, the suffix and the pair bundle', async () => {
        const hooks: ChannelHooks = { ...fixture(), postDistribute: fixture().preFund };
        const channel = key(2);
        const base = {
            accounts: [{ address: address(key(1)), role: AccountRole.WRITABLE_SIGNER }],
            data: new Uint8Array([1, 7, 7, 7]),
            programAddress: address(CHANNEL_PROGRAM),
        };
        const open = await withLifecycleHooks(base, {
            channel,
            discriminator: OPEN_WITH_HOOKS_DISCRIMINATOR,
            hooks,
            phases: [0, 2],
            suffix: encodeOpenHookSuffix(hooks),
        });
        expect(open.data[0]).toBe(10);
        expect(Array.from(open.data.slice(1, 4))).toEqual([7, 7, 7]);
        expect(open.data.length).toBe(4 + encodeOpenHookSuffix(hooks).length);
        // preFund bundle: target, authority, one extra; the V1 account first.
        expect(open.accounts.length).toBe(1 + 3);
        expect(open.accounts[1]?.address).toBe(key(8));
        expect(open.accounts[1]?.role).toBe(AccountRole.READONLY);
        const authority = await findCallbackAuthorityPda({
            channel,
            configHash: await hookConfigHash(hooks),
            phase: 0,
            programAddress: CHANNEL_PROGRAM,
            target: key(8),
        });
        expect(open.accounts[2]?.address).toBe(authority);
        expect(open.accounts[3]?.role).toBe(AccountRole.WRITABLE);
        expect(open.accounts.slice(1).every(account => !('signer' in account))).toBe(true);

        const distribute = await withLifecycleHooks(base, {
            channel,
            discriminator: DISTRIBUTE_WITH_HOOKS_DISCRIMINATOR,
            hooks,
            phases: [2, 4],
        });
        expect(distribute.data[0]).toBe(12);
        expect(distribute.data.length).toBe(4);
        // The distribution pair's authority is phase 3: distinct from phase 0.
        expect(distribute.accounts[2]?.address).not.toBe(authority);
        expect([TOP_UP_WITH_HOOKS_DISCRIMINATOR, WITHDRAW_PAYER_WITH_HOOKS_DISCRIMINATOR]).toEqual([11, 13]);
        // Disabled pair: no bundle.
        const topUp = await withLifecycleHooks(base, {
            channel,
            discriminator: TOP_UP_WITH_HOOKS_DISCRIMINATOR,
            hooks: { postDistribute: fixture().preFund },
            phases: [0, 2],
        });
        expect(topUp.accounts.length).toBe(1);
    });

    test('bounds, aliases and the zero or self target are refused', () => {
        const good = fixture();
        expect(() => validateChannelHooks(good, CHANNEL_PROGRAM)).not.toThrow();
        const self = { preFund: { ...good.preFund!, programId: CHANNEL_PROGRAM } };
        expect(() => validateChannelHooks(self, CHANNEL_PROGRAM)).toThrow(/zero or self/);
        const zero = { preFund: { ...good.preFund!, programId: getAddressDecoder().decode(new Uint8Array(32)) } };
        expect(() => validateChannelHooks(zero, CHANNEL_PROGRAM)).toThrow(/zero or self/);
        const tooMany = {
            preFund: { ...good.preFund!, accounts: [3, 4, 5, 6, 7].map(n => ({ address: key(n), writable: false })) },
        };
        expect(() => validateChannelHooks(tooMany, CHANNEL_PROGRAM)).toThrow(/bounds/);
        const duplicate = {
            preFund: { ...good.preFund!, accounts: [key(9), key(9)].map(a => ({ address: a, writable: true })) },
        };
        expect(() => validateChannelHooks(duplicate, CHANNEL_PROGRAM)).toThrow(/duplicate/);
        const shortEntrypoint = { preFund: { ...good.preFund!, entrypoint: [1, 2, 3] } };
        expect(() => validateChannelHooks(shortEntrypoint, CHANNEL_PROGRAM)).toThrow(/8 bytes/);
    });

    test('the deployment binds program, version, hooks and network as one tuple', () => {
        expect(resolveChannelDeployment({ channelProgram: CHANNEL_PROGRAM }).channelVersion).toBe(1);
        expect(resolveChannelDeployment({ channelProgram: CANARY_PAYMENT_CHANNELS_PROGRAM }).channelVersion).toBe(1);
        expect(
            resolveChannelDeployment({ channelProgram: CHANNEL_PROGRAM, channelVersion: 2, network: 'devnet' })
                .channelVersion,
        ).toBe(2);
        expect(
            resolveChannelDeployment({
                channelHooks: fixture(),
                channelProgram: CANARY_PAYMENT_CHANNELS_PROGRAM,
                channelVersion: 2,
                network: 'localnet',
            }).channelHooks,
        ).toEqual(fixture());
        expect(() => resolveChannelDeployment({ channelProgram: key(5) })).toThrow(/unknown channel program/);
        expect(() => resolveChannelDeployment({ channelProgram: CHANNEL_PROGRAM, channelVersion: 3 })).toThrow(
            /unsupported channel ABI version/,
        );
        expect(() => resolveChannelDeployment({ channelHooks: fixture(), channelProgram: CHANNEL_PROGRAM })).toThrow(
            /channelHooks requires the V2/,
        );
        expect(() =>
            resolveChannelDeployment({ channelProgram: CHANNEL_PROGRAM, channelVersion: 2, network: 'mainnet' }),
        ).toThrow(/devnet and localnet/);
    });
});
