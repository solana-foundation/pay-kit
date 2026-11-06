/**
 * V2 (hooked) payment-channel instruction transforms — a faithful port of
 * `rust/crates/kit/src/core/payment_channel/v2.rs`.
 *
 * Why this file exists: the TypeScript payment-channels client in
 * `@solana/mpp` is generated for the V1 channel program
 * (`CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX`) and has no hooked
 * instruction builders, while Musebook credit channels live on the V2
 * deployment (`CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ`). A hooked
 * instruction is exactly the V1 instruction with (a) its discriminator
 * byte retagged, (b) for `open`, the compact hook suffix appended to the
 * data, and (c) the callback accounts appended — the program signs only
 * the dedicated callback-authority PDAs. Until a generated V2 client
 * lands in the SDK, this example carries the transform itself; every
 * layout below is byte-for-byte the Rust one.
 */
import {
    AccountRole,
    type Address,
    address,
    getAddressEncoder,
    getProgramDerivedAddress,
    type Instruction,
} from '@solana/kit';
import { type ChannelHooks, type HookDescriptor, PAYMENT_CHANNELS_V2_PROGRAM_ID } from '@solana/mpp/client';

export const OPEN_WITH_HOOKS_DISCRIMINATOR = 10;
export const TOP_UP_WITH_HOOKS_DISCRIMINATOR = 11;
export const DISTRIBUTE_WITH_HOOKS_DISCRIMINATOR = 12;
export const WITHDRAW_PAYER_WITH_HOOKS_DISCRIMINATOR = 13;

const HOOK_DESCRIPTOR_SIZE = 206;
const MAX_HOOK_ACCOUNTS = 4;
const MAX_STATIC_DATA = 32;
const ZERO_ADDRESS = '11111111111111111111111111111111';

type AccountMeta = { readonly address: Address; readonly role: AccountRole };

function slots(hooks: ChannelHooks): (HookDescriptor | undefined)[] {
    return [hooks.preFund, hooks.postFund, hooks.preDistribute, hooks.postDistribute];
}

function addressBytes(value: string): Uint8Array {
    return new Uint8Array(getAddressEncoder().encode(address(value)));
}

/** Mirror of Rust `ChannelHooks::validate`. */
export function validateHooks(hooks: ChannelHooks): void {
    for (const hook of slots(hooks)) {
        if (!hook) continue;
        if (hook.programId === ZERO_ADDRESS || hook.programId === PAYMENT_CHANNELS_V2_PROGRAM_ID) {
            throw new Error('payment-channel ABI: enabled hook has zero or self target program');
        }
        if (hook.accounts.length > MAX_HOOK_ACCOUNTS || hook.staticData.length > MAX_STATIC_DATA) {
            throw new Error('payment-channel ABI: hook exceeds account or static-data bounds');
        }
        const seen = new Set<string>();
        for (const account of hook.accounts) {
            if (seen.has(account.address) || account.address === hook.programId) {
                throw new Error('payment-channel ABI: duplicate or target-aliasing hook account');
            }
            seen.add(account.address);
        }
    }
}

/** Compact `open` suffix: per slot, an enabled byte then only used data/accounts. */
export function encodeOpenSuffix(hooks: ChannelHooks): Uint8Array {
    validateHooks(hooks);
    const bytes: number[] = [];
    for (const hook of slots(hooks)) {
        bytes.push(hook ? 1 : 0);
        if (!hook) continue;
        bytes.push(...addressBytes(hook.programId));
        bytes.push(...hook.entrypoint);
        bytes.push(hook.accounts.length, hook.staticData.length);
        bytes.push(...hook.staticData);
        for (const account of hook.accounts) {
            bytes.push(...addressBytes(account.address));
            bytes.push(account.writable ? 1 : 0);
        }
    }
    return new Uint8Array(bytes);
}

/** Canonical fixed representation (4 × 206 bytes); unused bytes are zero. */
export function encodeFixed(hooks: ChannelHooks): Uint8Array {
    validateHooks(hooks);
    const bytes = new Uint8Array(4 * HOOK_DESCRIPTOR_SIZE);
    slots(hooks).forEach((hook, index) => {
        if (!hook) return;
        const out = bytes.subarray(index * HOOK_DESCRIPTOR_SIZE, (index + 1) * HOOK_DESCRIPTOR_SIZE);
        out.set(addressBytes(hook.programId), 0);
        out.set(hook.entrypoint, 32);
        out[40] = hook.accounts.length;
        out[41] = hook.staticData.length;
        out.set(hook.staticData, 42);
        hook.accounts.forEach((account, accountIndex) => {
            const offset = 74 + accountIndex * 33;
            out.set(addressBytes(account.address), offset);
            out[offset + 32] = account.writable ? 1 : 0;
        });
    });
    return bytes;
}

/** `sha256(encode_fixed(hooks))` — the hash stored in the channel account. */
export async function configHash(hooks: ChannelHooks): Promise<Uint8Array> {
    return new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(encodeFixed(hooks))));
}

/** Capability PDA: the program signs only this dedicated callback authority. */
export async function findCallbackAuthority(
    channel: string,
    hash: Uint8Array,
    phase: number,
    target: string,
): Promise<string> {
    if (phase > 3) throw new Error('payment-channel ABI: invalid callback phase');
    const [derived] = await getProgramDerivedAddress({
        programAddress: address(PAYMENT_CHANNELS_V2_PROGRAM_ID),
        seeds: [
            new Uint8Array([99, 104, 97, 110, 110, 101, 108, 95, 104, 111, 111, 107]), // "channel_hook"
            addressBytes(channel),
            new Uint8Array(hash),
            new Uint8Array([phase]),
            addressBytes(target),
        ],
    });
    return derived.toString();
}

/**
 * Callback accounts for `phases` (0..2 for fund-side instructions, 2..4
 * for distribute-side ones), appended in slot order: hook program
 * (readonly), callback authority (readonly), then the hook's accounts.
 * Additional callback accounts never acquire signer privileges.
 */
async function appendedHookAccounts(
    channel: string,
    hooks: ChannelHooks,
    phases: readonly number[],
): Promise<AccountMeta[]> {
    const hash = await configHash(hooks);
    const metas: AccountMeta[] = [];
    for (const phase of phases) {
        const hook = slots(hooks)[phase];
        if (!hook) continue;
        const authority = await findCallbackAuthority(channel, hash, phase, hook.programId);
        metas.push({ address: address(hook.programId), role: AccountRole.READONLY });
        metas.push({ address: address(authority), role: AccountRole.READONLY });
        for (const account of hook.accounts) {
            if (account.address === channel || account.address === authority) {
                throw new Error('payment-channel ABI: hook extra aliases channel or callback authority');
            }
            metas.push({
                address: address(account.address),
                role: account.writable ? AccountRole.WRITABLE : AccountRole.READONLY,
            });
        }
    }
    return metas;
}

function retag(base: Instruction, hooks: ChannelHooks, tag: number): Uint8Array {
    const data = new Uint8Array(base.data ?? []);
    if (slots(hooks).some(hook => hook !== undefined)) data[0] = tag;
    return data;
}

function withAccounts(base: Instruction, data: Uint8Array, extra: AccountMeta[]): Instruction {
    return { accounts: [...(base.accounts ?? []), ...extra], data, programAddress: base.programAddress };
}

/** V1 open instruction → OpenWithHooks (discriminator 10 + open suffix). */
export async function buildOpenWithHooks(
    base: Instruction,
    hooks: ChannelHooks,
    channel: string,
): Promise<Instruction> {
    const head = retag(base, hooks, OPEN_WITH_HOOKS_DISCRIMINATOR);
    const data = new Uint8Array(head.length + encodeOpenSuffix(hooks).length);
    data.set(head, 0);
    data.set(encodeOpenSuffix(hooks), head.length);
    return withAccounts(base, data, await appendedHookAccounts(channel, hooks, [0, 1]));
}

/** V1 distribute instruction → DistributeWithHooks (discriminator 12). */
export async function buildDistributeWithHooks(
    base: Instruction,
    hooks: ChannelHooks,
    channel: string,
): Promise<Instruction> {
    return withAccounts(
        base,
        retag(base, hooks, DISTRIBUTE_WITH_HOOKS_DISCRIMINATOR),
        await appendedHookAccounts(channel, hooks, [2, 3]),
    );
}

/** V1 withdraw-payer instruction → WithdrawPayerWithHooks (discriminator 13). */
export async function buildWithdrawPayerWithHooks(
    base: Instruction,
    hooks: ChannelHooks,
    channel: string,
): Promise<Instruction> {
    return withAccounts(
        base,
        retag(base, hooks, WITHDRAW_PAYER_WITH_HOOKS_DISCRIMINATOR),
        await appendedHookAccounts(channel, hooks, [2, 3]),
    );
}
