// V2 payment-channel profile: lifecycle hooks (payment-channels#102).
//
// A hooked channel commits four immutable callback descriptors at `open`
// (`preFund`, `postFund`, `preDistribute`, `postDistribute`). The hooked
// instruction family has its own discriminators — `openWithHooks` (10),
// `topUpWithHooks` (11), `distributeWithHooks` (12), `withdrawPayerWithHooks`
// (13) — and each hooked instruction appends, after its V1 accounts, one
// bundle per enabled slot of its active pair: the target program, the
// callback authority PDA and the committed extra accounts. `openWithHooks`
// also appends the compact four-slot configuration after the V1 payload.
//
// Mirrors `rust/crates/kit/src/core/payment_channel/v2.rs`. The hook
// programs are never executed here; this module only encodes what the
// channel program commits and verifies.

import {
    type AccountMeta,
    AccountRole,
    type Address,
    address,
    getAddressEncoder,
    getBase58Decoder,
    getProgramDerivedAddress,
    type Instruction,
    type ReadonlyUint8Array,
} from '@solana/kit';

import { normalizeNetwork } from '../constants.js';
import { PAYMENT_CHANNELS_PROGRAM_ADDRESS } from '../generated/payment-channels/programs/paymentChannels.js';

/** A V1 channel account (the frozen prefix of a V2 account). */
export const CHANNEL_V1_ACCOUNT_SIZE = 256;
/** A hooked (V2) channel account: the V1 prefix plus guard, sequence, commitment and four descriptors. */
export const CHANNEL_V2_ACCOUNT_SIZE = 1121;
export const HOOK_DESCRIPTOR_SIZE = 206;
export const HOOK_FIXED_CONFIG_SIZE = 4 * HOOK_DESCRIPTOR_SIZE;
export const MAX_HOOK_ACCOUNTS = 4;
export const MAX_HOOK_STATIC_DATA = 32;
export const HOOK_ENTRYPOINT_LENGTH = 8;

export const OPEN_WITH_HOOKS_DISCRIMINATOR = 10;
export const TOP_UP_WITH_HOOKS_DISCRIMINATOR = 11;
export const DISTRIBUTE_WITH_HOOKS_DISCRIMINATOR = 12;
export const WITHDRAW_PAYER_WITH_HOOKS_DISCRIMINATOR = 13;

/** Seed of the callback authority PDA, the only signer forwarded to a callback. */
export const CALLBACK_AUTHORITY_SEED = 'channel_hook';

/**
 * The canary deployment (`Solex.toml` channel `canary`). Both known programs
 * run the dual-version runtime: V1 and hooked V2 accounts load at the same
 * address, so the ABI version is explicit configuration, never inferred
 * from the program id.
 */
export const CANARY_PAYMENT_CHANNELS_PROGRAM = 'CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ';

const ZERO_ADDRESS = '11111111111111111111111111111111';

/** Channel ABI version: 1 (the audited V1 surface) or 2 (lifecycle hooks). */
export type ChannelVersion = 1 | 2;

/** Hook phase: the slot index. */
export type HookPhase = 0 | 1 | 2 | 3;

export const HOOK_SLOTS = ['preFund', 'postFund', 'preDistribute', 'postDistribute'] as const;
export type HookSlot = (typeof HOOK_SLOTS)[number];

/** An extra account a callback receives; never a signer. */
export interface HookAccount {
    readonly address: string;
    readonly writable: boolean;
}

/** One committed callback: target program, 8-byte entrypoint, extras and static context. */
export interface HookDescriptor {
    readonly accounts?: HookAccount[] | undefined;
    readonly entrypoint: number[];
    readonly programId: string;
    readonly staticData?: number[] | undefined;
}

/** The four optional slots, committed at open and immutable afterwards. */
export interface ChannelHooks {
    readonly postDistribute?: HookDescriptor | undefined;
    readonly postFund?: HookDescriptor | undefined;
    readonly preDistribute?: HookDescriptor | undefined;
    readonly preFund?: HookDescriptor | undefined;
}

/** The slots in phase order. */
export function hookSlots(hooks: ChannelHooks): readonly (HookDescriptor | undefined)[] {
    return HOOK_SLOTS.map(slot => hooks[slot]);
}

/** Whether any slot is enabled. */
export function hasEnabledHooks(hooks: ChannelHooks | undefined): boolean {
    return hooks !== undefined && hookSlots(hooks).some(slot => slot !== undefined);
}

function invalid(message: string): Error {
    return new Error(`payment-channel ABI: ${message}`);
}

function addressBytes(value: string, what: string): Uint8Array {
    try {
        return new Uint8Array(getAddressEncoder().encode(address(value)));
    } catch {
        throw invalid(`${what} is not a base58 address`);
    }
}

/**
 * Validate a hook configuration against the channel program it will be
 * committed on: enabled targets are neither the zero address nor the
 * channel program; at most four extras and 32 static bytes; no duplicate
 * extras and none aliasing the target. Mirrors `ChannelHooks::validate`.
 */
export function validateChannelHooks(hooks: ChannelHooks, channelProgram: string): void {
    for (const descriptor of hookSlots(hooks)) {
        if (!descriptor) continue;
        if (descriptor.programId === ZERO_ADDRESS || descriptor.programId === channelProgram) {
            throw invalid('enabled hook has zero or self target program');
        }
        addressBytes(descriptor.programId, 'hook target program');
        if (descriptor.entrypoint.length !== HOOK_ENTRYPOINT_LENGTH) {
            throw invalid(`hook entrypoint must be ${HOOK_ENTRYPOINT_LENGTH} bytes`);
        }
        const accounts = descriptor.accounts ?? [];
        const staticData = descriptor.staticData ?? [];
        if (accounts.length > MAX_HOOK_ACCOUNTS || staticData.length > MAX_HOOK_STATIC_DATA) {
            throw invalid('hook exceeds account or static-data bounds');
        }
        for (const byte of [...descriptor.entrypoint, ...staticData]) {
            if (!Number.isInteger(byte) || byte < 0 || byte > 255) throw invalid('hook bytes must be 0 through 255');
        }
        const seen = new Set<string>();
        for (const account of accounts) {
            addressBytes(account.address, 'hook account');
            if (typeof account.writable !== 'boolean') throw invalid('hook account writable must be a boolean');
            if (account.address === descriptor.programId || seen.has(account.address)) {
                throw invalid('duplicate or target-aliasing hook account');
            }
            seen.add(account.address);
        }
    }
}

/**
 * The compact configuration `openWithHooks` appends after the V1 open
 * payload: per slot an enabled byte, then `program | entrypoint |
 * account_count | static_len | static | (address | writable) × count`.
 */
export function encodeOpenHookSuffix(hooks: ChannelHooks): Uint8Array {
    const out: number[] = [];
    for (const descriptor of hookSlots(hooks)) {
        if (!descriptor) {
            out.push(0);
            continue;
        }
        const accounts = descriptor.accounts ?? [];
        const staticData = descriptor.staticData ?? [];
        out.push(1);
        out.push(...addressBytes(descriptor.programId, 'hook target program'));
        out.push(...descriptor.entrypoint);
        out.push(accounts.length, staticData.length);
        out.push(...staticData);
        for (const account of accounts) {
            out.push(...addressBytes(account.address, 'hook account'), account.writable ? 1 : 0);
        }
    }
    return Uint8Array.from(out);
}

/**
 * The four fixed 206-byte descriptors stored in the account (bytes 297..1121),
 * zero-padded; a disabled slot is entirely zero.
 */
export function encodeFixedHookDescriptors(hooks: ChannelHooks): Uint8Array {
    const out = new Uint8Array(HOOK_FIXED_CONFIG_SIZE);
    hookSlots(hooks).forEach((descriptor, index) => {
        if (!descriptor) return;
        const base = index * HOOK_DESCRIPTOR_SIZE;
        const accounts = descriptor.accounts ?? [];
        const staticData = descriptor.staticData ?? [];
        out.set(addressBytes(descriptor.programId, 'hook target program'), base);
        out.set(Uint8Array.from(descriptor.entrypoint), base + 32);
        out[base + 40] = accounts.length;
        out[base + 41] = staticData.length;
        out.set(Uint8Array.from(staticData), base + 42);
        accounts.forEach((account, slot) => {
            const at = base + 74 + slot * 33;
            out.set(addressBytes(account.address, 'hook account'), at);
            out[at + 32] = account.writable ? 1 : 0;
        });
    });
    return out;
}

/** SHA-256 of the fixed 824 descriptor bytes: the on-chain commitment. */
export async function hookConfigHash(hooks: ChannelHooks): Promise<Uint8Array> {
    const bytes = encodeFixedHookDescriptors(hooks);
    const digest = await crypto.subtle.digest('SHA-256', bytes.buffer as ArrayBuffer);
    return new Uint8Array(digest);
}

/**
 * The callback authority PDA under the channel program: seeds
 * `["channel_hook", channel, commitment, phase, target]`. The program signs
 * the callback CPI with it alone; the escrow authority is never forwarded.
 */
export async function findCallbackAuthorityPda(args: {
    readonly channel: string;
    readonly configHash: ReadonlyUint8Array;
    readonly phase: HookPhase;
    readonly programAddress: string;
    readonly target: string;
}): Promise<Address> {
    const [authority] = await getProgramDerivedAddress({
        programAddress: address(args.programAddress),
        seeds: [
            new TextEncoder().encode(CALLBACK_AUTHORITY_SEED),
            getAddressEncoder().encode(address(args.channel)),
            args.configHash,
            new Uint8Array([args.phase]),
            getAddressEncoder().encode(address(args.target)),
        ],
    });
    return authority;
}

/**
 * The account bundles a hooked instruction appends for the active pair
 * `phases` (`[0, 2)` for funding, `[2, 4)` for distribution): per enabled
 * slot the target program and callback authority (read-only) and the
 * committed extras with their declared writability, never signers.
 */
export async function hookAccountBundle(args: {
    readonly channel: string;
    readonly hooks: ChannelHooks;
    /** The active pair as a half-open range: `[0, 2]` funding, `[2, 4]` distribution. */
    readonly phases: readonly [number, number];
    readonly programAddress: string;
}): Promise<AccountMeta[]> {
    const hash = await hookConfigHash(args.hooks);
    const slots = hookSlots(args.hooks);
    const out: AccountMeta[] = [];
    for (let phase = args.phases[0]; phase < args.phases[1]; phase++) {
        const descriptor = slots[phase];
        if (!descriptor) continue;
        const authority = await findCallbackAuthorityPda({
            channel: args.channel,
            configHash: hash,
            phase: phase as HookPhase,
            programAddress: args.programAddress,
            target: descriptor.programId,
        });
        out.push({ address: address(descriptor.programId), role: AccountRole.READONLY });
        out.push({ address: authority, role: AccountRole.READONLY });
        for (const account of descriptor.accounts ?? []) {
            if (account.address === args.channel || account.address === authority) {
                throw invalid('hook extra aliases channel or callback authority');
            }
            out.push({
                address: address(account.address),
                role: account.writable ? AccountRole.WRITABLE : AccountRole.READONLY,
            });
        }
    }
    return out;
}

/** A hooked instruction: the V1 instruction with the hooked tag, optional suffix and bundle. */
export interface HookedInstruction {
    readonly accounts: readonly AccountMeta[];
    readonly data: Uint8Array;
    readonly programAddress: Address;
}

/**
 * Turn a V1 channel instruction into its hooked variant: the discriminator
 * is replaced, `suffix` (the open's compact configuration) is appended to
 * the data, and the active pair's account bundle is appended to the
 * accounts. The V1 accounts and arguments are unchanged.
 */
export async function withLifecycleHooks(
    instruction: Instruction,
    args: {
        readonly channel: string;
        readonly discriminator: number;
        readonly hooks: ChannelHooks;
        /** The active pair as a half-open range: `[0, 2]` funding, `[2, 4]` distribution. */
        readonly phases: readonly [number, number];
        readonly suffix?: Uint8Array | undefined;
    },
): Promise<HookedInstruction> {
    const programAddress = instruction.programAddress;
    validateChannelHooks(args.hooks, programAddress);
    const base = instruction.data ?? new Uint8Array();
    const data = new Uint8Array(base.length + (args.suffix?.length ?? 0));
    data.set(base, 0);
    data[0] = args.discriminator;
    if (args.suffix) data.set(args.suffix, base.length);
    const bundle = await hookAccountBundle({
        channel: args.channel,
        hooks: args.hooks,
        phases: args.phases,
        programAddress,
    });
    return { accounts: [...(instruction.accounts ?? []), ...bundle], data, programAddress };
}

/** A known program bound to an explicit ABI version and hook policy. */
export interface ChannelDeployment {
    readonly channelHooks: ChannelHooks | undefined;
    readonly channelVersion: ChannelVersion;
    readonly programAddress: Address;
}

/**
 * Bind a channel program, ABI version, hook policy and network as one
 * configured tuple (mpp-specs-v2 Versioned Channel Profiles). An absent
 * version is V1; version 2 selects the hooked instruction family and is
 * supported on devnet and localnet only; hooks require version 2. Mirrors
 * `Deployment::resolve` and `channel_deployment::resolve_for_network`.
 */
export function resolveChannelDeployment(args: {
    readonly channelHooks?: ChannelHooks | undefined;
    readonly channelProgram?: string | undefined;
    readonly channelVersion?: number | undefined;
    readonly network?: string | undefined;
}): ChannelDeployment {
    const program = args.channelProgram ?? PAYMENT_CHANNELS_PROGRAM_ADDRESS;
    if (program !== PAYMENT_CHANNELS_PROGRAM_ADDRESS && program !== CANARY_PAYMENT_CHANNELS_PROGRAM) {
        throw invalid(`unknown channel program ${program}`);
    }
    const version = args.channelVersion ?? 1;
    if (version !== 1 && version !== 2) {
        throw invalid(`unsupported channel ABI version ${String(args.channelVersion)}`);
    }
    if (version === 1 && args.channelHooks !== undefined) {
        throw invalid('channelHooks requires the V2 channel deployment (channelVersion 2)');
    }
    if (version === 2) {
        if (args.network !== undefined) {
            const network = normalizeNetwork(args.network);
            if (network !== 'devnet' && network !== 'localnet') {
                throw invalid('V2 channel deployment supports only devnet and localnet');
            }
        }
        if (args.channelHooks) validateChannelHooks(args.channelHooks, program);
    }
    return { channelHooks: args.channelHooks, channelVersion: version, programAddress: address(program) };
}

/** The hook extension of a decoded V2 channel account. */
export interface DecodedChannelHooks {
    /** SHA-256 commitment stored at bytes 265..297. */
    readonly configHash: Uint8Array;
    readonly hooks: ChannelHooks;
    /** Operation sequence, u64 little-endian at bytes 257..265. */
    readonly operationSequence: bigint;
}

/**
 * Decode the hook extension of a 1121-byte V2 channel account: version 2,
 * idle guard, canonical zero padding, and a commitment equal to the SHA-256
 * of the stored descriptors. The V1 prefix (bytes 0..256) is left to the
 * generated `Channel` decoder. Mirrors `payment_channels_v2::decode_channel`.
 */
export async function decodeChannelHooks(
    data: ReadonlyUint8Array,
    programAddress: string = PAYMENT_CHANNELS_PROGRAM_ADDRESS,
): Promise<DecodedChannelHooks> {
    if (data.length !== CHANNEL_V2_ACCOUNT_SIZE) throw invalid('invalid V2 channel length');
    if (data[0] !== 1 || data[1] !== 2) throw invalid('invalid channel discriminator or version');
    if (data[256] !== 0) throw invalid('channel callback guard is active');
    const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
    const operationSequence = view.getBigUint64(257, true);
    const configHash = new Uint8Array(data.slice(265, 297));
    const base58 = getBase58Decoder();
    const slots: (HookDescriptor | undefined)[] = [];
    for (let index = 0; index < 4; index++) {
        const raw = data.slice(297 + index * HOOK_DESCRIPTOR_SIZE, 297 + (index + 1) * HOOK_DESCRIPTOR_SIZE);
        if (raw.slice(0, 32).every(byte => byte === 0)) {
            if (raw.some(byte => byte !== 0)) throw invalid('disabled hook has nonzero payload');
            slots.push(undefined);
            continue;
        }
        const count = raw[40] ?? 0;
        const length = raw[41] ?? 0;
        if (count > MAX_HOOK_ACCOUNTS || length > MAX_HOOK_STATIC_DATA) throw invalid('invalid hook bounds');
        if (
            raw.slice(42 + length, 74).some(byte => byte !== 0) ||
            raw.slice(74 + count * 33).some(byte => byte !== 0)
        ) {
            throw invalid('noncanonical hook padding');
        }
        const accounts: HookAccount[] = [];
        for (let slot = 0; slot < count; slot++) {
            const at = 74 + slot * 33;
            const writable = raw[at + 32];
            if (writable !== 0 && writable !== 1) throw invalid('invalid hook writable flag');
            accounts.push({ address: base58.decode(raw.slice(at, at + 32)), writable: writable === 1 });
        }
        slots.push({
            accounts,
            entrypoint: Array.from(raw.slice(32, 40)),
            programId: base58.decode(raw.slice(0, 32)),
            staticData: Array.from(raw.slice(42, 42 + length)),
        });
    }
    const [preFund, postFund, preDistribute, postDistribute] = slots;
    const hooks: ChannelHooks = {
        ...(preFund ? { preFund } : {}),
        ...(postFund ? { postFund } : {}),
        ...(preDistribute ? { preDistribute } : {}),
        ...(postDistribute ? { postDistribute } : {}),
    };
    validateChannelHooks(hooks, programAddress);
    const expected = await hookConfigHash(hooks);
    if (!expected.every((byte, index) => byte === configHash[index])) {
        throw invalid('hook configuration hash mismatch');
    }
    return { configHash, hooks, operationSequence };
}

/** Whether two hook policies commit the same descriptors (the same on-chain bytes). */
export function sameChannelHooks(left: ChannelHooks | undefined, right: ChannelHooks | undefined): boolean {
    const a = encodeFixedHookDescriptors(left ?? {});
    const b = encodeFixedHookDescriptors(right ?? {});
    return a.every((byte, index) => byte === b[index]);
}
