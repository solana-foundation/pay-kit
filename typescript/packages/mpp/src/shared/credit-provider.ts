/**
 * Merchant-facing credit-provider policy, independent of payment protocols.
 *
 * Mirrors `rust/crates/kit/src/core/credit_provider` (pay-kit PRs #411/#414):
 * a merchant only ever selects a provider *name*. Program IDs, entrypoints,
 * seeds and hook accounts are pinned per deployment and are never
 * caller-supplied. Only devnet has a reviewed Musebook deployment; every
 * other network is unavailable, and every check in this module fails closed.
 */
import { address, getAddressEncoder, getProgramDerivedAddress, getUtf8Encoder } from '@solana/kit';
import { findAssociatedTokenPda } from '@solana-program/token';

import { TOKEN_PROGRAM } from '../constants.js';

/** A recognized credit provider a merchant wants to accept alongside currency. */
export type CreditProvider = 'coinflow' | 'musebook';

/** One hook account, in the exact order the provider program expects. */
export interface HookAccount {
    readonly address: string;
    readonly writable: boolean;
}

/**
 * One lifecycle callback descriptor. `entrypoint` and `staticData` are byte
 * arrays on the wire, exactly as the Rust `HookDescriptor` serializes them.
 */
export interface HookDescriptor {
    readonly accounts: HookAccount[];
    readonly entrypoint: number[];
    readonly programId: string;
    readonly staticData: number[];
}

/** The four V2 lifecycle hook slots; absent slots are unset. */
export interface ChannelHooks {
    readonly postDistribute?: HookDescriptor | undefined;
    readonly postFund?: HookDescriptor | undefined;
    readonly preDistribute?: HookDescriptor | undefined;
    readonly preFund?: HookDescriptor | undefined;
}

/** Callback entrypoint discriminator checked by the provider program. */
export const MUSEBOOK_ENTRYPOINT: number[] = [...getUtf8Encoder().encode('musebook')];
export const MUSEBOOK_LEDGER_SEED = 'musebook-credit';
export const MUSEBOOK_CONFIG_SEED = 'musebook-config';
/**
 * Hooked channel instructions run the provider callback inside the channel
 * instruction, so credit opens/top-ups always request this explicit limit.
 */
export const MUSEBOOK_COMPUTE_UNIT_LIMIT = 400_000;
/** The provider custodies classic SPL Token mints only. */
export const SPL_TOKEN_PROGRAM_ID = TOKEN_PROGRAM;
/** Longest authorization window (slots past `open_slot`) an issuer co-signs. */
export const MAX_AUTHORIZATION_SLOTS = 9_000n;

/** Reviewed Musebook provider program ID on devnet (Squads 2-of-3 governed). */
export const MUSEBOOK_DEVNET_PROGRAM_ID = '97F68uhs5fmvddJxH1LrKytbBXrhx6ZBZwuZAdUdP7QA';
/**
 * Payment-channels program whose callbacks the provider accepts: the V2
 * hooks deployment. This is *not* the V1 program the generated TypeScript
 * client targets (`PAYMENT_CHANNELS_PROGRAM_ADDRESS`); credit channels live
 * on this deployment only.
 */
export const PAYMENT_CHANNELS_V2_PROGRAM_ID = 'CHNLxBtXw7VPqd5GMcbtVoEbn4ehyaSoiHj56Ao5sWkJ';

/** A reviewed, pinned deployment of the provider and the channel program it trusts. */
export interface CreditDeployment {
    /** Payment-channels program whose callbacks the provider accepts. */
    readonly channelProgramId: string;
    /** Cluster name the deployment is pinned to (`'devnet'`). */
    readonly cluster: string;
    /** Provider program ID for this deployment. */
    readonly programId: string;
}

/** Devnet: provider `97F68uhs…` trusting the V2-hooks channel deployment `CHNLxBt…`. */
export const MUSEBOOK_DEVNET_DEPLOYMENT: CreditDeployment = {
    channelProgramId: PAYMENT_CHANNELS_V2_PROGRAM_ID,
    cluster: 'devnet',
    programId: MUSEBOOK_DEVNET_PROGRAM_ID,
};

/** Thrown when a selected credit provider cannot be used. Always fail-closed. */
export class CreditProviderError extends Error {
    readonly provider: CreditProvider;
    constructor(provider: CreditProvider, message: string) {
        super(message);
        this.name = 'CreditProviderError';
        this.provider = provider;
    }
}

function unavailable(provider: CreditProvider): CreditProviderError {
    return new CreditProviderError(
        provider,
        `credit provider ${provider} is unavailable: no reviewed issuer integration is registered`,
    );
}

/**
 * Resolve the pinned deployment for a PayKit network name or CAIP-2-ish
 * `solana:<cluster>` string. Unknown or undeployed networks yield
 * `undefined`. Mirrors Rust `musebook::deployment` exactly: the `solana:`
 * prefix is stripped, the cluster match is exact and case-sensitive.
 */
export function deploymentForNetwork(network: string): CreditDeployment | undefined {
    const cluster = network.startsWith('solana:') ? network.slice('solana:'.length) : network;
    return cluster === 'devnet' ? MUSEBOOK_DEVNET_DEPLOYMENT : undefined;
}

/**
 * Resolve the deployment for `network`, optionally replaced by an explicit
 * `program` override. The override is honored on devnet only (the channel
 * program stays pinned); on any other network it makes the provider
 * unavailable. Mirrors Rust `musebook::resolve`.
 */
export function resolveDeployment(network: string, program?: string  ): CreditDeployment | undefined {
    if (program === undefined) return deploymentForNetwork(network);
    if (program === MUSEBOOK_DEVNET_PROGRAM_ID) return deploymentForNetwork(network);
    const cluster = network.startsWith('solana:') ? network.slice('solana:'.length) : network;
    if (cluster !== 'devnet') return undefined;
    // A caller-supplied override must still be a real address.
    try {
        address(program);
    } catch {
        return undefined;
    }
    return { ...MUSEBOOK_DEVNET_DEPLOYMENT, programId: program };
}

/**
 * A devnet-only deployment of the same provider code at a different program
 * ID (e.g. a throwaway instance whose upgrade authority is the operator's own
 * devnet key). Never available on any other cluster; the channel program
 * stays pinned. Off unless a caller explicitly asks for it.
 */
export function devnetWithProgram(programId: string): CreditDeployment | undefined {
    try {
        address(programId);
    } catch {
        return undefined;
    }
    return { ...MUSEBOOK_DEVNET_DEPLOYMENT, programId };
}

/**
 * Validate merchant credit-provider policy before starting payment handlers,
 * without a network context: every recognized provider is unavailable,
 * because availability is a property of a reviewed deployment on a specific
 * network. Mirrors Rust `validate_credit_providers`.
 */
export function validateCreditProviders(providers: readonly CreditProvider[]): void {
    for (const provider of providers) throw unavailable(provider);
}

/**
 * Validate merchant credit-provider policy for a known network. Musebook is
 * available exactly where a deployment is pinned (devnet today); Coinflow
 * stays unavailable everywhere. Mirrors Rust
 * `validate_credit_providers_for_network`.
 */
export function validateCreditProvidersForNetwork(providers: readonly CreditProvider[], network: string): void {
    for (const provider of providers) {
        if (provider === 'musebook' && deploymentForNetwork(network) !== undefined) continue;
        throw unavailable(provider);
    }
}

async function pda(programAddress: string, seeds: readonly Uint8Array[]): Promise<string> {
    const [derived] = await getProgramDerivedAddress({
        programAddress: address(programAddress),
        // The kit encoders hand back readonly byte arrays; copy into the
        // mutable seed shape `getProgramDerivedAddress` expects.
        seeds: seeds.map(seed => new Uint8Array(seed)),
    });
    return derived.toString();
}

/** The provider ledger PDA for `owner`'s credits in `mint`. */
export async function ledgerAddress(deployment: CreditDeployment, owner: string, mint: string): Promise<string> {
    return await pda(deployment.programId, [
        new Uint8Array(getUtf8Encoder().encode(MUSEBOOK_LEDGER_SEED)),
        new Uint8Array(getAddressEncoder().encode(address(owner))),
        new Uint8Array(getAddressEncoder().encode(address(mint))),
    ]);
}

/** The provider config PDA (a hook-adjacent account, never a hook account). */
export async function configAddress(deployment: CreditDeployment): Promise<string> {
    return await pda(deployment.programId, [new Uint8Array(getUtf8Encoder().encode(MUSEBOOK_CONFIG_SEED))]);
}

async function ata(owner: string, mint: string): Promise<string> {
    const [derived] = await findAssociatedTokenPda({
        mint: address(mint),
        owner: address(owner),
        tokenProgram: address(SPL_TOKEN_PROGRAM_ID),
    });
    return derived.toString();
}

/**
 * The exact, immutable hook policy for `owner`'s credits in `mint`: the same
 * descriptor in the `preFund` and `postDistribute` slots (no `postFund` /
 * `preDistribute`), accounts
 * `[ledger (w), ledger vault ATA (w), owner ATA (w), SPL Token (ro)]`,
 * entrypoint `musebook`, no static data.
 */
export async function hooksForDeployment(
    deployment: CreditDeployment,
    owner: string,
    mint: string,
): Promise<ChannelHooks> {
    const ledger = await ledgerAddress(deployment, owner, mint);
    const descriptor: HookDescriptor = {
        accounts: [
            { address: ledger, writable: true },
            { address: await ata(ledger, mint), writable: true },
            { address: await ata(owner, mint), writable: true },
            { address: SPL_TOKEN_PROGRAM_ID, writable: false },
        ],
        entrypoint: MUSEBOOK_ENTRYPOINT,
        programId: deployment.programId,
        staticData: [],
    };
    return { postDistribute: descriptor, preFund: descriptor };
}

function descriptorEquals(a: HookDescriptor | undefined, b: HookDescriptor | undefined): boolean {
    if (a === undefined || b === undefined) return a === b;
    return (
        a.programId === b.programId &&
        a.entrypoint.length === b.entrypoint.length &&
        a.entrypoint.every((byte, i) => byte === b.entrypoint[i]) &&
        a.staticData.length === b.staticData.length &&
        a.staticData.every((byte, i) => byte === b.staticData[i]) &&
        a.accounts.length === b.accounts.length &&
        a.accounts.every(
            (account, i) => account.address === b.accounts[i]?.address && account.writable === b.accounts[i]?.writable,
        )
    );
}

/**
 * Detection: is this hook configuration exactly the Musebook credit-backed
 * hooks for `owner`/`mint` on this deployment? Exact match only — a
 * look-alike with a different program, entrypoint, slot set or account list
 * is not. Mirrors Rust `Deployment::is_credit_channel`.
 */
export async function isCreditChannel(
    deployment: CreditDeployment,
    hooks: ChannelHooks,
    owner: string,
    mint: string,
): Promise<boolean> {
    const expected = await hooksForDeployment(deployment, owner, mint);
    return (
        descriptorEquals(hooks.preFund, expected.preFund) &&
        descriptorEquals(hooks.postFund, expected.postFund) &&
        descriptorEquals(hooks.preDistribute, expected.preDistribute) &&
        descriptorEquals(hooks.postDistribute, expected.postDistribute)
    );
}

/**
 * `sha256(u32le(count) || recipient(32) || bps(u16le) || …)` over the
 * ordered distribution list — the preimage the channel program hashes at
 * `open` and re-checks at `distribute`. Mirrors Rust
 * `v1::distribution_hash`.
 */
export async function distributionHash(
    recipients: readonly { readonly bps: number; readonly recipient: string }[],
): Promise<Uint8Array> {
    const bytes = new Uint8Array(4 + recipients.length * 34);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, recipients.length, true);
    let offset = 4;
    for (const recipient of recipients) {
        bytes.set(new Uint8Array(getAddressEncoder().encode(address(recipient.recipient))), offset);
        offset += 32;
        view.setUint16(offset, recipient.bps, true);
        offset += 2;
    }
    return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}

/** Owner/issuer authorization fields for a channel about to be opened. */
export interface CreditAuthorization {
    readonly authorizedSigner: string;
    readonly cap: bigint;
    readonly distributionHash: Uint8Array;
    readonly expiresAtSlot: bigint;
    readonly nonce: bigint;
    readonly openSlot: bigint;
    readonly payee: string;
    readonly salt: bigint;
}

/** Encode the provider `Authorization` body (fixed 136 bytes, tag excluded). */
export function encodeAuthorization(authorization: CreditAuthorization): Uint8Array {
    const out = new Uint8Array(136);
    const view = new DataView(out.buffer);
    out.set(new Uint8Array(getAddressEncoder().encode(address(authorization.payee))), 0);
    out.set(new Uint8Array(getAddressEncoder().encode(address(authorization.authorizedSigner))), 32);
    if (authorization.distributionHash.length !== 32) {
        throw new Error('distributionHash must be 32 bytes');
    }
    out.set(new Uint8Array(authorization.distributionHash), 64);
    const numbers = [
        authorization.salt,
        authorization.openSlot,
        authorization.cap,
        authorization.nonce,
        authorization.expiresAtSlot,
    ];
    numbers.forEach((value, i) => view.setBigUint64(96 + i * 8, value, true));
    return out;
}
