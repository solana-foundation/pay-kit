/**
 * Transaction message versions (SIMD-0385) for the Solana MPP methods:
 * negotiation on the client, admission on the server, and the version-1
 * header compute budget. Mirrors the Rust kit's `core::tx` (`version.rs`,
 * `policy.rs`, `budget.rs`) so every SDK admits and builds the same versions.
 *
 * Version 1 carries its compute budget in the message header
 * (`computeUnitLimit`, `priorityFeeLamports`, `loadedAccountsDataSizeLimit`)
 * instead of ComputeBudget instructions, and allows 4096-byte transactions.
 */

/** A transaction message version a challenge can advertise (`methodDetails.transactionVersions`). */
export type TransactionVersion = 0 | 1;

/** The accepted set when a challenge omits `transactionVersions`. */
export const DEFAULT_TRANSACTION_VERSIONS: readonly TransactionVersion[] = Object.freeze([0]);

/** Serialized size limit of a legacy or version-0 transaction (`PACKET_DATA_SIZE`). */
export const V0_MAX_TRANSACTION_SIZE = 1232;
/** Static account limit of a version-0 transaction (`MAX_TX_ACCOUNT_LOCKS`). */
export const V0_MAX_STATIC_ACCOUNTS = 64;
/** Version-1 wire limits (`solana_message::v1`). */
export const V1_MAX_TRANSACTION_SIZE = 4096;
export const V1_MAX_STATIC_ACCOUNTS = 64;
export const V1_MAX_INSTRUCTIONS = 64;
export const V1_MAX_SIGNATURES = 12;

/** The loaded-account-data limit an MPP charge's version-1 header must carry: the runtime maximum, 64 MiB. */
export const MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES = 64 * 1024 * 1024;

const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111';
const U64_MAX = (1n << 64n) - 1n;

// Version-1 `TransactionConfigMask` bits.
const MASK_PRIORITY_FEE = 0b11;
const MASK_COMPUTE_UNIT_LIMIT = 0b100;
const MASK_LOADED_ACCOUNTS_DATA_SIZE = 0b1000;
const MASK_HEAP_SIZE = 0b10000;

/**
 * The accepted set: `[0]` only when the field is absent; a present, empty
 * list accepts nothing. A repeated entry names the same version.
 */
export function acceptedTransactionVersions(
    advertised: readonly TransactionVersion[] | undefined,
): readonly TransactionVersion[] {
    return advertised ?? DEFAULT_TRANSACTION_VERSIONS;
}

/**
 * The `transactionVersions` a server advertises for its accepted set: omitted
 * for the default `[0]`, which an absent field already means. Throws on an
 * empty set or a version outside 0 and 1.
 */
export function advertisedTransactionVersions(
    versions: readonly TransactionVersion[] | undefined,
): TransactionVersion[] | undefined {
    if (versions === undefined) return undefined;
    const unique = [...new Set(versions)].sort();
    if (unique.length === 0) {
        throw new Error('transactionVersions must list at least one transaction version');
    }
    if (unique.some(version => version !== 0 && version !== 1)) {
        throw new Error('transactionVersions entries must be 0 or 1');
    }
    return unique.length === 1 && unique[0] === 0 ? undefined : unique;
}

/**
 * The version a client builds: the highest advertised version its signer can
 * sign (`maxSignable`, unrestricted when omitted). Throws when nothing is
 * advertised or no advertised version is signable.
 */
export function negotiateTransactionVersion(
    advertised: readonly TransactionVersion[] | undefined,
    maxSignable?: TransactionVersion,
): TransactionVersion {
    const accepted = acceptedTransactionVersions(advertised);
    if (accepted.length === 0) {
        throw new Error('the counterparty advertises no transaction version (transactionVersions is empty)');
    }
    const candidates = accepted.filter(version => maxSignable === undefined || version <= maxSignable);
    if (candidates.length === 0) {
        throw new Error(
            `the server accepts transaction versions [${accepted.join(', ')}] but the signer signs up to version ${maxSignable}`,
        );
    }
    return candidates.reduce<TransactionVersion>((max, version) => (version > max ? version : max), 0);
}

/** Total priority fee in lamports for a limit and a per-unit price, rounded up. */
export function priorityFeeLamports(unitLimit: number, unitPriceMicroLamports: bigint): bigint {
    const micro = BigInt(unitLimit) * unitPriceMicroLamports;
    const fee = (micro + 999_999n) / 1_000_000n;
    return fee > U64_MAX ? U64_MAX : fee;
}

/** A compiled instruction in one shape across message versions. */
export type CompiledInstructionView = {
    accountIndices: readonly number[];
    data: Uint8Array;
    programAddressIndex: number;
};

/** The version-1 header config, read from its mask. */
export type TransactionV1Config = {
    computeUnitLimit?: number;
    heapSize?: number;
    loadedAccountsDataSizeLimit?: number;
    priorityFeeLamports?: bigint;
};

/** A decoded compiled message, normalized across legacy, version 0 and version 1. */
export type CompiledMessageView = {
    addressTableLookups: readonly unknown[];
    /** Version-1 header config; undefined for legacy and version 0. */
    config: TransactionV1Config | undefined;
    header: { numSignerAccounts: number };
    instructions: readonly CompiledInstructionView[];
    lifetimeToken: string;
    staticAccounts: readonly string[];
    version: TransactionVersion | 'legacy';
};

type DecodedCompiledMessage = {
    addressTableLookups?: readonly unknown[];
    configMask?: number;
    configValues?: readonly { kind?: string; value: bigint | number }[];
    header: { numSignerAccounts: number };
    instructionHeaders?: readonly { programAccountIndex: number }[];
    instructionPayloads?: readonly { instructionAccountIndices?: readonly number[]; instructionData?: Uint8Array }[];
    instructions?: readonly { accountIndices?: readonly number[]; data?: Uint8Array; programAddressIndex?: number }[];
    lifetimeToken: string;
    staticAccounts: readonly string[];
    version: unknown;
};

/**
 * Normalize a message from `getCompiledTransactionMessageDecoder()`: a
 * version-1 message splits each instruction into a header and a payload and
 * carries its budget in a masked config. Missing instruction accounts or data
 * become empty, so policy checks reject them instead of crashing.
 */
export function normalizeCompiledMessage(decoded: unknown): CompiledMessageView {
    const message = decoded as DecodedCompiledMessage;
    const base = {
        addressTableLookups: message.addressTableLookups ?? [],
        header: { numSignerAccounts: message.header.numSignerAccounts },
        lifetimeToken: message.lifetimeToken,
        staticAccounts: message.staticAccounts,
    };
    if (message.version === 1) {
        const headers = message.instructionHeaders ?? [];
        const payloads = message.instructionPayloads ?? [];
        if (headers.length !== payloads.length) {
            throw new Error('version 1 instruction headers and payloads differ in length');
        }
        return {
            ...base,
            config: readV1Config(message.configMask ?? 0, message.configValues ?? []),
            instructions: headers.map((header, i) => ({
                accountIndices: payloads[i].instructionAccountIndices ?? [],
                data: payloads[i].instructionData ?? new Uint8Array(),
                programAddressIndex: header.programAccountIndex,
            })),
            version: 1,
        };
    }
    if ((message.version !== 0 && message.version !== 'legacy') || message.instructions === undefined) {
        throw new Error(`unsupported transaction version ${String(message.version)}`);
    }
    return {
        ...base,
        config: undefined,
        instructions: message.instructions.map(ix => ({
            accountIndices: ix.accountIndices ?? [],
            data: ix.data ?? new Uint8Array(),
            programAddressIndex: ix.programAddressIndex ?? -1,
        })),
        version: message.version,
    };
}

function readV1Config(mask: number, values: readonly { value: bigint | number }[]): TransactionV1Config {
    const priorityBits = mask & MASK_PRIORITY_FEE;
    if (priorityBits !== 0 && priorityBits !== MASK_PRIORITY_FEE) {
        throw new Error('version 1 transaction config sets one of the two priority fee bits');
    }
    if (mask & ~(MASK_PRIORITY_FEE | MASK_COMPUTE_UNIT_LIMIT | MASK_LOADED_ACCOUNTS_DATA_SIZE | MASK_HEAP_SIZE)) {
        throw new Error('version 1 transaction config sets an unknown mask bit');
    }
    const queue = [...values];
    const next = () => {
        const entry = queue.shift();
        if (entry === undefined) throw new Error('version 1 transaction config is missing a value');
        return entry.value;
    };
    const config: TransactionV1Config = {};
    if (priorityBits) config.priorityFeeLamports = BigInt(next());
    if (mask & MASK_COMPUTE_UNIT_LIMIT) config.computeUnitLimit = Number(next());
    if (mask & MASK_LOADED_ACCOUNTS_DATA_SIZE) config.loadedAccountsDataSizeLimit = Number(next());
    if (mask & MASK_HEAP_SIZE) config.heapSize = Number(next());
    return config;
}

/** The version a message is policed as: legacy is policed as version 0. */
export function policyVersion(message: CompiledMessageView): TransactionVersion {
    return message.version === 'legacy' ? 0 : message.version;
}

/**
 * Admit a decoded transaction against the accepted set (Rust
 * `check_envelope_without_legacy`): MPP servers refuse a legacy message,
 * refuse a version they do not accept, refuse address lookup tables, and
 * hold the transaction to its version's size, account, instruction and
 * signature limits. Returns the admitted version.
 */
export function checkTransactionEnvelope(
    message: CompiledMessageView,
    wireSize: number,
    accepted: readonly TransactionVersion[],
): TransactionVersion {
    const listed = accepted.join(', ');
    if (message.version === 'legacy') {
        throw new Error(`legacy transaction version is not accepted; accepted versions: ${listed}`);
    }
    const version = message.version;
    if (!accepted.includes(version)) {
        throw new Error(`transaction version ${version} is not accepted; accepted versions: ${listed}`);
    }
    if (message.addressTableLookups.length > 0) {
        throw new Error('transactions with address lookup tables are not supported');
    }
    const maxBytes = version === 1 ? V1_MAX_TRANSACTION_SIZE : V0_MAX_TRANSACTION_SIZE;
    if (wireSize > maxBytes) {
        throw new Error(`version ${version} transaction is ${wireSize} bytes, over the ${maxBytes}-byte limit`);
    }
    const maxAccounts = version === 1 ? V1_MAX_STATIC_ACCOUNTS : V0_MAX_STATIC_ACCOUNTS;
    if (message.staticAccounts.length > maxAccounts) {
        throw new Error(
            `version ${version} transaction has ${message.staticAccounts.length} accounts, over the limit of ${maxAccounts}`,
        );
    }
    if (version === 1) {
        if (message.instructions.length > V1_MAX_INSTRUCTIONS) {
            throw new Error(
                `version 1 transaction has ${message.instructions.length} instructions, over the limit of ${V1_MAX_INSTRUCTIONS}`,
            );
        }
        if (message.header.numSignerAccounts > V1_MAX_SIGNATURES) {
            throw new Error(
                `version 1 transaction requires ${message.header.numSignerAccounts} signatures, over the limit of ${V1_MAX_SIGNATURES}`,
            );
        }
    }
    return version;
}

/**
 * Hold a version-1 header budget to the caps the ComputeBudget instructions
 * get on version 0 (Rust `check_v1_budget_caps`): no ComputeBudget
 * instruction, a positive `computeUnitLimit` within `maxUnitLimit`, a
 * per-unit price (`priorityFee * 1e6 / computeUnitLimit`, rounded up) within
 * `maxUnitPriceMicroLamports`, and the 64 MiB loaded-account-data limit. A
 * no-op for legacy and version 0.
 */
export function checkV1BudgetCaps(
    message: CompiledMessageView,
    maxUnitLimit: number,
    maxUnitPriceMicroLamports: bigint,
): void {
    if (message.version !== 1 || message.config === undefined) return;
    if (message.instructions.some(ix => message.staticAccounts[ix.programAddressIndex] === COMPUTE_BUDGET_PROGRAM)) {
        throw new Error('version 1 transactions must not contain ComputeBudget instructions');
    }
    const { computeUnitLimit: limit, loadedAccountsDataSizeLimit: loaded, priorityFeeLamports: fee } = message.config;
    if (limit === undefined) {
        throw new Error('version 1 transaction config must set computeUnitLimit');
    }
    if (limit === 0) {
        throw new Error('compute unit limit must be positive');
    }
    if (limit > maxUnitLimit) {
        throw new Error(`compute unit limit ${limit} exceeds maximum ${maxUnitLimit}`);
    }
    if (fee !== undefined) {
        const micro = fee * 1_000_000n;
        const price = (micro + BigInt(limit) - 1n) / BigInt(limit);
        if (price > maxUnitPriceMicroLamports) {
            throw new Error(`compute unit price ${price} exceeds maximum ${maxUnitPriceMicroLamports}`);
        }
    }
    if (loaded !== MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES) {
        throw new Error(`version 1 loaded accounts data size limit must be ${MAX_LOADED_ACCOUNTS_DATA_SIZE_BYTES}`);
    }
}
