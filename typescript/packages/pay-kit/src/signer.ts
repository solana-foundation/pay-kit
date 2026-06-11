import {
    createMemorySignerFromBytes,
    createMemorySignerFromKeyPair,
    createMemorySignerFromKeypairFile,
    createMemorySignerFromPrivateKeyString,
} from '@solana/keychain-memory';
import {
    createSignableMessage,
    generateKeyPair,
    type MessagePartialSigner,
    type TransactionPartialSigner,
} from '@solana/kit';

import { InvalidKeyError } from './errors.js';

/**
 * Any Solana Keychain signer: a kit signer that can sign both messages and
 * transactions and knows its address. All `@solana/keychain-*` backends
 * (memory, AWS KMS, GCP KMS, Vault, Privy, Turnkey, ...) satisfy this.
 */
export type KeychainSigner = MessagePartialSigner & TransactionPartialSigner;

/**
 * The PayKit signer contract, shared across the SDK family:
 * `pubkey`, `sign`, `isFeePayer`, `isDemo` — plus the underlying Keychain
 * signer for handing to protocol methods.
 */
export type PayKitSigner = {
    /** True only for the package-shipped demo signer. */
    readonly isDemo: boolean;
    /** Whether this signer may be used to sponsor transaction fees. */
    readonly isFeePayer: boolean;
    /** Base58 public key. */
    readonly pubkey: string;
    /** Signs an arbitrary message, returning the 64-byte Ed25519 signature. */
    readonly sign: (message: Uint8Array) => Promise<Uint8Array>;
    /** The underlying Keychain signer, accepted by protocol methods. */
    readonly signer: KeychainSigner;
};

/**
 * The package-shipped demo keypair, byte-for-byte identical across the Ruby,
 * Python, PHP, and Lua SDKs so processes running different SDKs can exchange
 * traffic during local development. Public by design — never fund it.
 */
const DEMO_SECRET_BYTES = new Uint8Array([
    26, 61, 117, 192, 9, 232, 24, 51, 89, 135, 105, 182, 47, 9, 83, 244, 11, 214, 85, 170, 227, 83, 170, 26, 55, 129,
    58, 114, 89, 160, 195, 51, 138, 209, 127, 35, 54, 41, 202, 166, 199, 166, 97, 238, 181, 63, 254, 185, 45, 16, 174,
    102, 250, 198, 30, 191, 232, 236, 147, 167, 41, 178, 151, 26,
]);

const HEX_PATTERN = /^[0-9a-fA-F]{128}$/;

function wrap(signer: KeychainSigner, options: { isDemo?: boolean; isFeePayer?: boolean } = {}): PayKitSigner {
    return Object.freeze({
        isDemo: options.isDemo ?? false,
        isFeePayer: options.isFeePayer ?? true,
        pubkey: signer.address,
        async sign(message: Uint8Array): Promise<Uint8Array> {
            const [dictionary] = await signer.signMessages([createSignableMessage(message)]);
            const signature = dictionary?.[signer.address];
            if (!signature) throw new InvalidKeyError(`Signer ${signer.address} returned no signature.`);
            return new Uint8Array(signature);
        },
        signer,
    });
}

async function rethrowingInvalidKey(build: () => Promise<KeychainSigner>): Promise<KeychainSigner> {
    try {
        return await build();
    } catch (error) {
        if (error instanceof InvalidKeyError) throw error;
        throw new InvalidKeyError(error instanceof Error ? error.message : String(error), { cause: error });
    }
}

let demoSigner: Promise<PayKitSigner> | undefined;

/**
 * Static factory for PayKit signers. Local key material is handled by
 * Solana Keychain's in-memory backend (`@solana/keychain-memory`); remote
 * backends (AWS KMS, GCP KMS, Vault, Privy, Turnkey, ...) plug in through
 * {@link Signer.from}.
 *
 * @example
 * ```ts
 * const local = await Signer.file('~/.config/solana/id.json');
 *
 * import { createKeychainSigner } from '@solana/keychain';
 * const remote = Signer.from(await createKeychainSigner({ backend: 'vault', ... }));
 * ```
 */
export const Signer = {
    /** From a base58-encoded 64-byte secret (Phantom/Solflare export). */
    async base58(secret: string): Promise<PayKitSigner> {
        return wrap(await rethrowingInvalidKey(() => createMemorySignerFromPrivateKeyString(secret)));
    },

    /** From raw secret bytes: 64-byte Solana CLI keypair or 32-byte Ed25519 seed. */
    async bytes(secret: Uint8Array | readonly number[]): Promise<PayKitSigner> {
        const bytes = secret instanceof Uint8Array ? secret : new Uint8Array(secret);
        return wrap(await rethrowingInvalidKey(() => createMemorySignerFromBytes(bytes)));
    },

    /**
     * The package-shipped demo keypair, cached per process. Warns once;
     * refused on mainnet at configure time.
     */
    demo(): Promise<PayKitSigner> {
        demoSigner ??= (async () => {
            console.warn('[pay-kit] Using the shared demo signer. It is public and for local development only.');
            return wrap(await createMemorySignerFromBytes(DEMO_SECRET_BYTES), { isDemo: true });
        })();
        return demoSigner;
    },

    /**
     * From an environment variable, auto-detecting JSON-array, hex, or base58
     * encoding. Returns `undefined` when the variable is unset or empty.
     */
    async env(name: string): Promise<PayKitSigner | undefined> {
        const value = process.env[name]?.trim();
        if (!value) return undefined;
        if (HEX_PATTERN.test(value)) return await Signer.hex(value);
        return wrap(await rethrowingInvalidKey(() => createMemorySignerFromPrivateKeyString(value)));
    },

    /** From a Solana CLI keypair JSON file. */
    async file(path: string): Promise<PayKitSigner> {
        return wrap(await rethrowingInvalidKey(() => createMemorySignerFromKeypairFile(path)));
    },

    /**
     * Wraps an existing Keychain (or any kit) signer — the bridge to remote
     * backends such as AWS KMS, GCP KMS, Vault, Privy, and Turnkey.
     *
     * @param options.feePayer - Whether the signer may sponsor transaction
     * fees. Defaults to `true`; set `false` for remote signers that must not
     * co-sign server-built transactions.
     */
    from(signer: KeychainSigner, options: { feePayer?: boolean } = {}): PayKitSigner {
        return wrap(signer, { isFeePayer: options.feePayer ?? true });
    },

    /** Fresh ephemeral keypair (tests and throwaway environments). */
    async generate(): Promise<PayKitSigner> {
        return wrap(await createMemorySignerFromKeyPair(await generateKeyPair()));
    },

    /** From a 128-character hex string (64 bytes). */
    async hex(secret: string): Promise<PayKitSigner> {
        if (!HEX_PATTERN.test(secret)) {
            throw new InvalidKeyError('Hex secrets must be exactly 128 hex characters (64 bytes).');
        }
        const bytes = Uint8Array.from({ length: 64 }, (_, i) => parseInt(secret.slice(i * 2, i * 2 + 2), 16));
        return await Signer.bytes(bytes);
    },

    /** From a Solana CLI JSON array string, e.g. `"[1,2,...,64]"`. */
    async json(jsonArray: string): Promise<PayKitSigner> {
        return wrap(await rethrowingInvalidKey(() => createMemorySignerFromPrivateKeyString(jsonArray)));
    },
};
