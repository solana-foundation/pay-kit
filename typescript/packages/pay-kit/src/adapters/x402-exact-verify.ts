import {
    type CompiledTransactionMessage,
    getBase64Encoder,
    getCompiledTransactionMessageDecoder,
    getTransactionDecoder,
} from '@solana/kit';

import { InvalidProofError } from '../errors.js';

/**
 * The route-side `PaymentRequirements` fields the credential is bound to.
 * Structural so the public signature does not leak the bundled `@x402/core`
 * types.
 */
export interface X402ExactRouteRequirements {
    readonly amount: string;
    readonly asset: string;
    readonly extra?: Readonly<Record<string, unknown>>;
    readonly network: string;
    readonly payTo: string;
    readonly scheme: string;
}

/**
 * The decoded `PaymentPayload` fields these checks read: v2 names the
 * requirement it accepts in `accepted`; v1 commits only to a top-level
 * `scheme` and `network`. A payload without `x402Version` is read as v2.
 */
export interface X402ExactCredential {
    readonly accepted?: unknown;
    readonly network?: unknown;
    readonly payload?: unknown;
    readonly scheme?: unknown;
    readonly x402Version?: unknown;
}

/** The v2 payload {@link bindX402ExactCredential} hands the exact facilitator. */
export interface X402ExactBoundCredential {
    readonly accepted: Readonly<Record<string, unknown>>;
    readonly extensions?: Record<string, unknown>;
    readonly payload: Record<string, unknown>;
    readonly resource?: unknown;
    readonly x402Version: 2;
}

/**
 * x402 v1 SVM network names (x402-specification-v1.md; `@x402/svm/v1`
 * `NETWORKS`) and the CAIP-2 cluster each names.
 */
const X402_V1_NETWORKS: Readonly<Record<string, string>> = {
    solana: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
    'solana-devnet': 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
    'solana-testnet': 'solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z',
};

/**
 * The x402 v1 network name for a CAIP-2 Solana network: `solana-devnet`,
 * `solana-testnet`, else `solana` (mainnet), as the Rust kit's
 * `v1_network_for_requirements`.
 */
export function x402V1Network(caip2: string): string {
    for (const [name, network] of Object.entries(X402_V1_NETWORKS)) {
        if (network === caip2) return name;
    }
    return 'solana';
}

/** Reason for a v1 credential naming another network than the route's. */
export const X402_NETWORK_MISMATCH = 'network_mismatch';

/** Top-level `PaymentRequirements` fields a v2 `accepted` must echo verbatim. */
const BOUND_FIELDS = ['scheme', 'network', 'amount', 'asset', 'payTo'] as const;

/**
 * `extra` keys this server may add that are not exact-scheme fields (the
 * scheme defines `feePayer`, `memo`, `recentBlockhash` and
 * `lastValidBlockHeight`; RULINGS S1). A client that builds `accepted` from
 * the spec fields alone may leave them out; one it does echo must still match.
 */
const NON_SPEC_EXTRA_HINTS: ReadonlySet<string> = new Set(['decimals', 'tokenProgram', 'transactionVersions']);

/**
 * Transient challenge build hints: present in the challenge the client echoes
 * but not part of the route's pinned requirements.
 */
const TRANSIENT_EXTRA_HINTS: ReadonlySet<string> = new Set(['recentBlockhash', 'lastValidBlockHeight']);

/**
 * Reason for a credential whose `accepted` is not the route's requirement.
 * Classified as `accepted-mismatch` by the conformance harness.
 */
export const X402_ACCEPTED_MISMATCH = 'accepted_mismatch';

/**
 * Reason for a transaction that references the fee payer from an instruction
 * (scheme_exact_svm.md §2.1.1). Same reason code as the upstream facilitator
 * family.
 */
export const X402_FEE_PAYER_IN_INSTRUCTION_ACCOUNTS =
    'invalid_exact_svm_payload_transaction_fee_payer_included_in_instruction_accounts';

function acceptedMismatch(detail: string): InvalidProofError {
    return new InvalidProofError(X402_ACCEPTED_MISMATCH, `${X402_ACCEPTED_MISMATCH}: ${detail}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

/** Structural JSON equality: arrays by position, objects by key regardless of order. */
function jsonEqual(a: unknown, b: unknown): boolean {
    if (a === b) return true;
    if (Array.isArray(a) || Array.isArray(b)) {
        return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((v, i) => jsonEqual(v, b[i]));
    }
    if (isRecord(a) && isRecord(b)) {
        const keys = Object.keys(a);
        return keys.length === Object.keys(b).length && keys.every(k => k in b && jsonEqual(a[k], b[k]));
    }
    return false;
}

/**
 * Bind a v2 credential's `accepted` to the route's own requirements.
 *
 * `accepted` is the "PaymentRequirements object indicating the payment method
 * chosen" (x402-specification-v2.md §5.2.2), so every pinned field (scheme,
 * network, amount, asset, payTo) and every `extra` field the route issued
 * (feePayer, memo) must be echoed unchanged. Non-spec server hints the client
 * did not echo are tolerated, as the Rust kit does; unknown fields the client
 * adds are ignored (RULINGS X1).
 *
 * @throws {InvalidProofError} `accepted_mismatch` naming the first field that differs.
 */
export function assertX402AcceptedMatchesRoute(accepted: unknown, requirements: X402ExactRouteRequirements): void {
    if (!isRecord(accepted)) throw acceptedMismatch('accepted is not an object');
    for (const field of BOUND_FIELDS) {
        if (accepted[field] !== requirements[field]) {
            throw acceptedMismatch(`accepted.${field} differs from the route`);
        }
    }
    const routeExtra = requirements.extra ?? {};
    const echoedExtra = isRecord(accepted.extra) ? accepted.extra : {};
    for (const [key, value] of Object.entries(routeExtra)) {
        if (TRANSIENT_EXTRA_HINTS.has(key)) continue;
        if (NON_SPEC_EXTRA_HINTS.has(key) && !(key in echoedExtra)) continue;
        // Compared by content: a decoded echo is a new object even when equal.
        if (!jsonEqual(echoedExtra[key], value)) {
            throw acceptedMismatch(`accepted.extra.${key} differs from the route`);
        }
    }
}

/**
 * Keep the fee payer out of every instruction (scheme_exact_svm.md §2.1.1):
 * "The `feePayer` MUST NOT appear in the `accounts` list of any instruction
 * ... and MUST NOT be invoked as a program." A `feePayer == payTo` route still
 * passes, because the transfer names payTo's token account, not payTo.
 *
 * Checks the static account keys. Accounts loaded through address lookup
 * tables are resolved (or the transaction refused) by the facilitator, which
 * owns RPC access (§2.1.2).
 *
 * @throws {InvalidProofError} when the transaction cannot be decoded or references the fee payer.
 */
export function assertX402FeePayerIsolated(transaction: unknown, feePayer: string): void {
    let staticAccounts: readonly string[];
    let instructions: readonly ReferencedAccounts[];
    try {
        if (typeof transaction !== 'string') throw new Error('transaction is not a string');
        const { messageBytes } = getTransactionDecoder().decode(getBase64Encoder().encode(transaction));
        const message = getCompiledTransactionMessageDecoder().decode(messageBytes);
        staticAccounts = message.staticAccounts;
        instructions = referencedAccounts(message);
    } catch (error) {
        const reason = 'invalid_exact_svm_payload_transaction_could_not_be_decoded';
        throw new InvalidProofError(reason, `${reason}: ${error instanceof Error ? error.message : String(error)}`);
    }
    const feePayerIndex = staticAccounts.indexOf(feePayer);
    if (feePayerIndex === -1) return;
    for (const [position, instruction] of instructions.entries()) {
        if (instruction.program === feePayerIndex || instruction.accounts.includes(feePayerIndex)) {
            throw new InvalidProofError(
                X402_FEE_PAYER_IN_INSTRUCTION_ACCOUNTS,
                `${X402_FEE_PAYER_IN_INSTRUCTION_ACCOUNTS}: instruction ${position} references the fee payer`,
            );
        }
    }
}

/** The account indices one compiled instruction references. */
interface ReferencedAccounts {
    readonly accounts: readonly number[];
    readonly program: number;
}

/** Per-instruction account indices of a legacy, v0 or v1 compiled message. */
function referencedAccounts(message: CompiledTransactionMessage): ReferencedAccounts[] {
    if (message.version === 1) {
        return message.instructionHeaders.map((header, index) => ({
            accounts: message.instructionPayloads[index]?.instructionAccountIndices ?? [],
            program: header.programAccountIndex,
        }));
    }
    return message.instructions.map(instruction => ({
        accounts: instruction.accountIndices ?? [],
        program: instruction.programAddressIndex,
    }));
}

/**
 * Bind a v1 credential to the route (x402-specification-v1.md §5.2): v1 has
 * no `accepted`, so it commits only to `scheme` and a plain network name,
 * which must name the route's own scheme and CAIP-2 network.
 *
 * @throws {InvalidProofError} `unsupported_scheme` or `network_mismatch`.
 */
export function assertX402V1EnvelopeMatchesRoute(
    credential: X402ExactCredential,
    requirements: X402ExactRouteRequirements,
): void {
    if (credential.scheme !== requirements.scheme) {
        throw new InvalidProofError(
            'unsupported_scheme',
            `unsupported_scheme: v1 scheme ${String(credential.scheme)} is not ${requirements.scheme}`,
        );
    }
    const network = typeof credential.network === 'string' ? X402_V1_NETWORKS[credential.network] : undefined;
    if (network !== requirements.network) {
        throw new InvalidProofError(
            X402_NETWORK_MISMATCH,
            `Network mismatch: expected ${requirements.network}, got ${String(credential.network)}`,
        );
    }
}

/**
 * Pay-kit's checks on a decoded v2 exact credential, run before the vendored
 * `@x402/svm` facilitator verifies the transaction: bind `accepted` to the
 * route, then keep the route's fee payer out of every instruction. The
 * facilitator only checks the fee payer as `TransferChecked` authority.
 *
 * @throws {InvalidProofError} on the first failed check.
 */
export function verifyX402ExactCredential(
    credential: X402ExactCredential,
    requirements: X402ExactRouteRequirements,
): void {
    assertX402AcceptedMatchesRoute(credential.accepted, requirements);
    const feePayer = requirements.extra?.feePayer;
    if (typeof feePayer !== 'string') return;
    const transaction = isRecord(credential.payload) ? credential.payload.transaction : undefined;
    assertX402FeePayerIsolated(transaction, feePayer);
}

/**
 * Bind a decoded exact credential of either x402 version to the route and
 * return the v2 payload the exact facilitator verifies and settles.
 *
 * A v2 credential runs {@link verifyX402ExactCredential} and is returned as
 * is. A legacy v1 credential (`X-PAYMENT`) is bound by its scheme and network
 * ({@link assertX402V1EnvelopeMatchesRoute}) and its fee payer isolation
 * checked; then, as the Rust kit verifies both versions with one transaction
 * verifier, it is carried to the facilitator as a v2 payload accepting the
 * route's own requirements. Its transaction is still checked against those
 * requirements (amount, asset, payTo, memo), so v1 gets every verification v2
 * gets.
 *
 * @throws {InvalidProofError} `invalid_x402_version` for any other version, or the first failed check.
 */
export function bindX402ExactCredential(
    credential: X402ExactCredential,
    requirements: X402ExactRouteRequirements,
): X402ExactBoundCredential {
    if (credential.x402Version === 2) {
        verifyX402ExactCredential(credential, requirements);
        return credential as X402ExactBoundCredential;
    }
    if (credential.x402Version !== 1) {
        throw new InvalidProofError(
            'invalid_x402_version',
            `Unsupported x402 version: ${String(credential.x402Version)}`,
        );
    }
    assertX402V1EnvelopeMatchesRoute(credential, requirements);
    const payload = isRecord(credential.payload) ? credential.payload : {};
    const feePayer = requirements.extra?.feePayer;
    if (typeof feePayer === 'string') assertX402FeePayerIsolated(payload.transaction, feePayer);
    return { accepted: { ...requirements }, payload, x402Version: 2 };
}
