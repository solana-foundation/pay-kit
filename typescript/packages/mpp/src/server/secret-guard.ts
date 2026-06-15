// Defensive secret-key strength guard for the MPP server (audit #24).
//
// pay-kit's TypeScript SDK delegates HMAC-bound challenge issuance/verification
// to `mppx` via `Mppx.create({ secretKey })`. mppx@0.5.x only rejects an empty
// secret (`if (!secretKey) throw`), so a weak key such as `"key"` is accepted as
// the HMAC-SHA256 key that binds challenge IDs — an attacker who guesses or
// brute-forces a low-entropy key can forge challenges. Per NIST SP 800-107 the
// HMAC-SHA256 key should be at least the hash output size (32 bytes).
//
// Until a length floor lands upstream in mppx, we gate at OUR `@solana/mpp`
// boundary, mirroring `challenge-guard.ts`: this module re-exports the `Mppx`
// namespace with `create` wrapped so a short secret is rejected before any
// challenge is signed. We do NOT fork or vendor mppx, and we touch only the
// secret-strength gate, never the signing or settlement path.

import { Mppx as MppxBase } from 'mppx/server';

/**
 * Minimum accepted MPP HMAC secret-key length in bytes (audit #24).
 *
 * 32 bytes matches the HMAC-SHA256 output size (NIST SP 800-107). Generate a
 * conforming key with `openssl rand -base64 32`.
 */
export const MIN_SECRET_KEY_BYTES = 32;

function assertStrongSecret(config: Parameters<typeof MppxBase.create>[0]): void {
    // Mirror mppx's own resolution order: explicit `secretKey`, else the
    // `MPP_SECRET_KEY` environment variable. When neither is set we stay silent
    // and let mppx raise its own "secret key required" error, so we own only the
    // strength check and never change the missing-secret behavior.
    const secret = config.secretKey ?? process.env.MPP_SECRET_KEY;
    if (secret === undefined) return;

    const byteLength = new TextEncoder().encode(secret).length;
    if (byteLength < MIN_SECRET_KEY_BYTES) {
        throw new Error(
            `MPP secret key must be at least ${MIN_SECRET_KEY_BYTES} bytes (got ${byteLength}); ` +
                'generate one with `openssl rand -base64 32`',
        );
    }
}

/**
 * `Mppx.create` with the audit #24 secret-strength gate applied. Identical to
 * `mppx`'s `Mppx.create` except a secret shorter than {@link MIN_SECRET_KEY_BYTES}
 * bytes (whether passed explicitly or via `MPP_SECRET_KEY`) is rejected.
 */
export const create: typeof MppxBase.create = (config => {
    assertStrongSecret(config);
    return MppxBase.create(config);
}) as typeof MppxBase.create;

/**
 * The `Mppx` namespace as exposed by `@solana/mpp/server`: the upstream `mppx`
 * surface with the secret-strength gate applied to `create`. Use this instead
 * of importing `Mppx` directly from `mppx` so a weak HMAC secret is rejected at
 * server construction.
 */
export const Mppx: typeof MppxBase = {
    ...MppxBase,
    create,
};
