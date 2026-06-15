// Defensive challenge-parse guard for the canonical MPP protocol wire.
//
// pay-kit's TypeScript SDK leans on `mppx` for the WWW-Authenticate challenge
// codec. The canonical mpp-tools protocol vectors require that a challenge `id`
// is a non-empty, HMAC-bound value: a `Payment id="", ...` header MUST be
// rejected on parse. mppx@0.5.x's zod schema types `id` as a plain string and
// therefore accepts an empty `id=""`, so a malformed challenge slips through.
//
// Until that lands upstream in mppx, we guard at OUR `@solana/mpp` boundary:
// this module re-exports the full `Challenge` namespace from mppx, with
// `deserialize` / `deserializeList` wrapped so an empty `id` is rejected the
// same way the canonical golden demands. We do NOT fork or vendor mppx, and we
// touch only the protocol header codec, never the Solana settlement path.

import { Challenge as MppxChallenge } from 'mppx';

/** Re-exported challenge type, identical to mppx's. */
export type Challenge<
    request = Record<string, unknown>,
    intent extends string = string,
    method extends string = string,
> = MppxChallenge.Challenge<request, intent, method>;

function assertNonEmptyId(challenge: { id?: unknown }): void {
    if (typeof challenge.id !== 'string' || challenge.id.length === 0) {
        // Mirror mppx's parse-failure surface so callers (and the protocol
        // conformance runner) classify this as a parse_error, not a success.
        throw new Error('challenge id must be a non-empty value');
    }
}

/**
 * Deserializes a `WWW-Authenticate` header value to a challenge, rejecting a
 * challenge whose `id` is empty (canonical mpp-tools requires a non-empty,
 * HMAC-bound id). Otherwise identical to `mppx`'s `Challenge.deserialize`.
 */
export const deserialize: typeof MppxChallenge.deserialize = ((value, options) => {
    const challenge = MppxChallenge.deserialize(value, options);
    assertNonEmptyId(challenge as { id?: unknown });
    return challenge;
}) as typeof MppxChallenge.deserialize;

/**
 * Deserializes a `WWW-Authenticate` header value that may contain multiple
 * challenges, rejecting any challenge whose `id` is empty.
 */
export const deserializeList: typeof MppxChallenge.deserializeList = ((value, options) => {
    const challenges = MppxChallenge.deserializeList(value, options);
    for (const challenge of challenges) assertNonEmptyId(challenge as { id?: unknown });
    return challenges;
}) as typeof MppxChallenge.deserializeList;

/**
 * The `Challenge` namespace as exposed by `@solana/mpp`: the upstream `mppx`
 * surface with the empty-id parse guard applied to the header-parsing entry
 * points. Use this instead of importing `Challenge` directly from `mppx` when
 * canonical-conformant parsing is required.
 */
export const Challenge = {
    ...MppxChallenge,
    deserialize,
    deserializeList,
} as typeof MppxChallenge;
