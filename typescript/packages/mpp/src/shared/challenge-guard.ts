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
 * Maximum accepted `WWW-Authenticate` challenge header length (audit #9).
 *
 * mppx@0.5.x base64-decodes + JSON-parses the embedded `request` parameter with
 * no size cap, so an oversized header drives proportionally larger decode/parse
 * work — a client-side DoS surface. Until a cap lands upstream, we guard the
 * full header at OUR `@solana/mpp` boundary, mirroring the existing empty-id
 * guard. 16 KiB matches the `MAX_TOKEN_LEN` the canonical credential/receipt
 * parsers already enforce.
 */
export const MAX_CHALLENGE_HEADER_LEN = 16 * 1024;

function assertWithinSizeCap(value: string): void {
    if (value.length > MAX_CHALLENGE_HEADER_LEN) {
        throw new Error(`challenge header exceeds maximum size of ${MAX_CHALLENGE_HEADER_LEN} bytes`);
    }
}

// The top-level challenge fields that mppx's `serialize` interpolates verbatim
// into quoted-string auth-params. `request` / `opaque` are serialized to
// base64url (never quotes/backslash/CR/LF) so they are excluded here.
const QUOTED_STRING_FIELDS = ['id', 'realm', 'method', 'intent', 'description', 'digest', 'expires'] as const;

/**
 * Rejects a quoted-string field carrying a carriage-return or newline.
 *
 * mppx's `serialize` interpolates these values verbatim, so an embedded CR/LF
 * would split the emitted `WWW-Authenticate` header (a header-injection
 * surface). We reject at OUR boundary, matching the guard's existing
 * throw-on-malformed style.
 */
function assertNoHeaderBreaks(challenge: Record<string, unknown>): void {
    for (const field of QUOTED_STRING_FIELDS) {
        const value = challenge[field];
        if (typeof value === 'string' && /[\r\n]/.test(value)) {
            throw new Error(`challenge field "${field}" must not contain a carriage-return or newline`);
        }
    }
}

/**
 * Escapes a quoted-string parameter value for the `WWW-Authenticate` wire:
 * backslash then double-quote, so mppx's escape-aware `deserialize` un-escapes
 * it back to the original. Applied to a shallow clone of the challenge before
 * handing it to `mppx`'s serializer, so `deserialize(serialize(x))` round-trips.
 */
function escapeQuotedString(value: string): string {
    return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/**
 * Value-level guard for a single challenge-bound string that will cross into
 * `mppx`'s raw (unescaped) `serialize` as a quoted-string auth-param — e.g. a
 * gate `description` or `realm` handed to `Mppx.create` / a charge's per-request
 * options.
 *
 * mppx interpolates such values verbatim into the `WWW-Authenticate` header, so:
 *   - a carriage-return / newline would split the emitted header (a
 *     header-injection surface). We reject it outright, throwing the same
 *     message shape the header-formatting guard uses. Callers apply this at
 *     configuration time so the failure is a fail-fast error, not a per-request
 *     header-construction 500.
 *   - a backslash / double-quote would break the quoted string and truncate the
 *     value on the client's escape-aware `deserialize`. We escape both so the
 *     emitted header stays parseable and round-trips losslessly.
 *
 * The returned value is escaped exactly once; it must NOT be fed through the
 * guarded {@link serialize} afterwards, which would double-escape it.
 *
 * @param field - The auth-param name, used only for the error message.
 * @param value - The raw string to guard.
 * @returns The escaped value, safe to interpolate into a quoted-string param.
 */
export function guardChallengeValue(field: string, value: string): string {
    if (/[\r\n]/.test(value)) {
        throw new Error(`challenge field "${field}" must not contain a carriage-return or newline`);
    }
    return escapeQuotedString(value);
}

/**
 * Produces the serialize-input clone: rejects CR/LF in any quoted-string field,
 * then escapes backslash / double-quote so the emitted header round-trips
 * through mppx's escape-aware `deserialize`. mppx's raw `serialize` does
 * neither, making its codec asymmetric — this closes the gap at our boundary.
 */
function guardSerializeInput<T extends { readonly [key: string]: unknown }>(challenge: T): T {
    assertNoHeaderBreaks(challenge as Record<string, unknown>);
    const escaped: Record<string, unknown> = { ...challenge };
    for (const field of QUOTED_STRING_FIELDS) {
        const value = escaped[field];
        if (typeof value === 'string') escaped[field] = escapeQuotedString(value);
    }
    return escaped as T;
}

/**
 * Deserializes a `WWW-Authenticate` header value to a challenge, rejecting a
 * challenge whose `id` is empty (canonical mpp-tools requires a non-empty,
 * HMAC-bound id). Otherwise identical to `mppx`'s `Challenge.deserialize`.
 */
export const deserialize: typeof MppxChallenge.deserialize = ((value, options) => {
    if (typeof value === 'string') assertWithinSizeCap(value);
    const challenge = MppxChallenge.deserialize(value, options);
    assertNonEmptyId(challenge as { id?: unknown });
    return challenge;
}) as typeof MppxChallenge.deserialize;

/**
 * Deserializes a `WWW-Authenticate` header value that may contain multiple
 * challenges, rejecting any challenge whose `id` is empty.
 */
export const deserializeList: typeof MppxChallenge.deserializeList = ((value, options) => {
    if (typeof value === 'string') assertWithinSizeCap(value);
    const challenges = MppxChallenge.deserializeList(value, options);
    for (const challenge of challenges) assertNonEmptyId(challenge as { id?: unknown });
    return challenges;
}) as typeof MppxChallenge.deserializeList;

/**
 * Serializes a challenge to a `WWW-Authenticate` header value, escaping
 * backslash / double-quote in quoted-string fields and rejecting any field
 * that contains a carriage-return or newline. mppx's raw `serialize` does
 * neither (its codec is asymmetric — `deserialize` is escape-aware), so a
 * value with a quote fails to round-trip and a value with a CR/LF splits the
 * emitted header. This wrapper closes both gaps; otherwise identical to
 * `mppx`'s `Challenge.serialize`.
 */
export const serialize: typeof MppxChallenge.serialize = (challenge =>
    MppxChallenge.serialize(guardSerializeInput(challenge))) as typeof MppxChallenge.serialize;

/**
 * Serializes multiple challenges into a single, comma-joined
 * `WWW-Authenticate` header value, applying the same escape / CR/LF guard to
 * every challenge (RFC 9110 §11.6.1). mppx exposes no `serializeList`, so we
 * join guarded `serialize` outputs the way `deserializeList` splits them.
 */
export const serializeList = ((challenges: readonly Parameters<typeof serialize>[0][]): string =>
    challenges.map(challenge => serialize(challenge)).join(', ')) as (
    challenges: readonly Parameters<typeof serialize>[0][],
) => string;

/**
 * The `Challenge` namespace as exposed by `@solana/mpp`: the upstream `mppx`
 * surface with the empty-id parse guard applied to the header-parsing entry
 * points and the escape / CR/LF guard applied to the header-formatting entry
 * points. Use this instead of importing `Challenge` directly from `mppx` when
 * canonical-conformant parsing or formatting is required.
 */
export const Challenge = {
    ...MppxChallenge,
    deserialize,
    deserializeList,
    serialize,
    serializeList,
} as typeof MppxChallenge & { serializeList: typeof serializeList };
