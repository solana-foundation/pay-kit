<?php

declare(strict_types=1);

/**
 * PHP mpp-protocol primitive conformance runner.
 *
 * Speaks the canonical mpp-tools adapter ABI used by the protocol-conformance
 * layer (harness/src/protocol/runners/typescript.ts is the reference): read one
 *   { "op": "<operation>", "input": <op-specific> }
 * request as JSON on stdin and write one
 *   { "success": true,  "result": <op-specific> }
 *   { "success": false, "error": "<msg>", "error_type": "<type>" }
 * response as JSON on stdout. This is the protocol-primitive counterpart to the
 * charge/x402 conformance runner (conformance/runner.php); the two ABIs are
 * distinct, so they live in separate entrypoints.
 *
 * The operations map onto the PHP SDK's existing protocol surface
 * (PayKit\Protocols\Mpp\Core\*, PayKit\PayCore\Wire\*) per the Reference map:
 *
 *   challenge.parse   -> Headers::parseWwwAuthenticate
 *   challenge.format  -> Headers::formatWwwAuthenticate
 *   credential.parse  -> Credential::fromAuthorizationHeader
 *   credential.format -> Credential::toAuthorizationHeader
 *   receipt.parse     -> Headers::parseReceipt
 *   receipt.format    -> Headers::formatReceipt
 *   base64url.encode  -> Base64Url::encode
 *   base64url.decode  -> Base64Url::decode
 *   challenge.id      -> Challenge::computeId
 *
 * Every operation here is implemented by the PHP SDK, so this runner never
 * emits unsupported_operation for the canonical op set; it only does so for an
 * op string the SDK has no surface for (forward-compat guard).
 *
 * RPC-free and deterministic: no validator, no network, no signing. Pure
 * wire codec + HMAC math.
 */

error_reporting(error_reporting() & ~E_DEPRECATED & ~E_USER_DEPRECATED);
ini_set('display_errors', 'stderr');

require __DIR__ . '/../vendor/autoload.php';

use PayKit\PayCore\Wire\Base64Url;
use PayKit\PayCore\Wire\Json;
use PayKit\Protocols\Mpp\Core\Challenge;
use PayKit\Protocols\Mpp\Core\Credential;
use PayKit\Protocols\Mpp\Core\Headers;

/**
 * Re-encode a JSON `request` slot to the SDK's stored base64url(JCS) form,
 * preserving the object/array distinction that PHP's associative decode
 * erases.
 *
 * PHP collapses both `{}` and `[]` to the same empty `array`, and
 * Json::canonicalize emits a list `[]` for it, so a request that is (or nests)
 * an empty JSON object would canonicalize to `[]` (`W10`) instead of `{}`
 * (`e30`). The canonical wire and every other SDK encode an empty object as
 * `{}`. This re-decodes the slot from the ORIGINAL JSON text with object
 * preservation (json_decode without associative) and recurses, deferring every
 * scalar and every non-empty container to the SDK canonicalizer
 * (Json::canonicalize) — only the empty-object ambiguity is resolved here, not
 * a second JCS implementation.
 *
 * `$requestJson` is the raw JSON text of the request slot; `$fallback` is the
 * already-decoded associative value used when no raw text is available.
 */
function request_to_base64url(?string $requestJson, mixed $fallback): string
{
    if ($requestJson !== null) {
        $preserving = json_decode($requestJson, false, flags: JSON_THROW_ON_ERROR);
        return Base64Url::encode(canonicalize_preserving_objects($preserving));
    }
    if (is_array($fallback) && $fallback !== []) {
        return Base64Url::encodeJson($fallback);
    }
    // Absent or empty object -> canonical `{}`.
    return Base64Url::encode('{}');
}

/**
 * RFC 8785 canonical JSON that keeps empty objects as `{}`.
 *
 * A value with no empty-object descendants is canonicalized in one shot by the
 * SDK (Json::canonicalize on its associative form), so the JCS math (key order,
 * number/string escaping) is always the SDK's. Only when an empty object is
 * present (which PHP's array type cannot distinguish from `[]`) does this
 * recurse to splice the literal `{}` token into the SDK-canonical object,
 * preserving the SDK's key ordering by canonicalizing the object with that key
 * temporarily mapped to a unique sentinel and substituting the `{}` back in.
 */
function canonicalize_preserving_objects(mixed $value): string
{
    if (!has_empty_object($value)) {
        return Json::canonicalize(object_tree_to_assoc($value));
    }
    if ($value instanceof \stdClass) {
        $entries = get_object_vars($value);
        if ($entries === []) {
            return '{}';
        }
        // Map every value to a unique scalar sentinel string, canonicalize the
        // object through the SDK (exact JCS key order + key escaping), then
        // replace each quoted sentinel with its child's canonical bytes,
        // recursing so nested empty objects resolve to `{}`.
        $sentinels = [];
        $substitutions = [];
        $i = 0;
        foreach ($entries as $k => $v) {
            $token = "\u{0000}sentinel{$i}\u{0000}";
            $sentinels[(string) $k] = $token;
            // The SDK emits the sentinel as a JSON string literal; map that
            // exact literal to the child's already-canonical bytes.
            $substitutions[Json::canonicalize($token)] = canonicalize_preserving_objects($v);
            $i++;
        }
        return strtr(Json::canonicalize($sentinels), $substitutions);
    }
    if (is_array($value)) {
        $parts = array_map('canonicalize_preserving_objects', $value);
        return '[' . implode(',', $parts) . ']';
    }

    return Json::canonicalize($value);
}

/**
 * Recursively convert a json_decode object tree (stdClass + array) to the
 * associative-array shape the SDK canonicalizer consumes. Only used for values
 * with no empty objects, so the lossy `{}` -> `[]` collapse never bites.
 */
function object_tree_to_assoc(mixed $value): mixed
{
    if ($value instanceof \stdClass) {
        $out = [];
        foreach (get_object_vars($value) as $k => $v) {
            $out[(string) $k] = object_tree_to_assoc($v);
        }
        return $out;
    }
    if (is_array($value)) {
        return array_map('object_tree_to_assoc', $value);
    }
    return $value;
}

/**
 * True when $value is, or contains anywhere, an empty JSON object (`{}`),
 * decoded with object preservation as an empty stdClass.
 */
function has_empty_object(mixed $value): bool
{
    if ($value instanceof \stdClass) {
        $entries = get_object_vars($value);
        if ($entries === []) {
            return true;
        }
        foreach ($entries as $v) {
            if (has_empty_object($v)) {
                return true;
            }
        }
        return false;
    }
    if (is_array($value)) {
        foreach ($value as $v) {
            if (has_empty_object($v)) {
                return true;
            }
        }
    }
    return false;
}

/**
 * Read the entire request JSON from stdin.
 */
function read_stdin(): string
{
    $raw = stream_get_contents(STDIN);
    if (!is_string($raw)) {
        throw new RuntimeException('php protocol runner failed to read stdin');
    }
    $trimmed = trim($raw);
    if ($trimmed === '') {
        throw new RuntimeException('php protocol runner received empty stdin');
    }
    return $trimmed;
}

/**
 * @param array<string, mixed> $result
 */
function emit(array $result): void
{
    fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
}

/**
 * Map the PHP SDK's parsed Challenge onto the canonical adapter-ABI challenge
 * object shape. The canonical object carries `request` as a DECODED JSON
 * object (not the base64url string the PHP value type stores), so we decode it
 * here, exactly as mppx's deserialized challenge surfaces it.
 *
 * The PHP parser intentionally drops unknown auth-params (including
 * `description`), mirroring the rust spine's strict PaymentChallenge struct.
 * The canonical golden object echoes a top-level `description` when the wire
 * carried one, so scenarios that pin a description diverge structurally on
 * that single field; the runner emits the SDK's true output and the driver
 * reports the gap honestly.
 *
 * @return array<string, mixed>
 */
function challenge_to_canonical(Challenge $challenge): array
{
    $object = [
        'id' => $challenge->id,
        'realm' => $challenge->realm,
        'method' => $challenge->method,
        'intent' => $challenge->intent,
        // Decode the stored base64url(JCS) request with OBJECT preservation so an
        // empty `{}` survives as a JSON object, not the `[]` PHP's associative
        // decode + json_encode would otherwise emit. The canonical wire and
        // every other SDK echo an empty request as `{}`.
        'request' => json_decode(Base64Url::decode($challenge->request), false, flags: JSON_THROW_ON_ERROR),
    ];
    if ($challenge->description !== null) {
        $object['description'] = $challenge->description;
    }
    if ($challenge->expires !== '') {
        $object['expires'] = $challenge->expires;
    }
    if ($challenge->digest !== '') {
        $object['digest'] = $challenge->digest;
    }
    if ($challenge->opaque !== null) {
        $object['opaque'] = $challenge->opaque;
    }

    return $object;
}

/**
 * Build a PHP Challenge value type from the canonical adapter-ABI challenge
 * object. `request` arrives as a decoded JSON object and must be re-encoded to
 * the base64url(JCS) form the PHP value type stores. A non-lowercase or empty
 * required field surfaces through the Challenge constructor as a format_error.
 *
 * @param array<string, mixed> $object
 */
function challenge_from_canonical(array $object, mixed $requestObj = null): Challenge
{
    $request = $object['request'] ?? [];
    if (!is_array($request)) {
        throw new InvalidArgumentException('challenge.request must be an object');
    }

    // Encode the request from the object-preserving input so an empty `{}`
    // canonicalizes to `e30`, not the `[]` -> `W10` PHP's associative array
    // would yield. The JCS math stays the SDK canonicalizer's.
    $encodedRequest = $requestObj !== null
        ? Base64Url::encode(canonicalize_preserving_objects($requestObj))
        : Base64Url::encodeJson($request);

    return new Challenge(
        id: as_string($object['id'] ?? null, 'id'),
        realm: as_string($object['realm'] ?? null, 'realm'),
        method: as_string($object['method'] ?? null, 'method'),
        intent: as_string($object['intent'] ?? null, 'intent'),
        request: $encodedRequest,
        expires: opt_string($object['expires'] ?? null),
        digest: opt_string($object['digest'] ?? null),
        opaque: isset($object['opaque']) ? as_string($object['opaque'], 'opaque') : null,
        description: isset($object['description']) ? as_string($object['description'], 'description') : null,
    );
}

/**
 * Build a PHP Credential from the canonical adapter-ABI credential object.
 * The canonical object nests the challenge with `request` as a decoded object;
 * ChallengeEcho::fromArray already re-encodes a nested object request to the
 * stored base64url(JCS) string, so the object is consumed as-is.
 *
 * @param array<string, mixed> $object
 */
function credential_from_canonical(array $object): Credential
{
    // Round-trip through the SDK's own credential decoder by serializing the
    // canonical object to the SDK's Authorization wire and parsing it back.
    // This drives Credential::fromAuthorizationHeader (the parse surface) for
    // the format direction, so format and parse share one code path and the
    // SDK owns every field-shape decision (challenge echo, payload, source).
    $header = 'Payment ' . Base64Url::encodeJson($object);
    return Credential::fromAuthorizationHeader($header);
}

function as_string(mixed $value, string $field): string
{
    if (!is_string($value)) {
        throw new InvalidArgumentException(sprintf('field "%s" must be a string', $field));
    }
    return $value;
}

function opt_string(mixed $value): string
{
    return is_string($value) ? $value : '';
}

/**
 * @param array<string, mixed> $input
 */
function require_header(array $input): string
{
    $header = $input['header'] ?? null;
    if (!is_string($header)) {
        throw new InvalidArgumentException('input.header must be a string');
    }
    return $header;
}

/**
 * @param array<string, mixed> $input
 */
function require_text(array $input): string
{
    $text = $input['text'] ?? null;
    if (!is_string($text)) {
        throw new InvalidArgumentException('input.text must be a string');
    }
    return $text;
}

/**
 * Dispatch a single adapter-ABI request to the PHP SDK protocol surface.
 *
 * `$input` is the associative-decoded input; `$inputObj` is the same input
 * decoded with object preservation (stdClass for objects), used only to keep
 * the empty-object `{}` distinction PHP's associative decode erases — needed
 * for the byte-exact challenge.id HMAC.
 *
 * @param array<string, mixed> $input
 * @return array<string, mixed> the success result payload (op-specific)
 */
function dispatch(string $op, array $input, mixed $inputObj): array
{
    switch ($op) {
        case 'challenge.parse':
            return challenge_to_canonical(Headers::parseWwwAuthenticate(require_header($input)));

        case 'challenge.format':
            $requestObj = ($inputObj instanceof \stdClass && property_exists($inputObj, 'request'))
                ? $inputObj->request
                : null;
            return ['header' => Headers::formatWwwAuthenticate(challenge_from_canonical($input, $requestObj))];

        case 'credential.parse':
            return Credential::fromAuthorizationHeader(require_header($input))->toArray();

        case 'credential.format':
            return ['header' => credential_from_canonical($input)->toAuthorizationHeader()];

        case 'receipt.parse':
            return Headers::parseReceipt(require_header($input))->toArray();

        case 'receipt.format':
            // Re-issue the SDK's own receipt parse over a wire built from the
            // canonical object, so the format direction drives the SDK
            // formatter (Headers::formatReceipt) on a faithfully-typed Receipt.
            $receipt = Headers::parseReceipt(Base64Url::encodeJson($input));
            return ['header' => Headers::formatReceipt($receipt)];

        case 'base64url.encode':
            return ['text' => Base64Url::encode(require_text($input))];

        case 'base64url.decode':
            return ['text' => Base64Url::decode(require_text($input))];

        case 'challenge.id':
            $request = $input['request'] ?? [];
            if (!is_array($request)) {
                throw new InvalidArgumentException('challenge.id input.request must be an object');
            }
            // Encode the request from the object-preserving input so an empty
            // `{}` canonicalizes to `e30`, not `[]` -> `W10`. The HMAC math,
            // pipe layout, and base64url all stay the SDK's (Challenge::computeId).
            $requestObj = ($inputObj instanceof \stdClass && property_exists($inputObj, 'request'))
                ? $inputObj->request
                : $request;
            $id = Challenge::computeId(
                as_string($input['secretKey'] ?? null, 'secretKey'),
                opt_string($input['realm'] ?? null),
                opt_string($input['method'] ?? null),
                opt_string($input['intent'] ?? null),
                request_to_base64url(json_encode($requestObj, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: null, $request),
                opt_string($input['expires'] ?? null),
                opt_string($input['digest'] ?? null),
                isset($input['opaque']) ? as_string($input['opaque'], 'opaque') : null,
            );
            return ['id' => $id];

        default:
            throw new RuntimeException('UNSUPPORTED_OPERATION');
    }
}

/**
 * Classify a thrown error into the canonical error_type vocabulary keyed on
 * the operation suffix (mirrors the TS reference runner's catch arm).
 */
function error_type_for(string $op): string
{
    if (str_ends_with($op, '.parse')) {
        return 'parse_error';
    }
    if (str_ends_with($op, '.format')) {
        return 'format_error';
    }
    if (str_starts_with($op, 'base64url.')) {
        return 'encoding_error';
    }
    if ($op === 'challenge.id') {
        return 'generation_error';
    }
    return 'unknown_error';
}

try {
    $raw = read_stdin();
    $request = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
    if (!is_array($request)) {
        throw new RuntimeException('request must be a JSON object');
    }
    $op = $request['op'] ?? null;
    if (!is_string($op) || $op === '') {
        throw new RuntimeException('request.op must be a non-empty string');
    }
    $input = $request['input'] ?? [];
    if (!is_array($input)) {
        throw new RuntimeException('request.input must be an object');
    }
    // Object-preserving copy of input so the empty-object `{}` distinction
    // survives for challenge.id (PHP's associative decode collapses `{}` to []).
    $requestObj = json_decode($raw, false, flags: JSON_THROW_ON_ERROR);
    $inputObj = ($requestObj instanceof \stdClass && property_exists($requestObj, 'input'))
        ? $requestObj->input
        : null;

    try {
        $result = dispatch($op, $input, $inputObj);
        emit(['success' => true, 'result' => $result]);
    } catch (Throwable $error) {
        if ($error->getMessage() === 'UNSUPPORTED_OPERATION') {
            emit([
                'success' => false,
                'error' => 'php protocol runner does not implement operation: ' . $op,
                'error_type' => 'unsupported_operation',
            ]);
        } else {
            emit([
                'success' => false,
                'error' => $error->getMessage(),
                'error_type' => error_type_for($op),
            ]);
        }
    }
} catch (Throwable $fatal) {
    fwrite(STDERR, 'php protocol runner fatal: ' . $fatal->getMessage() . "\n");
    emit([
        'success' => false,
        'error' => $fatal->getMessage(),
        'error_type' => 'unknown_error',
    ]);
    exit(1);
}
