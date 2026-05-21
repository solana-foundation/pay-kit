<?php

declare(strict_types=1);

use SolanaMpp\Core\Credential;
use SolanaMpp\Core\Headers;
use SolanaMpp\Core\Challenge;
use SolanaMpp\Intent\ChargeRequest;
use SolanaMpp\Server\ChargeServer;
use SolanaMpp\Server\SolanaChargeTransactionVerifier;

require_once __DIR__ . '/../../../php/vendor/autoload.php';

/**
 * Write a JSON response to stdout for the TypeScript harness.
 *
 * @param array<string, mixed> $value
 */
function write_json(array $value): void
{
    echo json_encode($value, JSON_THROW_ON_ERROR) . PHP_EOL;
}

/**
 * Read a required bridge input field.
 *
 * @param array<string, mixed> $input
 */
function required(array $input, string $key): mixed
{
    $value = $input[$key] ?? null;
    if ($value === null || $value === '') {
        throw new InvalidArgumentException($key . ' is required');
    }

    return $value;
}

/**
 * Build the charge request used for both challenge issuance and replay pinning.
 *
 * @param array<string, mixed> $input
 */
function charge_request(array $input): ChargeRequest
{
    $methodDetails = [
        'network' => $input['network'] ?? 'localnet',
        'decimals' => $input['decimals'] ?? 6,
    ];
    if (($input['feePayer'] ?? false) === true) {
        $methodDetails['feePayer'] = true;
        if (isset($input['feePayerKey'])) {
            $methodDetails['feePayerKey'] = $input['feePayerKey'];
        }
    }
    if (isset($input['recentBlockhash'])) {
        $methodDetails['recentBlockhash'] = $input['recentBlockhash'];
    }
    if (isset($input['splits'])) {
        $methodDetails['splits'] = $input['splits'];
    }

    return new ChargeRequest(
        amount: (string) required($input, 'amount'),
        currency: (string) required($input, 'currency'),
        recipient: (string) required($input, 'recipient'),
        description: isset($input['description']) ? (string) $input['description'] : '',
        methodDetails: $methodDetails,
    );
}

/**
 * Emit a Payment challenge for the requested charge.
 *
 * @param array<string, mixed> $input
 */
function challenge(array $input): void
{
    $server = new ChargeServer(
        secretKey: (string) required($input, 'secretKey'),
        realm: 'MPP Interop',
    );
    $request = charge_request($input);
    $challenge = $server->createChallenge($request);
    write_json([
        'type' => 'challenge',
        'request' => $request->toArray(),
        'wwwAuthenticate' => Headers::formatWwwAuthenticate($challenge),
    ]);
}

/**
 * Verify a Payment credential against an expected charge request.
 *
 * @param array<string, mixed> $input
 */
function verify_payment(array $input): void
{
    $server = new ChargeServer(
        secretKey: (string) required($input, 'secretKey'),
        realm: 'MPP Interop',
    );
    $expected = ChargeRequest::fromArray(required($input, 'expected'));
    $result = $server->verifyAuthorizationHeader(
        (string) required($input, 'authorization'),
        new SolanaChargeTransactionVerifier(),
        expectedRequest: $expected,
    );
    if (!$result->ok) {
        throw new InvalidArgumentException($result->reason ?? 'payment verification failed');
    }

    $credential = Credential::fromAuthorizationHeader((string) required($input, 'authorization'));
    $echo = $credential->challenge;
    $challenge = new Challenge(
        id: $echo->id,
        realm: $echo->realm,
        method: $echo->method,
        intent: $echo->intent,
        request: $echo->request,
        expires: $echo->expires,
        digest: $echo->digest,
        opaque: $echo->opaque,
    );

    write_json([
        'type' => 'verified',
        'receipt' => $server->createReceiptHeader($challenge, $result),
        'reference' => $result->reference,
        'transaction' => $credential->payload['transaction'] ?? null,
        'signature' => $credential->payload['signature'] ?? null,
    ]);
}

/**
 * Map verifier failures to structured bridge error codes.
 */
function error_code(string $message): string
{
    return match (true) {
        str_contains($message, 'charge request mismatch') => 'charge_request_mismatch',
        str_contains($message, 'challenge realm mismatch') => 'challenge_realm_mismatch',
        str_contains($message, 'challenge verification failed') => 'challenge_verification_failed',
        str_contains($message, 'challenge expired') => 'challenge_expired',
        str_contains($message, 'challenge method or intent mismatch') => 'challenge_method_or_intent_mismatch',
        str_contains($message, 'missing settlement reference') => 'missing_settlement_reference',
        default => 'bridge_error',
    };
}

try {
    $input = json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR);
    if (!is_array($input)) {
        throw new InvalidArgumentException('input must be an object');
    }

    $command = (string) required($input, 'command');
    match ($command) {
        'challenge' => challenge($input),
        'verify' => verify_payment($input),
        default => throw new InvalidArgumentException('unsupported command: ' . $command),
    };
} catch (Throwable $error) {
    write_json([
        'type' => 'error',
        'code' => error_code($error->getMessage()),
        'error' => $error->getMessage(),
    ]);
    exit(1);
}
