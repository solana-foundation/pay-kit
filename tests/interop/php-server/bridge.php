<?php

declare(strict_types=1);

use SolanaMpp\Core\Credential;
use SolanaMpp\Core\Headers;
use SolanaMpp\Core\Json;
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
 * Read a required bridge input string.
 *
 * @param array<string, mixed> $input
 */
function required_string(array $input, string $key): string
{
    return Json::string(required($input, $key), $key);
}

/**
 * Read a required bridge input object.
 *
 * @param array<string, mixed> $input
 * @return array<string, mixed>
 */
function required_object(array $input, string $key): array
{
    return Json::object(required($input, $key), $key);
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
        amount: required_string($input, 'amount'),
        currency: required_string($input, 'currency'),
        recipient: required_string($input, 'recipient'),
        description: Json::optionalString($input['description'] ?? null, 'description'),
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
        secretKey: required_string($input, 'secretKey'),
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
        secretKey: required_string($input, 'secretKey'),
        realm: 'MPP Interop',
    );
    $expected = ChargeRequest::fromArray(required_object($input, 'expected'));
    $result = $server->verifyAuthorizationHeader(
        required_string($input, 'authorization'),
        new SolanaChargeTransactionVerifier(),
        expectedRequest: $expected,
    );
    if (!$result->ok) {
        throw new InvalidArgumentException('payment rejected: ' . $result->reason);
    }

    $credential = Credential::fromAuthorizationHeader(required_string($input, 'authorization'));

    write_json([
        'type' => 'verified',
        'challenge' => [
            'id' => $credential->challenge->id,
            'request' => $credential->challenge->toChallenge()->decodeRequest(),
        ],
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
        str_starts_with($message, 'payment rejected: ') => 'payment_rejected',
        default => 'bridge_error',
    };
}

try {
    $input = Json::object(json_decode(stream_get_contents(STDIN), true, flags: JSON_THROW_ON_ERROR), 'input');

    $command = required_string($input, 'command');
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
