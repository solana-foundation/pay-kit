<?php

declare(strict_types=1);

use SolanaMpp\Core\Challenge;
use SolanaMpp\Core\Credential;
use SolanaMpp\Intent\ChargeRequest;
use SolanaMpp\Server\ChargeServer;
use SolanaMpp\Server\PaymentVerifier;
use SolanaMpp\Server\VerificationResult;

require_once __DIR__ . '/../vendor/autoload.php';

/**
 * Demonstrates how an application verifies a credential payload.
 */
final class ExampleVerifier implements PaymentVerifier
{
    /**
     * Accept a demo signature/transaction reference from the credential payload.
     */
    public function verify(Credential $credential, Challenge $challenge): VerificationResult
    {
        $reference = $credential->payload['signature'] ?? $credential->payload['transaction'] ?? '';
        if (!is_string($reference) || $reference === '') {
            return VerificationResult::failure('missing payment reference');
        }

        return VerificationResult::success(reference: $reference);
    }
}

$server = new ChargeServer(secretKey: 'local-dev-secret', realm: 'PHP example');
$request = new ChargeRequest(
    amount: '1000',
    currency: 'USDC',
    recipient: 'ExampleRecipient1111111111111111111111111111111',
    description: 'PHP example protected endpoint',
    methodDetails: [
        'network' => 'localnet',
    ],
);

$path = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH);
if ($path !== '/paid') {
    http_response_code(404);
    header('content-type: application/json');
    echo json_encode(['error' => 'not_found'], JSON_THROW_ON_ERROR);
    return;
}

$authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
if ($authorization === '') {
    http_response_code(402);
    header('cache-control: no-store');
    header('content-type: application/problem+json');
    header('www-authenticate: ' . $server->createChallengeHeader($request));
    echo json_encode([
        'detail' => 'Payment is required.',
        'status' => 402,
        'title' => 'Payment Required',
        'type' => 'https://paymentauth.org/problems/payment-required',
    ], JSON_THROW_ON_ERROR);
    return;
}

$result = $server->verifyAuthorizationHeader(
    $authorization,
    new ExampleVerifier(),
    expectedRequest: $request,
);

if (!$result->ok) {
    http_response_code(402);
    header('cache-control: no-store');
    header('content-type: application/problem+json');
    header('www-authenticate: ' . $server->createChallengeHeader($request));
    echo json_encode([
        'detail' => $result->reason,
        'status' => 402,
        'title' => 'Payment Required',
        'type' => 'https://paymentauth.org/problems/payment-required',
    ], JSON_THROW_ON_ERROR);
    return;
}

$credential = Credential::fromAuthorizationHeader($authorization);
$challenge = new Challenge(
    id: $credential->challenge->id,
    realm: $credential->challenge->realm,
    method: $credential->challenge->method,
    intent: $credential->challenge->intent,
    request: $credential->challenge->request,
    expires: $credential->challenge->expires,
    digest: $credential->challenge->digest,
    opaque: $credential->challenge->opaque,
);

http_response_code(200);
header('content-type: application/json');
header('payment-receipt: ' . $server->createReceiptHeader($challenge, $result));
echo json_encode(['ok' => true, 'paid' => true], JSON_THROW_ON_ERROR);
