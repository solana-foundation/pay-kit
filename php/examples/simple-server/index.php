<?php

declare(strict_types=1);

use SolanaMpp\Core\Challenge;
use SolanaMpp\Core\Credential;
use SolanaMpp\Intent\ChargeRequest;
use SolanaMpp\Server\ChargeServer;
use SolanaMpp\Server\PaymentVerifier;
use SolanaMpp\Server\VerificationResult;
use SolanaPhpSdk\Rpc\RpcClient;

require_once __DIR__ . '/../../vendor/autoload.php';

$rpc = new RpcClient('https://402.surfnet.dev:8899');
$server = new ChargeServer(
    secretKey: 'local-dev-secret',
    realm: 'PHP example',
    blockhashProvider: fn (): string => $rpc->getLatestBlockhash()['blockhash'],
);
$request = new ChargeRequest(
    amount: '1000',
    currency: 'USDC',
    recipient: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
    methodDetails: ['network' => 'localnet'],
);

$verifier = new class () implements PaymentVerifier {
    public function verify(Credential $credential, Challenge $challenge): VerificationResult
    {
        $reference = $credential->payload['signature'] ?? $credential->payload['transaction'] ?? '';
        return is_string($reference) && $reference !== ''
            ? VerificationResult::success(reference: $reference)
            : VerificationResult::failure('missing payment reference');
    }
};

$rawAuthorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
$authorization = is_string($rawAuthorization) ? $rawAuthorization : '';
$result = $authorization === ''
    ? VerificationResult::failure('Payment is required.')
    : $server->verifyAuthorizationHeader($authorization, $verifier, expectedRequest: $request);

if (!$result->ok) {
    $problem = $server->paymentRequiredResponse($request, $result->reason);
    http_response_code($problem->status);
    foreach ($problem->headers as $name => $value) {
        // Pinning the status on every header() call avoids PHP's built-in CLI
        // server rewriting 402 to 401 when WWW-Authenticate is present.
        header($name . ': ' . $value, true, $problem->status);
    }
    echo json_encode($problem->body, JSON_THROW_ON_ERROR);
    return;
}

header('content-type: application/json');
header('payment-receipt: ' . $server->createReceiptHeader($result));
echo json_encode(['ok' => true, 'paid' => true], JSON_THROW_ON_ERROR);
