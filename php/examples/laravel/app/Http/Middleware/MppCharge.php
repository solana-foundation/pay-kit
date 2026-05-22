<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use SolanaMpp\Core\Challenge;
use SolanaMpp\Core\Credential;
use SolanaMpp\Intent\ChargeRequest;
use SolanaMpp\Server\ChargeServer;
use SolanaMpp\Server\PaymentVerifier;
use SolanaMpp\Server\VerificationResult;
use SolanaPhpSdk\Rpc\RpcClient;
use Symfony\Component\HttpFoundation\Response;

/**
 * Gates a Laravel route behind an MPP charge challenge.
 *
 * Returns 402 with a signed `www-authenticate` challenge when no credential is
 * presented or verification fails. On success the request reaches the route
 * handler and the response gains a `payment-receipt` header.
 */
final class MppCharge
{
    private readonly ChargeServer $server;
    private readonly ChargeRequest $request;
    private readonly PaymentVerifier $verifier;

    public function __construct()
    {
        $rpc = new RpcClient((string) env('MPP_RPC_URL', 'https://402.surfnet.dev:8899'));
        $this->server = new ChargeServer(
            secretKey: (string) env('MPP_SECRET', 'local-dev-secret'),
            realm: (string) env('MPP_REALM', 'PHP Laravel example'),
            blockhashProvider: fn (): string => $rpc->getLatestBlockhash()['blockhash'],
        );
        $this->request = new ChargeRequest(
            amount: (string) env('MPP_AMOUNT', '1000'),
            currency: (string) env('MPP_CURRENCY', 'USDC'),
            recipient: (string) env('MPP_RECIPIENT', 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'),
            description: 'Laravel protected endpoint',
            methodDetails: [
                'network' => (string) env('MPP_NETWORK', 'localnet'),
            ],
        );
        $this->verifier = new ExampleVerifier();
    }

    public function handle(Request $request, Closure $next): Response
    {
        $authorization = (string) $request->header('Authorization', '');
        $result = $authorization === ''
            ? VerificationResult::failure('Payment is required.')
            : $this->server->verifyAuthorizationHeader($authorization, $this->verifier, expectedRequest: $this->request);

        if (!$result->ok) {
            $problem = $this->server->paymentRequiredResponse($this->request, $result->reason);
            return response()->json($problem->body, $problem->status, $problem->headers);
        }

        /** @var Response $response */
        $response = $next($request);
        $response->headers->set('payment-receipt', $this->server->createReceiptHeader($result));
        return $response;
    }
}

/**
 * Demo verifier that accepts any non-empty signature/transaction reference.
 *
 * Replace with a real on-chain verifier — e.g. SolanaChargeTransactionVerifier
 * — before pointing this at a production network.
 */
final class ExampleVerifier implements PaymentVerifier
{
    public function verify(Credential $credential, Challenge $challenge): VerificationResult
    {
        $reference = $credential->payload['signature']
            ?? $credential->payload['transaction']
            ?? '';
        if (!is_string($reference) || $reference === '') {
            return VerificationResult::failure('missing payment reference');
        }

        return VerificationResult::success(reference: $reference);
    }
}
