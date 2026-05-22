<?php

declare(strict_types=1);

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use SolanaMpp\Intent\ChargeRequest;
use SolanaMpp\Server\ChargeServer;
use SolanaMpp\Server\ChargeSettlement;
use SolanaMpp\Server\PaymentRequiredResponse;
use SolanaMpp\Server\SolanaChargeHandler;
use SolanaPhpSdk\Rpc\RpcClient;
use Symfony\Component\HttpFoundation\Response;

/**
 * Gates a Laravel route behind an MPP charge.
 *
 * 402 + `www-authenticate` when the credential is missing or fails
 * verification. On success the payment has already been broadcast and
 * confirmed by `SolanaChargeHandler`; the middleware forwards the request to
 * the route handler and attaches `payment-receipt` plus the on-chain
 * signature to whatever response the route returns, so the route still owns
 * the response body.
 */
final class MppCharge
{
    private readonly SolanaChargeHandler $handler;
    private readonly ChargeRequest $request;

    public function __construct()
    {
        $rpc = new RpcClient((string) env('MPP_RPC_URL', 'https://402.surfnet.dev:8899'));
        $this->handler = new SolanaChargeHandler(
            challenges: new ChargeServer(
                secretKey: (string) env('MPP_SECRET', 'local-dev-secret'),
                realm: (string) env('MPP_REALM', 'PHP Laravel example'),
                blockhashProvider: fn (): string => $rpc->getLatestBlockhash()['blockhash'],
            ),
            rpc: $rpc,
            network: (string) env('MPP_NETWORK', 'localnet'),
        );
        $this->request = new ChargeRequest(
            amount: (string) env('MPP_AMOUNT', '1000'),
            currency: (string) env('MPP_CURRENCY', 'USDC'),
            recipient: (string) env('MPP_RECIPIENT', 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY'),
            description: 'Laravel protected endpoint',
            methodDetails: [
                'network' => (string) env('MPP_NETWORK', 'localnet'),
                'decimals' => 6,
            ],
        );
    }

    public function handle(Request $request, Closure $next): Response
    {
        $authorization = (string) $request->header('Authorization', '');
        $result = $this->handler->handle($authorization === '' ? null : $authorization, $this->request);

        if ($result instanceof PaymentRequiredResponse) {
            return response()->json($result->body, $result->status, $result->headers);
        }

        /** @var ChargeSettlement $result */
        /** @var Response $response */
        $response = $next($request);
        foreach ($result->headers as $name => $value) {
            if (strtolower($name) === 'content-type') {
                continue; // let the route own its own content type
            }
            $response->headers->set($name, $value);
        }
        return $response;
    }
}
