<?php

declare(strict_types=1);

namespace PayKit\Middleware;

use Closure;
use PayKit\PayKit;
use PayKit\Exception\InvalidProofException;
use PayKit\Exception\PaymentRequiredException;
use PayKit\Gate;
use PayKit\PayCore\HttpFactory;
use PayKit\Pricing;
use PayKit\Protocol;
use PayKit\Protocols\Mpp\Adapter as MppAdapter;
use PayKit\Protocols\X402\Adapter as X402Adapter;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * PSR-15 middleware that gates a route behind a {@see Gate}.
 *
 * Three shapes for the gate argument:
 *
 *   - `Gate $gate` — concrete value object (inline pricing).
 *   - `string $name` — property name on a {@see Pricing} instance;
 *     resolved via the constructor-supplied $pricing fallback or
 *     the request attribute "paykit.pricing".
 *   - `Closure(ServerRequestInterface): Gate` — dynamic resolver.
 *
 * On success the middleware attaches the verified {@see \PayKit\Payment}
 * to the request as "paykit.payment" and calls the next handler;
 * settlement headers are merged into the upstream 2xx response. On
 * failure it short-circuits with a 402 carrying the active protocol
 * adapter's challenge headers and an `error: "payment_required"`
 * JSON body.
 */
final class RequirePayment implements MiddlewareInterface
{
    private MppAdapter $mpp;
    private ?X402Adapter $x402;

    /**
     * @param Gate|string|Closure(ServerRequestInterface):Gate $gateRef
     */
    public function __construct(
        private readonly PayKit $client,
        private readonly Gate|string|Closure $gateRef,
        private readonly ?Pricing $pricing = null,
        ?MppAdapter $mpp = null,
        ?X402Adapter $x402 = null,
    ) {
        $this->mpp  = $mpp ?? new MppAdapter($client->config);
        // Auto-wire the X402 adapter when the client's accept list
        // includes Protocol::X402. Callers can still pass an explicit
        // adapter to override (e.g. with an offline blockhash provider).
        if ($x402 !== null) {
            $this->x402 = $x402;
        } elseif (in_array(Protocol::X402, $client->config->accept, true)) {
            $this->x402 = new X402Adapter($client->config);
        } else {
            $this->x402 = null;
        }
    }

    public function process(
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $gate = $this->resolveGate($request);

        $adapter = $this->pickAdapter($gate, $request);
        if ($adapter === null) {
            return $this->build402($gate, $request);
        }

        try {
            $payment = $adapter->verifyAndSettle($gate, $request);
        } catch (InvalidProofException | PaymentRequiredException $e) {
            return $this->build402($gate, $request);
        }

        $req = $request->withAttribute('paykit.payment', $payment);
        $response = $handler->handle($req);
        foreach ($payment->settlementHeaders as $k => $v) {
            $response = $response->withHeader($k, $v);
        }
        return $response;
    }

    private function resolveGate(ServerRequestInterface $request): Gate
    {
        if ($this->gateRef instanceof Gate) {
            return $this->gateRef;
        }
        if ($this->gateRef instanceof Closure) {
            return ($this->gateRef)($request);
        }
        $pricing = $this->pricing ?? $request->getAttribute('paykit.pricing');
        if (!$pricing instanceof Pricing) {
            throw new \LogicException(sprintf(
                'pay_kit: RequirePayment("%s") needs a Pricing instance via the '
                . 'constructor or request attribute "paykit.pricing"',
                $this->gateRef,
            ));
        }
        return $pricing->gate($this->gateRef);
    }

    private function pickAdapter(Gate $gate, ServerRequestInterface $request): ?object
    {
        $accept = $gate->accept ?? $this->client->config->accept;
        $auth = $request->getHeaderLine('Authorization');
        $sig  = $request->getHeaderLine('Payment-Signature');
        foreach ($accept as $protocol) {
            if ($protocol === Protocol::X402 && $sig !== '' && $this->x402 !== null) {
                return $this->x402;
            }
            if ($protocol === Protocol::Mpp && $auth !== '' && stripos($auth, 'payment ') === 0) {
                return $this->mpp;
            }
        }
        return null;
    }

    private function build402(Gate $gate, ServerRequestInterface $request): ResponseInterface
    {
        $accepts = [];
        $headers = [];
        $accept = $gate->accept ?? $this->client->config->accept;

        if ($this->x402 !== null && in_array(Protocol::X402, $accept, true) && !$gate->hasFees()) {
            $accepts[] = $this->x402->acceptsEntry($gate, $request);
            $headers   = array_merge($headers, $this->x402->challengeHeaders($gate, $request));
        }
        if (in_array(Protocol::Mpp, $accept, true)) {
            $accepts[] = $this->mpp->acceptsEntry($gate, $request);
            $headers   = array_merge($headers, $this->mpp->challengeHeaders($gate, $request));
        }

        $body = [
            'error'    => 'payment_required',
            'resource' => $request->getUri()->getPath(),
            'accepts'  => $accepts,
        ];
        $factory = HttpFactory::responseFactory();
        // 402 challenges are per-request and MUST NOT be cached by any
        // intermediary or browser. Without `no-store` a CDN could replay a
        // stale challenge (different blockhash / expiry / amount) to a
        // later client. Matches the protocol 402 helper at
        // ChargeServer::paymentRequiredResponse() and the cross-SDK rule
        // (main-audit medium finding 6).
        $resp = $factory->createResponse(402)
            ->withHeader('cache-control', 'no-store')
            ->withHeader('content-type', 'application/json');
        foreach ($headers as $k => $v) {
            $resp = $resp->withHeader($k, $v);
        }
        $stream = HttpFactory::streamFactory()->createStream(json_encode($body, JSON_THROW_ON_ERROR));
        return $resp->withBody($stream);
    }
}
