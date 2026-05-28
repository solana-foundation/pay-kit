<?php

declare(strict_types=1);

namespace PayKit\Frameworks\Laravel;

use Closure;
use Illuminate\Contracts\Container\Container;
use Illuminate\Http\Request;
use PayKit\Client;
use PayKit\Gate;
use PayKit\Middleware\RequirePayment;
use PayKit\PayCore\HttpFactory;
use PayKit\Payment;
use PayKit\Pricing;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;

/**
 * Laravel route middleware. Mounted via the `paykit` alias the
 * service provider registers:
 *
 *   Route::get('/report', ReportController::class)
 *       ->middleware('paykit:report');         // string handle
 *
 *   Route::get('/oneoff', $handler)
 *       ->middleware('paykit');                // inline; gate comes from container
 *
 * The handle string is resolved against the bound {@see Pricing}
 * instance. Bridges Laravel's HTTP request to PSR-7 via
 * symfony/psr-http-message-bridge and delegates to the canonical
 * {@see RequirePayment} PSR-15 middleware so both stacks share one
 * implementation.
 */
final class RequirePaymentMiddleware
{
    public function __construct(
        private readonly Client $client,
        private readonly Container $container,
        private readonly PsrHttpFactory $psrFactory,
        private readonly HttpFoundationFactory $httpFactory,
    ) {
    }

    public function handle(Request $request, Closure $next, ?string $gateHandle = null)
    {
        $gateRef = $gateHandle ?? null;
        if ($gateRef === null) {
            // Inline form: caller wraps the gate in container binding
            // or attaches a Gate to the request attributes.
            $gateRef = $request->attributes->get('paykit.gate');
        }
        if ($gateRef === null) {
            throw new \LogicException(
                'pay_kit: middleware("paykit") needs a gate handle, '
                . 'e.g. middleware("paykit:report")',
            );
        }

        $pricing = $this->container->bound(Pricing::class)
            ? $this->container->make(Pricing::class)
            : null;

        $psrRequest = $this->psrFactory->createRequest($request);

        $captured = null;
        $next = function ($req) use (&$captured) {
            $captured = $req;
            $factory = HttpFactory::responseFactory();
            return $factory->createResponse(200);
        };
        $handler = new class ($next) implements \Psr\Http\Server\RequestHandlerInterface {
            public function __construct(private $next)
            {
            }
            public function handle(\Psr\Http\Message\ServerRequestInterface $request): \Psr\Http\Message\ResponseInterface
            {
                return ($this->next)($request);
            }
        };

        $mw = new RequirePayment($this->client, $gateRef, $pricing);
        $psrResponse = $mw->process($psrRequest, $handler);

        if ($psrResponse->getStatusCode() === 402) {
            // Convert PSR-7 response back to Laravel.
            return $this->httpFactory->createResponse($psrResponse);
        }

        // Payment present; carry it onto the Laravel request and call next.
        $payment = $captured?->getAttribute('paykit.payment');
        if ($payment instanceof Payment) {
            $request->attributes->set('paykit.payment', $payment);
        }
        /** @var \Symfony\Component\HttpFoundation\Response $appResponse */
        $appResponse = $next($request);
        if ($payment instanceof Payment) {
            foreach ($payment->settlementHeaders as $k => $v) {
                $appResponse->headers->set($k, $v);
            }
        }
        return $appResponse;
    }
}
