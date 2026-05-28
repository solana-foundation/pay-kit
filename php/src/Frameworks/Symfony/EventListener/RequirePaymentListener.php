<?php

declare(strict_types=1);

namespace PayKit\Frameworks\Symfony\EventListener;

use PayKit\Client;
use PayKit\Middleware\RequirePayment as PsrRequirePayment;
use PayKit\Pricing;
use PayKit\Frameworks\Symfony\Attribute\RequirePayment;
use ReflectionMethod;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\HttpKernel\Event\ControllerArgumentsEvent;

/**
 * Reads `#[RequirePayment('gate')]` off the resolved controller and
 * gates the request through the PSR-15 RequirePayment middleware.
 * Bridges Symfony Request <-> PSR-7 so the underlying middleware
 * matches the Laravel + Slim + Mezzio + raw-PSR-15 codepath exactly.
 */
final class RequirePaymentListener
{
    public function __construct(
        private readonly Client $client,
        private readonly ?Pricing $pricing,
        private readonly PsrHttpFactory $psrFactory,
        private readonly HttpFoundationFactory $httpFactory,
    ) {
    }

    public function onKernelControllerArguments(ControllerArgumentsEvent $event): void
    {
        $controller = $event->getController();
        $attribute = $this->extractAttribute($controller);
        if ($attribute === null) {
            return;
        }
        $psrRequest = $this->psrFactory->createRequest($event->getRequest());
        $middleware = new PsrRequirePayment($this->client, $attribute->gate, $this->pricing);
        $psrResponse = $middleware->process(
            $psrRequest,
            new class () implements \Psr\Http\Server\RequestHandlerInterface {
                public function handle(\Psr\Http\Message\ServerRequestInterface $req): \Psr\Http\Message\ResponseInterface
                {
                    $factory = new \Nyholm\Psr7\Factory\Psr17Factory();
                    return $factory->createResponse(200);
                }
            },
        );
        if ($psrResponse->getStatusCode() === 402) {
            $event->getRequest()->attributes->set('_controller', function () use ($psrResponse) {
                return $this->httpFactory->createResponse($psrResponse);
            });
            $event->setController(function () use ($psrResponse) {
                return $this->httpFactory->createResponse($psrResponse);
            });
        }
    }

    private function extractAttribute(mixed $controller): ?RequirePayment
    {
        if (!is_array($controller) || count($controller) !== 2) {
            return null;
        }
        [$class, $method] = $controller;
        if (!is_object($class) || !is_string($method)) {
            return null;
        }
        $refl = new ReflectionMethod($class, $method);
        $attrs = $refl->getAttributes(RequirePayment::class);
        if ($attrs === []) {
            return null;
        }
        return $attrs[0]->newInstance();
    }
}
