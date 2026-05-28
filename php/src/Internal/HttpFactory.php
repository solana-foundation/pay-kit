<?php

declare(strict_types=1);

namespace PayKit\Internal;

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * Internal helper: resolves the PSR-17 (PHP-FIG HTTP factory interfaces)
 * ResponseFactoryInterface + StreamFactoryInterface the
 * {@see \PayKit\Middleware\RequirePayment} middleware uses to build
 * its 402 responses, without forcing the caller to pass them.
 *
 * Defaults to nyholm/psr7. Apps that ship a different PSR-17 factory
 * (Slim, Guzzle, Laminas-diactoros, ...) can set their own via
 * {@see setResponseFactory()} / {@see setStreamFactory()}.
 *
 * @internal
 */
final class HttpFactory
{
    private static ?Psr17Factory $default = null;
    private static ?ResponseFactoryInterface $responseFactory = null;
    private static ?StreamFactoryInterface $streamFactory = null;

    /** @codeCoverageIgnore */
    private function __construct()
    {
    }

    public static function responseFactory(): ResponseFactoryInterface
    {
        return self::$responseFactory ??= self::defaultFactory();
    }

    public static function streamFactory(): StreamFactoryInterface
    {
        return self::$streamFactory ??= self::defaultFactory();
    }

    public static function setResponseFactory(?ResponseFactoryInterface $f): void
    {
        self::$responseFactory = $f;
    }

    public static function setStreamFactory(?StreamFactoryInterface $f): void
    {
        self::$streamFactory = $f;
    }

    private static function defaultFactory(): Psr17Factory
    {
        return self::$default ??= new Psr17Factory();
    }
}
