<?php

declare(strict_types=1);

namespace PayKit\Internal;

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * Internal helper: resolve a PSR-17 factory the middleware can use to
 * build 402 responses without taking a constructor argument.
 *
 * Defaults to nyholm/psr7. Apps that ship a different PSR-17 factory
 * can set their own via {@see setFactory()}.
 *
 * @internal
 */
final class Psr17
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
