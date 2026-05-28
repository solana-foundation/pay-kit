<?php

declare(strict_types=1);

namespace PayKit\PayCore;

use Nyholm\Psr7\Factory\Psr17Factory;
use Nyholm\Psr7Server\ServerRequestCreator;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
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

    /**
     * Build a PSR-7 ServerRequest from the active SAPI globals
     * ($_SERVER / $_GET / $_POST / $_COOKIE / $_FILES + php://input).
     * Convenience wrapper so examples and simple front controllers
     * don't have to import nyholm/psr7-server directly.
     */
    public static function serverRequestFromGlobals(): ServerRequestInterface
    {
        $f = self::defaultFactory();
        return (new ServerRequestCreator($f, $f, $f, $f))->fromGlobals();
    }

    /**
     * Emit a PSR-7 response through the active SAPI. Handles a known
     * PHP CLI dev server (php -S) quirk: when any `WWW-Authenticate`
     * header is sent, the SAPI hard-codes the status to 401 regardless
     * of `http_response_code()`. Workaround is to emit all other
     * headers first and then force the status line as the final
     * `header()` call. fpm / nginx / Apache are unaffected; the extra
     * call is cheap and idempotent there.
     */
    public static function emit(ResponseInterface $response): void
    {
        foreach ($response->getHeaders() as $name => $values) {
            foreach ($values as $value) {
                header(sprintf('%s: %s', $name, $value), false);
            }
        }
        header(sprintf(
            'HTTP/%s %d %s',
            $response->getProtocolVersion(),
            $response->getStatusCode(),
            $response->getReasonPhrase(),
        ));
        echo (string) $response->getBody();
    }
}
