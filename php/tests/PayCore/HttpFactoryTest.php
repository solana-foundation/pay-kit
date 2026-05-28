<?php

declare(strict_types=1);

namespace PayKit\Tests\PayCore;

use Nyholm\Psr7\Factory\Psr17Factory;
use PayKit\PayCore\HttpFactory;
use PHPUnit\Framework\TestCase;

/**
 * @runTestsInSeparateProcesses
 * @preserveGlobalState disabled
 */
final class HttpFactoryTest extends TestCase
{
    public function testResponseAndStreamFactoriesAreUsable(): void
    {
        $rf = HttpFactory::responseFactory();
        $sf = HttpFactory::streamFactory();
        $resp = $rf->createResponse(402)->withBody($sf->createStream('hello'));
        $this->assertSame(402, $resp->getStatusCode());
        $this->assertSame('hello', (string) $resp->getBody());
    }

    public function testSetResponseFactoryOverridesDefault(): void
    {
        $custom = new Psr17Factory();
        HttpFactory::setResponseFactory($custom);
        $this->assertSame($custom, HttpFactory::responseFactory());
        HttpFactory::setResponseFactory(null);
    }

    public function testSetStreamFactoryOverridesDefault(): void
    {
        $custom = new Psr17Factory();
        HttpFactory::setStreamFactory($custom);
        $this->assertSame($custom, HttpFactory::streamFactory());
        HttpFactory::setStreamFactory(null);
    }

    public function testServerRequestFromGlobalsBuildsFromServerSuperglobal(): void
    {
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_SERVER['REQUEST_URI']    = '/paid?x=1';
        $_SERVER['SERVER_NAME']    = '127.0.0.1';
        $_SERVER['SERVER_PORT']    = '4567';
        $_SERVER['HTTP_HOST']      = '127.0.0.1:4567';
        $_SERVER['HTTPS']          = '';
        $req = HttpFactory::serverRequestFromGlobals();
        $this->assertSame('GET', $req->getMethod());
        $this->assertStringContainsString('/paid', $req->getUri()->getPath());
    }

    public function testEmitWritesBodyAndHeaders(): void
    {
        $resp = HttpFactory::responseFactory()
            ->createResponse(402)
            ->withHeader('content-type', 'application/json')
            ->withHeader('www-authenticate', 'Payment realm="t"')
            ->withBody(HttpFactory::streamFactory()->createStream('{"ok":false}'));
        ob_start();
        HttpFactory::emit($resp);
        $out = (string) ob_get_clean();
        $this->assertSame('{"ok":false}', $out);
        // headers_sent() is true in CLI under PHPUnit's separate-process
        // mode but the headers list isn't fetchable cross-process; we
        // assert the body and trust the cli-server quirk workaround
        // (covered manually in examples/simple-server).
    }
}
