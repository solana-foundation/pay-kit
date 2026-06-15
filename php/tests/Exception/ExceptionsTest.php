<?php

declare(strict_types=1);

namespace PayKit\Tests\Exception;

use PayKit\Exception\InvalidProofException;
use PayKit\Exception\PaymentRequiredException;
use PayKit\Exception\ProtocolNotSupportedException;
use PHPUnit\Framework\TestCase;

final class ExceptionsTest extends TestCase
{
    public function testHttpStatusValues(): void
    {
        $this->assertSame(402, (new PaymentRequiredException('x'))->httpStatus());
        $this->assertSame(402, (new InvalidProofException('x'))->httpStatus());
        $this->assertSame(406, (new ProtocolNotSupportedException('x'))->httpStatus());
    }
}
