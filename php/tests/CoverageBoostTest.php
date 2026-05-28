<?php

declare(strict_types=1);

namespace PayKit\Tests;

use PayKit\Exception\InvalidKeyException;
use PayKit\Exception\PaymentRequiredException;
use PayKit\Gate;
use PayKit\Config;
use PayKit\Exception\ConfigurationException;
use PayKit\Protocols\Mpp\SecretResolver;
use PayKit\PayCore\Network;
use PayKit\Operator;
use PayKit\Protocols\Mpp\MppConfig;
use SolanaPhpSdk\Util\Base58;
use PayKit\Protocols\Mpp\Core\Rfc3339Parser;
use PayKit\PayCore\Solana\Mints;
use PayKit\Payment;
use PayKit\Price;
use PayKit\Protocol;
use PayKit\Signer;
use Nyholm\Psr7\ServerRequest;
use PHPUnit\Framework\TestCase;

use function PayKit\Middleware\isPaidFor;
use function PayKit\Middleware\requirePayment;

final class CoverageBoostTest extends TestCase
{
    public function testJsonRejectsNonArrayPayload(): void
    {
        $this->expectException(InvalidKeyException::class);
        Signer::json('42');
    }

    public function testEnvWhitespaceOnlyReturnsNull(): void
    {
        putenv('PAY_KIT_TEST_BLANK=   ');
        try {
            $this->assertNull(Signer::env('PAY_KIT_TEST_BLANK'));
        } finally {
            putenv('PAY_KIT_TEST_BLANK');
        }
    }

    public function testIsPaidForReturnsFalseWithoutPayment(): void
    {
        $req = new ServerRequest('GET', '/x');
        $this->assertFalse(isPaidFor($req, 'paid'));
    }

    public function testIsPaidForReturnsTrueForGateObjectMatch(): void
    {
        $gate = new Gate(Price::usd('0.01'), 'PAY_TO_RECIPIENT_BASE58_PUBKEY_111111111111');
        $payment = new Payment(
            protocol: Protocol::Mpp,
            transaction: 'sig',
            gateName: 'paid',
        );
        $req = (new ServerRequest('GET', '/x'))->withAttribute('paykit.payment', $payment);
        $this->assertTrue(isPaidFor($req, $gate));
    }

    public function testRequirePaymentThrowsWithoutAttribute(): void
    {
        $this->expectException(PaymentRequiredException::class);
        requirePayment(new ServerRequest('GET', '/x'));
    }

    public function testSecretResolverDotenvSkipsCommentsAndStripsQuotes(): void
    {
        $tmp = sys_get_temp_dir() . '/paykit-secret-resolver-' . bin2hex(random_bytes(4)) . '.env';
        file_put_contents($tmp, "# leading comment\n   \nPAY_KIT_MPP_CHALLENGE_BINDING_SECRET=\"quoted-value\"\n");
        $cwd = getcwd() ?: '.';
        $prev = $cwd;
        $dir  = dirname($tmp);
        chdir($dir);
        try {
            rename($tmp, $dir . '/.env');
            putenv('PAY_KIT_MPP_CHALLENGE_BINDING_SECRET');
            $resolved = SecretResolver::resolveMppSecret();
            $this->assertSame('quoted-value', $resolved['secret']);
            $this->assertSame('dotenv', $resolved['source']);
            $this->assertTrue($resolved['persisted']);
        } finally {
            @unlink($dir . '/.env');
            chdir($prev);
        }
    }

    public function testMintsSymbolForUnknownReturnsNull(): void
    {
        $this->assertNull(Mints::symbolFor('NOT_A_REAL_MINT_OR_SYMBOL', 'mainnet'));
    }

    public function testMintsSymbolForReverseLookupByMint(): void
    {
        // Pass an actual USDC mainnet mint, expect 'USDC' back.
        $mint = Mints::resolve('USDC', 'mainnet');
        $this->assertNotNull($mint);
        $this->assertSame('USDC', Mints::symbolFor($mint, 'mainnet'));
    }

    public function testRfc3339ParserRejectsMalformed(): void
    {
        $this->assertNull(Rfc3339Parser::parse('not-a-timestamp'));
    }

    public function testBase58SecretKeyRoundTrip(): void
    {
        $sgn = Signer::generate();
        $b58 = Base58::encode($sgn->secretKey());
        $rebuilt = Signer::base58($b58);
        $this->assertSame($sgn->pubkey(), $rebuilt->pubkey());
        $this->assertSame($sgn->secretKey(), $rebuilt->secretKey());
    }

    public function testExceptionHttpStatusValues(): void
    {
        $this->assertSame(402, (new \PayKit\Exception\PaymentRequiredException('x'))->httpStatus());
        $this->assertSame(402, (new \PayKit\Exception\InvalidProofException('x'))->httpStatus());
        $this->assertSame(406, (new \PayKit\Exception\ProtocolNotSupportedException('x'))->httpStatus());
    }

    public function testDemoResetForTestsClearsSingleton(): void
    {
        $a = Signer::demo();
        \PayKit\Signer\Demo::resetForTests();
        $b = Signer::demo();
        $this->assertSame($a->pubkey(), $b->pubkey());
    }

    public function testConfigRejectsEmptyStablecoins(): void
    {
        $this->expectException(ConfigurationException::class);
        new Config(
            network: Network::SolanaDevnet,
            stablecoins: [],
            operator: new Operator(recipient: Signer::generate()->pubkey()),
            preflight: false,
            mpp: new MppConfig(challengeBindingSecret: 'x'),
        );
    }

    public function testRfc3339ParserAcceptsZuluTimestamp(): void
    {
        $dt = Rfc3339Parser::parse('2024-12-31T23:59:59Z');
        $this->assertNotNull($dt);
        $this->assertSame('2024-12-31T23:59:59+00:00', $dt->format('c'));
    }

    public function testSecretResolverAppendsToExistingDotenv(): void
    {
        $dir = sys_get_temp_dir() . '/paykit-secret-existing-' . bin2hex(random_bytes(4));
        mkdir($dir, 0700, true);
        $prev = getcwd() ?: '.';
        chdir($dir);
        try {
            file_put_contents($dir . '/.env', "OTHER_KEY=other\n");
            putenv('PAY_KIT_MPP_CHALLENGE_BINDING_SECRET');
            $resolved = SecretResolver::resolveMppSecret();
            $this->assertSame('generated+persisted', $resolved['source']);
            $this->assertTrue($resolved['persisted']);
            $contents = (string) file_get_contents($dir . '/.env');
            $this->assertStringContainsString('OTHER_KEY=other', $contents);
            $this->assertStringContainsString('PAY_KIT_MPP_CHALLENGE_BINDING_SECRET=', $contents);
        } finally {
            @unlink($dir . '/.env');
            @rmdir($dir);
            chdir($prev);
        }
    }
}
