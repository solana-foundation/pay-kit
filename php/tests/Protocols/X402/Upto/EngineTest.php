<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402\Upto;

use Nyholm\Psr7\Factory\Psr17Factory;
use PayKit\Config;
use PayKit\Gate;
use PayKit\Operator;
use PayKit\PayCore\Network;
use PayKit\Price;
use PayKit\Protocols\X402\Upto\Engine;
use PayKit\Protocols\X402\Upto\Types;
use PayKit\Signer;
use PHPUnit\Framework\TestCase;

/**
 * Challenge-shape coverage for the upto engine (no RPC / no on-chain).
 */
final class EngineTest extends TestCase
{
    public function testAcceptsEntryIsUptoSchemeWithOperatorSeats(): void
    {
        $engine = $this->engine();
        $gate = new Gate(amount: Price::usd('0.10'));
        $request = (new Psr17Factory())->createServerRequest('GET', '/usage');

        $entry = $engine->acceptsEntry($gate, $request);

        self::assertSame(Types::SCHEME, $entry['scheme']);
        self::assertSame('x402', $entry['protocol']);
        self::assertSame('100000', $entry['amount']);
        self::assertArrayHasKey('extra', $entry);
        $extra = $entry['extra'];
        self::assertIsArray($extra);
        self::assertSame($extra['feePayer'], $extra['receiverAuthorizer']);
        self::assertNotSame('', $extra['feePayer']);
        self::assertSame(Types::DEFAULT_WITHDRAW_DELAY_SECONDS, $extra['withdrawDelay']);
        self::assertSame('hint-blockhash', $extra['recentBlockhash']);
        self::assertSame('4242', $extra['recentSlot']);
    }

    public function testChallengeHeadersEmitPaymentRequiredBase64(): void
    {
        $engine = $this->engine();
        $gate = new Gate(amount: Price::usd('0.10'));
        $request = (new Psr17Factory())->createServerRequest('GET', '/usage');

        $headers = $engine->challengeHeaders($gate, $request);
        self::assertArrayHasKey('payment-required', $headers);
        $raw = base64_decode($headers['payment-required'], true);
        self::assertNotFalse($raw);
        $body = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        self::assertSame(Types::X402_VERSION, $body['x402Version']);
        self::assertSame(Types::SCHEME, $body['accepts'][0]['scheme']);
        self::assertSame('/usage', $body['resource']['url']);
    }

    private function engine(): Engine
    {
        $signer = Signer::generate();
        $config = new Config(
            network: Network::SolanaDevnet,
            operator: new Operator(
                recipient: $signer->pubkey(),
                signer: $signer,
                feePayer: true,
            ),
            preflight: false,
        );

        return new Engine(
            $config,
            chainHintsProvider: static fn (): array => [
                'blockhash' => 'hint-blockhash',
                'slot'      => '4242',
            ],
        );
    }
}
