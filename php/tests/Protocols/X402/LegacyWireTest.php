<?php

declare(strict_types=1);

namespace PayKit\Tests\Protocols\X402;

use Nyholm\Psr7\Factory\Psr17Factory;
use PayKit\Config;
use PayKit\Exception\InvalidProofException;
use PayKit\Gate;
use PayKit\Operator;
use PayKit\PayCore\Network;
use PayKit\Price;
use PayKit\Protocols\X402\Adapter;
use PayKit\Signer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;
use ReflectionMethod;

/**
 * Coverage for the x402 legacy-wire (coinbase/x402 v1) dual-accept path on
 * the PHP server adapter. The legacy credential rides the X-PAYMENT header
 * with a top-level scheme + plain network slug (siblings of payload) and NO
 * `accepted` object; the server normalizes the slug to a CAIP-2 chain id and
 * gates it against the route, then runs the IDENTICAL transaction MUST-checks
 * the canonical path runs. Mirrors the rust spine v1 arm
 * (server/exact.rs parse_payment_signature + find_matching_requirement).
 *
 * Assembling a fully-valid signed Solana wire transaction at PHPUnit level is
 * impractical (the structural verifier + cosign + broadcast run after the
 * envelope dispatch), so the credential-validation primitives are exercised
 * directly via reflection, and the dispatch/reject paths through
 * verifyAndSettle which throw before any broadcast.
 */
final class LegacyWireTest extends TestCase
{
    private function makeAdapter(Network $network = Network::SolanaDevnet): Adapter
    {
        $config = new Config(
            network: $network,
            operator: new Operator(
                recipient: Signer::generate()->pubkey(),
                signer:    Signer::generate(),
                feePayer:  true,
            ),
            preflight: false,
        );
        return new Adapter($config, recentBlockhashProvider: fn () => null);
    }

    private function makeGate(): Gate
    {
        return new Gate(amount: Price::usd('0.10'));
    }

    private function request(): ServerRequestInterface
    {
        return (new Psr17Factory())->createServerRequest('GET', '/paid');
    }

    /**
     * Build a base64(JSON) legacy x402 credential header. Standard (padded)
     * base64, matching the rust producer's STANDARD engine.
     *
     * @param array<string, mixed> $envelope
     */
    private function legacyHeader(array $envelope): string
    {
        return base64_encode(json_encode($envelope, JSON_THROW_ON_ERROR));
    }

    private function invoke(Adapter $adapter, string $method, mixed ...$args): mixed
    {
        $ref = new ReflectionMethod(Adapter::class, $method);
        $ref->setAccessible(true);
        return $ref->invoke($adapter, ...$args);
    }

    // ── caip2ForCluster: legacy plain-slug -> CAIP-2 normalization ──────────

    public function testCaip2ForClusterMapsPlainSlugs(): void
    {
        $adapter = $this->makeAdapter();
        $mainnet = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
        $devnet  = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
        $testnet = 'solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z';

        self::assertSame($mainnet, $this->invoke($adapter, 'caip2ForCluster', 'solana'));
        self::assertSame($mainnet, $this->invoke($adapter, 'caip2ForCluster', 'mainnet-beta'));
        self::assertSame($devnet, $this->invoke($adapter, 'caip2ForCluster', 'solana-devnet'));
        self::assertSame($devnet, $this->invoke($adapter, 'caip2ForCluster', 'devnet'));
        self::assertSame($devnet, $this->invoke($adapter, 'caip2ForCluster', 'localnet'));
        self::assertSame($testnet, $this->invoke($adapter, 'caip2ForCluster', 'solana-testnet'));
        self::assertSame($testnet, $this->invoke($adapter, 'caip2ForCluster', 'testnet'));
        // CAIP-2 ids pass through unchanged.
        self::assertSame($mainnet, $this->invoke($adapter, 'caip2ForCluster', $mainnet));
        self::assertSame($devnet, $this->invoke($adapter, 'caip2ForCluster', $devnet));
        // Unknown slugs default to mainnet, mirroring the rust spine.
        self::assertSame($mainnet, $this->invoke($adapter, 'caip2ForCluster', 'whatever'));
    }

    // ── matchLegacyCredential: scheme + network gate ───────────────────────

    public function testMatchLegacyCredentialAcceptsDevnetSlug(): void
    {
        $adapter = $this->makeAdapter(Network::SolanaDevnet);
        $this->invoke($adapter, 'matchLegacyCredential', [
            'x402Version' => 1,
            'scheme'      => 'exact',
            'network'     => 'solana-devnet',
            'payload'     => ['transaction' => 'AA=='],
        ]);
        // No exception means the scheme + network gate passed.
        $this->addToAssertionCount(1);
    }

    public function testMatchLegacyCredentialAcceptsPlainSolanaOnMainnet(): void
    {
        $adapter = $this->makeAdapter(Network::SolanaMainnet);
        $this->invoke($adapter, 'matchLegacyCredential', [
            'x402Version' => 1,
            'scheme'      => 'exact',
            'network'     => 'solana',
            'payload'     => ['transaction' => 'AA=='],
        ]);
        $this->addToAssertionCount(1);
    }

    public function testMatchLegacyCredentialRejectsWrongScheme(): void
    {
        $adapter = $this->makeAdapter(Network::SolanaDevnet);
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/unsupported scheme/');
        $this->invoke($adapter, 'matchLegacyCredential', [
            'x402Version' => 1,
            'scheme'      => 'upto',
            'network'     => 'solana-devnet',
        ]);
    }

    public function testMatchLegacyCredentialRejectsMissingNetwork(): void
    {
        $adapter = $this->makeAdapter(Network::SolanaDevnet);
        $this->expectException(InvalidProofException::class);
        $this->invoke($adapter, 'matchLegacyCredential', [
            'x402Version' => 1,
            'scheme'      => 'exact',
        ]);
    }

    public function testMatchLegacyCredentialRejectsWrongNetwork(): void
    {
        // Plain "solana" normalizes to mainnet; the route is devnet.
        $adapter = $this->makeAdapter(Network::SolanaDevnet);
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/Network mismatch/');
        $this->invoke($adapter, 'matchLegacyCredential', [
            'x402Version' => 1,
            'scheme'      => 'exact',
            'network'     => 'solana',
        ]);
    }

    // ── settlementNetwork: per-wire network echo ───────────────────────────

    public function testSettlementNetworkEchoesLegacyPlainSlug(): void
    {
        $adapter = $this->makeAdapter(Network::SolanaDevnet);
        $network = $this->invoke($adapter, 'settlementNetwork', [
            'x402Version' => 1,
            'network'     => 'solana-devnet',
            'payload'     => ['transaction' => 'AA=='],
        ]);
        self::assertSame('solana-devnet', $network);
    }

    public function testSettlementNetworkEchoesCanonicalAcceptedNetwork(): void
    {
        $adapter = $this->makeAdapter(Network::SolanaDevnet);
        $caip2 = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
        $network = $this->invoke($adapter, 'settlementNetwork', [
            'x402Version' => 2,
            'accepted'    => ['network' => $caip2],
            'payload'     => ['transaction' => 'AA=='],
        ]);
        self::assertSame($caip2, $network);
    }

    public function testSettlementNetworkFallsBackToRouteCaip2(): void
    {
        $adapter = $this->makeAdapter(Network::SolanaDevnet);
        $network = $this->invoke($adapter, 'settlementNetwork', [
            'x402Version' => 2,
            'payload'     => ['transaction' => 'AA=='],
        ]);
        self::assertSame('solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1', $network);
    }

    // ── decodeCredential: base64(JSON) decode guards ───────────────────────

    public function testDecodeCredentialRejectsBadBase64(): void
    {
        $adapter = $this->makeAdapter();
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/base64/');
        $this->invoke($adapter, 'decodeCredential', '@@@not-base64@@@');
    }

    public function testDecodeCredentialRejectsNonJson(): void
    {
        $adapter = $this->makeAdapter();
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/json/');
        $this->invoke($adapter, 'decodeCredential', base64_encode('not json at all'));
    }

    public function testDecodeCredentialAcceptsObjectAndScalarValues(): void
    {
        // A JSON object decodes to a PHP array (the only credential shape we
        // accept). A JSON array also decodes to a PHP array but carries no
        // x402Version, so it is rejected downstream by the version gate, not
        // here — decodeCredential only guards that the payload decodes at all.
        $adapter = $this->makeAdapter();
        $decoded = $this->invoke(
            $adapter,
            'decodeCredential',
            base64_encode(json_encode(['x402Version' => 1]) ?: '{}'),
        );
        self::assertSame(['x402Version' => 1], $decoded);
    }

    public function testVerifyAndSettleRejectsBareJsonArrayCredential(): void
    {
        // A JSON array decodes but has no x402Version; the version gate rejects
        // it as an unsupported version rather than letting it through.
        $adapter = $this->makeAdapter();
        $header = base64_encode(json_encode([1, 2, 3]) ?: '[]');
        $req = $this->request()->withHeader('X-PAYMENT', $header);
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/unsupported_x402_version/');
        $adapter->verifyAndSettle($this->makeGate(), $req);
    }

    // ── verifyAndSettle: dual-accept read + version dispatch ───────────────

    public function testVerifyAndSettleReadsLegacyXPaymentHeader(): void
    {
        // A well-formed legacy credential on X-PAYMENT must NOT be rejected at
        // the dispatch/gate; it advances past version + scheme + network and
        // fails only on the missing transaction proof (the "AA==" tx here is
        // empty-ish but present, so it reaches the structural verifier path).
        // We assert it does NOT trip "payment required" or "unsupported
        // version" — i.e. the X-PAYMENT fallback fired and v1 was accepted by
        // the gate.
        $adapter = $this->makeAdapter(Network::SolanaDevnet);
        $header = $this->legacyHeader([
            'x402Version' => 1,
            'scheme'      => 'exact',
            'network'     => 'solana-devnet',
            'payload'     => [], // no transaction -> trips missing-transaction
        ]);
        $req = $this->request()->withHeader('X-PAYMENT', $header);
        try {
            $adapter->verifyAndSettle($this->makeGate(), $req);
            self::fail('expected an InvalidProofException');
        } catch (InvalidProofException $e) {
            self::assertStringContainsString('missing_transaction', $e->getMessage());
        }
    }

    public function testVerifyAndSettleRejectsLegacyWrongNetwork(): void
    {
        $adapter = $this->makeAdapter(Network::SolanaDevnet);
        $header = $this->legacyHeader([
            'x402Version' => 1,
            'scheme'      => 'exact',
            'network'     => 'solana', // mainnet slug on a devnet route
            'payload'     => ['transaction' => 'AA=='],
        ]);
        $req = $this->request()->withHeader('X-PAYMENT', $header);
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/Network mismatch/');
        $adapter->verifyAndSettle($this->makeGate(), $req);
    }

    public function testVerifyAndSettleStillRejectsUnknownVersionOnLegacyHeader(): void
    {
        // Adding legacy support must NOT widen the version gate: a credential
        // shaped like v1 (top-level scheme/network) but carrying an unknown
        // version is still rejected.
        $adapter = $this->makeAdapter(Network::SolanaDevnet);
        $header = $this->legacyHeader([
            'x402Version' => 9,
            'scheme'      => 'exact',
            'network'     => 'solana-devnet',
            'payload'     => ['transaction' => 'AA=='],
        ]);
        $req = $this->request()->withHeader('X-PAYMENT', $header);
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/unsupported_x402_version/');
        $adapter->verifyAndSettle($this->makeGate(), $req);
    }

    public function testVerifyAndSettleCanonicalHeaderTakesPrecedenceOverLegacy(): void
    {
        // When both headers are present the canonical PAYMENT-SIGNATURE wins.
        // We send a canonical credential with a mismatched accepted (so it
        // trips the canonical identity-key check) AND a legacy credential that
        // would otherwise pass; the canonical-path error proves precedence.
        $adapter = $this->makeAdapter(Network::SolanaDevnet);
        $canonical = $this->legacyHeader([
            'x402Version' => 2,
            'accepted'    => ['scheme' => 'exact', 'network' => 'solana:WRONG', 'asset' => 'X', 'payTo' => 'Y'],
            'payload'     => ['transaction' => 'AA=='],
        ]);
        $legacy = $this->legacyHeader([
            'x402Version' => 1,
            'scheme'      => 'exact',
            'network'     => 'solana-devnet',
            'payload'     => ['transaction' => 'AA=='],
        ]);
        $req = $this->request()
            ->withHeader('Payment-Signature', $canonical)
            ->withHeader('X-PAYMENT', $legacy);
        $this->expectException(InvalidProofException::class);
        $this->expectExceptionMessageMatches('/charge_request_mismatch/');
        $adapter->verifyAndSettle($this->makeGate(), $req);
    }
}
