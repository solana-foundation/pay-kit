<?php

declare(strict_types=1);

namespace PayKit\Tests\Conformance;

use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Drives the x402 exact structural-verifier vectors through the PHP runner's
 * real stdin/stdout ABI. This protects both the production Verifier route and
 * the x402ExactRejectCode field that the shared harness asserts verbatim.
 */
final class X402ExactVerifierVectorTest extends TestCase
{
    private const RUNNER = __DIR__ . '/../../conformance/runner.php';
    private const VECTORS = __DIR__ . '/../../../harness/vectors/x402-exact-reject.json';

    /**
     * @param array<string, mixed> $vector
     * @return array<string, mixed>
     */
    private function runVector(array $vector): array
    {
        $process = proc_open(
            [PHP_BINARY, self::RUNNER],
            [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']],
            $pipes,
        );
        if (!is_resource($process)) {
            throw new RuntimeException('failed to spawn php conformance runner');
        }
        fwrite($pipes[0], json_encode($vector, JSON_THROW_ON_ERROR));
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        $code = proc_close($process);
        if ($code !== 0) {
            throw new RuntimeException("runner exited $code: $stderr");
        }
        $result = json_decode(trim((string) $stdout), true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($result)) {
            throw new RuntimeException('runner emitted non-object: ' . $stdout);
        }
        return $result;
    }

    public function testExactVerifierVectorsConform(): void
    {
        $raw = file_get_contents(self::VECTORS);
        if ($raw === false) {
            throw new RuntimeException('missing x402 exact verifier vectors');
        }
        $vectors = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($vectors);
        self::assertNotEmpty($vectors, 'expected x402 exact verifier vectors');

        foreach ($vectors as $vector) {
            self::assertIsArray($vector);
            $id = $vector['id'] ?? '?';
            $expect = $vector['expect'] ?? [];
            self::assertSame('verify-x402-transaction', $vector['mode'] ?? null, "mode mismatch for $id");

            $result = $this->runVector($vector);
            self::assertSame(
                $expect['outcome'] ?? null,
                $result['outcome'] ?? null,
                "outcome mismatch for $id: " . json_encode($result),
            );

            if (($expect['outcome'] ?? null) === 'reject') {
                self::assertSame(
                    $expect['x402ExactRejectCode'] ?? null,
                    $result['x402ExactRejectCode'] ?? null,
                    "x402ExactRejectCode mismatch for $id: " . json_encode($result),
                );
            }
        }
    }
}
