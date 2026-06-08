<?php

declare(strict_types=1);

namespace PayKit\Tests\Conformance;

use PHPUnit\Framework\TestCase;
use RuntimeException;

/**
 * Drives the cross-SDK x402 legacy-wire (v1) conformance vectors through the
 * PHP conformance runner (conformance/runner.php) over its real stdin/stdout
 * ABI, the same way the TypeScript harness driver does. PHP is a SERVER-only
 * SDK, so:
 *
 *   - verify-transaction vectors run the envelope verify (version dispatch +
 *     scheme + network gate) and assert accept (with x402EnvelopeShape) or
 *     reject (with rejectCode), matching the vector's expectation.
 *   - build-transaction vectors are client-side and SKIP for PHP
 *     (outcome === "unsupported-mode").
 *
 * This pins the PHP server's legacy-wire support to the shared vectors so the
 * cross-SDK contract fails loudly here if the runner or Adapter dispatch drifts
 * from the rust spine.
 */
final class X402LegacyVectorTest extends TestCase
{
    private const RUNNER = __DIR__ . '/../../conformance/runner.php';
    private const VECTORS = __DIR__ . '/../../../harness/vectors';

    /**
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
        $decoded = json_decode(trim((string) $stdout), true, flags: JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new RuntimeException('runner emitted non-object: ' . $stdout);
        }
        return $decoded;
    }

    /**
     * @return list<array<string, mixed>>
     */
    private function loadVectors(string $file): array
    {
        $raw = file_get_contents(self::VECTORS . '/' . $file);
        if ($raw === false) {
            throw new RuntimeException("missing vector file: $file");
        }
        $decoded = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
        self::assertIsArray($decoded);
        return $decoded;
    }

    public function testLegacyVerifyVectorsConform(): void
    {
        $vectors = $this->loadVectors('x402-v1-verify.json');
        self::assertNotEmpty($vectors, 'expected x402 v1 verify vectors');

        foreach ($vectors as $vector) {
            $expect = $vector['expect'] ?? [];
            $result = $this->runVector($vector);
            $id = $vector['id'] ?? '?';

            self::assertSame(
                $expect['outcome'] ?? null,
                $result['outcome'] ?? null,
                "outcome mismatch for $id: " . json_encode($result),
            );

            if (($expect['outcome'] ?? null) === 'accept') {
                self::assertArrayHasKey('x402EnvelopeShape', $result, "missing shape for $id");
                foreach (($expect['x402EnvelopeShape'] ?? []) as $key => $value) {
                    self::assertSame(
                        $value,
                        $result['x402EnvelopeShape'][$key] ?? null,
                        "shape.$key mismatch for $id",
                    );
                }
            }

            if (($expect['outcome'] ?? null) === 'reject') {
                self::assertSame(
                    $expect['rejectCode'] ?? null,
                    $result['rejectCode'] ?? null,
                    "rejectCode mismatch for $id: " . json_encode($result),
                );
            }
        }
    }

    public function testLegacyBuildVectorsAreSkippedForServerOnlySdk(): void
    {
        // PHP ships no client-side x402 envelope builder; the harness driver
        // SKIPs build vectors for PHP (outcome === "unsupported-mode").
        $vectors = $this->loadVectors('x402-v1-build.json');
        self::assertNotEmpty($vectors, 'expected x402 v1 build vectors');

        foreach ($vectors as $vector) {
            $result = $this->runVector($vector);
            self::assertSame(
                'unsupported-mode',
                $result['outcome'] ?? null,
                'build vector ' . ($vector['id'] ?? '?') . ' should be unsupported for server-only PHP',
            );
        }
    }
}
