<?php

declare(strict_types=1);

namespace PayKit\Tests\Conformance;

use PHPUnit\Framework\TestCase;

/**
 * Drives the canonical mpp-protocol vectors (vendored from tempoxyz/mpp-tools
 * under harness/vectors/mpp-protocol/) through the PHP protocol-conformance
 * runner (conformance/protocol-runner.php) over its real stdin/stdout adapter
 * ABI, mirroring the harness driver's comparison discipline:
 *
 *   - base64url.encode/decode + challenge.id  -> EXACT result compare
 *   - *.parse                                 -> object compare (credential
 *                                                request-decode normalized)
 *   - *.format                                -> SEMANTIC: re-parse the golden
 *                                                wire and the produced wire and
 *                                                compare the parsed objects
 *
 * Every supported op is asserted to conform on the happy-path scenarios. The
 * handful of scenarios where the PHP SDK genuinely diverges from the canonical
 * oracle are pinned in KNOWN_DIVERGENCES and asserted to STILL diverge, so the
 * gap fails loudly the moment the SDK conforms (and the entry can be removed),
 * exactly like the harness's KNOWN_TS_DIVERGENCES guard.
 */
final class ProtocolRunnerTest extends TestCase
{
    private const RUNNER = __DIR__ . '/../../conformance/protocol-runner.php';
    private const VECTORS = __DIR__ . '/../../../harness/vectors/mpp-protocol';

    /**
     * `${op} :: ${scenario}` keys where the PHP SDK does not match the
     * canonical oracle. The PHP protocol header-codec / base64url /
     * challenge-id layer now conforms to every canonical mpp-tools vector, so
     * this list is empty; any future regression fails loudly here.
     */
    private const KNOWN_DIVERGENCES = [];

    public function testUnknownOperationIsUnsupported(): void
    {
        $response = $this->runOp('session.parse', []);
        self::assertFalse($response['success']);
        self::assertSame('unsupported_operation', $response['error_type']);
    }

    public function testEveryCanonicalCaseConformsOrIsTrackedDivergence(): void
    {
        $cases = $this->collectCases();
        self::assertGreaterThan(80, count($cases), 'expected the full canonical vector set');

        $diverged = [];
        foreach ($cases as $case) {
            $key = $case['op'] . ' :: ' . $case['scenario'];
            [$ok, $detail] = $this->evaluate($case);
            if (in_array($key, self::KNOWN_DIVERGENCES, true)) {
                self::assertFalse(
                    $ok,
                    sprintf('%s now conforms — remove it from KNOWN_DIVERGENCES', $key),
                );
                continue;
            }
            if (!$ok) {
                $diverged[] = $key . ' -> ' . $detail;
            }
        }

        self::assertSame([], $diverged, "unexpected divergences:\n" . implode("\n", $diverged));
    }

    /**
     * @param array<string, mixed> $case
     * @return array{0: bool, 1: string}
     */
    private function evaluate(array $case): array
    {
        $response = $this->runOp($case['op'], $case['input']);

        if ($case['expectSuccess'] === false) {
            if (($response['success'] ?? null) !== false) {
                return [false, 'expected error, got ' . json_encode($response)];
            }
            $ok = ($response['error_type'] ?? '') === $case['errorType'];
            return [$ok, $ok ? '' : "want error_type={$case['errorType']} got=" . json_encode($response)];
        }

        if (($response['success'] ?? null) !== true) {
            return [false, 'expected success, got ' . json_encode($response)];
        }

        if (isset($case['reparseWith'])) {
            $goldenParsed = $this->runOp($case['reparseWith'], ['header' => $case['golden']['header']]);
            $gotParsed = $this->runOp($case['reparseWith'], ['header' => $response['result']['header']]);
            if (($goldenParsed['success'] ?? null) !== true) {
                return [false, 're-parsing golden wire failed: ' . json_encode($goldenParsed)];
            }
            if (($gotParsed['success'] ?? null) !== true) {
                return [false, 're-parsing produced wire failed: ' . json_encode($gotParsed)];
            }
            $a = $this->normalize($case['reparseWith'], $goldenParsed['result']);
            $b = $this->normalize($case['reparseWith'], $gotParsed['result']);
            $ok = $this->canon($a) === $this->canon($b);
            return [$ok, $ok ? '' : 'produced wire=' . $response['result']['header']];
        }

        $golden = $this->normalize($case['op'], $case['golden']);
        $got = $this->normalize($case['op'], $response['result']);
        $ok = $this->canon($golden) === $this->canon($got);
        return [$ok, $ok ? '' : 'want=' . $this->canon($golden) . ' got=' . $this->canon($got)];
    }

    /**
     * Decode the embedded base64url `challenge.request` string back into an
     * object for credential.parse comparison (mirrors the driver's
     * normalizeCredential).
     */
    private function normalize(string $op, mixed $result): mixed
    {
        if ($op !== 'credential.parse' || !is_array($result) || !isset($result['challenge']) || !is_array($result['challenge'])) {
            return $result;
        }
        $challenge = $result['challenge'];
        if (isset($challenge['request']) && is_string($challenge['request'])) {
            $pad = strlen($challenge['request']) % 4;
            $padded = $challenge['request'] . str_repeat('=', $pad === 0 ? 0 : 4 - $pad);
            $decoded = base64_decode(strtr($padded, '-_', '+/'), true);
            if ($decoded !== false) {
                $parsed = json_decode($decoded, true);
                if (is_array($parsed)) {
                    $challenge['request'] = $parsed;
                }
            }
        }
        $result['challenge'] = $challenge;
        return $result;
    }

    private function canon(mixed $value): string
    {
        if (is_array($value)) {
            $isList = array_keys($value) === range(0, count($value) - 1);
            if (!$isList) {
                ksort($value);
            }
            $parts = [];
            foreach ($value as $k => $v) {
                $parts[] = ($isList ? '' : json_encode((string) $k) . ':') . $this->canon($v);
            }
            return ($isList ? '[' : '{') . implode(',', $parts) . ($isList ? ']' : '}');
        }
        return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * @param mixed $input
     * @return array<string, mixed>
     */
    private function runOp(string $op, mixed $input): array
    {
        // Build the request preserving any empty objects nested in $input so
        // the challenge.id HMAC sees `{}`, not the lossy PHP `[]`.
        $request = '{"op":' . json_encode($op) . ',"input":'
            . json_encode($input, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . '}';
        $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open(['php', self::RUNNER], $descriptors, $pipes);
        self::assertIsResource($process);
        fwrite($pipes[0], $request);
        fclose($pipes[0]);
        $stdout = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        $line = trim((string) $stdout);
        $decoded = json_decode($line, true);
        self::assertIsArray($decoded, 'runner output is not a JSON object: ' . $line);

        return $decoded;
    }

    /**
     * Expand the vendored vectors into the flat case list, mirroring the
     * harness's collectProtocolCases. challenge.id and base64url inputs are
     * loaded object-preserving so empty `{}` survives.
     *
     * @return list<array<string, mixed>>
     */
    private function collectCases(): array
    {
        $cases = [];

        $header = function (string $file, string $parseOp, string $formatOp) use (&$cases): void {
            $data = json_decode((string) file_get_contents(self::VECTORS . '/' . $file), false, flags: JSON_THROW_ON_ERROR);
            foreach ($data->scenarios as $scenario) {
                $tests = $scenario->tests ?? new \stdClass();

                // Canonical adapter gating: a scenario with an `adapters`
                // allow-list only runs on the listed adapters (mirrors the
                // canonical vector runner). Skip anything not gated to php.
                if (isset($scenario->adapters) && !in_array('php', $scenario->adapters, true)) {
                    continue;
                }

                // Canonical constructed-wire shorthand: a `wire` object of
                // {prefix, repeat, count} materializes to
                // prefix . str_repeat(repeat, count).
                $wire = $scenario->wire ?? null;
                if (is_object($wire)) {
                    $wire = ($wire->prefix ?? '') . str_repeat($wire->repeat ?? '', $wire->count ?? 0);
                }
                $scenario->wire = $wire;

                if (isset($tests->parse)) {
                    if ($tests->parse === true && isset($scenario->object)) {
                        $cases[] = [
                            'op' => $parseOp,
                            'scenario' => $scenario->name,
                            'input' => ['header' => $scenario->wire],
                            'expectSuccess' => true,
                            'golden' => json_decode(json_encode($scenario->object), true),
                        ];
                    } elseif (is_object($tests->parse) && ($tests->parse->success ?? null) === false) {
                        $cases[] = [
                            'op' => $parseOp,
                            'scenario' => $scenario->name,
                            'input' => ['header' => $scenario->wire],
                            'expectSuccess' => false,
                            'errorType' => $tests->parse->error_type,
                        ];
                    }
                }

                if (isset($tests->format) && $tests->format === true && isset($scenario->object)) {
                    $cases[] = [
                        'op' => $formatOp,
                        'scenario' => $scenario->name,
                        'input' => $scenario->object,
                        'expectSuccess' => true,
                        'golden' => ['header' => $scenario->wire],
                        'reparseWith' => $parseOp,
                    ];
                }
            }
        };

        $header('www-authenticate.json', 'challenge.parse', 'challenge.format');
        $header('authorization.json', 'credential.parse', 'credential.format');
        $header('receipt.json', 'receipt.parse', 'receipt.format');

        $b64 = json_decode((string) file_get_contents(self::VECTORS . '/base64url.json'), false, flags: JSON_THROW_ON_ERROR);
        foreach ($b64->scenarios as $scenario) {
            if (($scenario->tests->format ?? null) === true) {
                $cases[] = [
                    'op' => 'base64url.encode',
                    'scenario' => $scenario->name,
                    'input' => ['text' => $scenario->decoded],
                    'expectSuccess' => true,
                    'golden' => ['text' => $scenario->encoded],
                ];
            }
            if (($scenario->tests->parse ?? null) === true) {
                $cases[] = [
                    'op' => 'base64url.decode',
                    'scenario' => $scenario->name,
                    'input' => ['text' => $scenario->encoded],
                    'expectSuccess' => true,
                    'golden' => ['text' => $scenario->decoded],
                ];
            }
        }

        $cid = json_decode((string) file_get_contents(self::VECTORS . '/challenge-id.json'), false, flags: JSON_THROW_ON_ERROR);
        foreach ($cid->scenarios as $scenario) {
            $cases[] = [
                'op' => 'challenge.id',
                'scenario' => $scenario->name,
                'input' => $scenario->input,
                'expectSuccess' => true,
                'golden' => ['id' => $scenario->expected],
            ];
        }

        return $cases;
    }
}
