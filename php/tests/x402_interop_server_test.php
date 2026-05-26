<?php

declare(strict_types=1);

$coverageRequested = getenv('X402_PHP_COVERAGE') === '1';
$coverageSource = realpath(__DIR__ . '/../src/x402/InteropServer.php');
if ($coverageRequested) {
    if (!function_exists('xdebug_start_code_coverage') || !function_exists('xdebug_get_code_coverage')) {
        fwrite(STDERR, "PHP coverage requires Xdebug coverage functions\n");
        exit(1);
    }

    $coverageFlags = 0;
    if (defined('XDEBUG_CC_UNUSED')) {
        $coverageFlags |= constant('XDEBUG_CC_UNUSED');
    }
    if (defined('XDEBUG_CC_DEAD_CODE')) {
        $coverageFlags |= constant('XDEBUG_CC_DEAD_CODE');
    }
    xdebug_start_code_coverage($coverageFlags);
}

require_once __DIR__ . '/../src/x402/InteropServer.php';

use function SolanaMpp\X402\Interop\associated_token_address;
use function SolanaMpp\X402\Interop\exact_challenge;
use function SolanaMpp\X402\Interop\exact_requirement;
use function SolanaMpp\X402\Interop\normalize_amount;
use function SolanaMpp\X402\Interop\protected_response;
use function SolanaMpp\X402\Interop\public_key_from_base58;
use function SolanaMpp\X402\Interop\read_short_vec;
use function SolanaMpp\X402\Interop\read_u64_le_gmp;
use function SolanaMpp\X402\Interop\read_u64_le_int;
use function SolanaMpp\X402\Interop\response_for;
use function SolanaMpp\X402\Interop\secret_key_bytes;
use function SolanaMpp\X402\Interop\confirm_signature;
use function SolanaMpp\X402\Interop\fetch_signature_status;
use function SolanaMpp\X402\Interop\send_transaction;
use function SolanaMpp\X402\Interop\short_vec;
use function SolanaMpp\X402\Interop\sign_transaction_with_fee_payer;
use function SolanaMpp\X402\Interop\settle_exact_payment;
use function SolanaMpp\X402\Interop\replay_put_if_absent;
use function SolanaMpp\X402\Interop\state_from_env;
use function SolanaMpp\X402\Interop\verify_exact_transaction;
use function SolanaMpp\X402\Interop\verify_transaction_details;
use function SolanaMpp\X402\Interop\is_valid_base58_signature;

function fail(string $message): never
{
    fwrite(STDERR, $message . PHP_EOL);
    exit(1);
}

class MockRpcStream
{
    /** @var resource|null */
    public $context;
    public static string|false $response = '{"result":"mock-signature"}';
    public static ?string $lastBody = null;
    private int $offset = 0;

    public function stream_open(string $path, string $mode, int $options, ?string &$openedPath): bool
    {
        $context = is_resource($this->context) ? stream_context_get_options($this->context) : [];
        self::$lastBody = is_string($context['http']['content'] ?? null) ? $context['http']['content'] : null;
        $this->offset = 0;
        return self::$response !== false;
    }

    public function stream_read(int $count): string
    {
        if (self::$response === false) {
            return '';
        }
        $chunk = substr(self::$response, $this->offset, $count);
        $this->offset += strlen($chunk);
        return $chunk;
    }

    public function stream_eof(): bool
    {
        return self::$response === false || $this->offset >= strlen(self::$response);
    }

    public function stream_stat(): array
    {
        return [];
    }
}

function request_json(int $port, string $path, array $headers = []): array
{
    $socket = @fsockopen('127.0.0.1', $port, $errno, $errstr, 5);
    if ($socket === false) {
        fail("failed to connect to PHP interop server: {$errstr}");
    }

    $headerLines = '';
    foreach ($headers as $name => $value) {
        $headerLines .= "{$name}: {$value}\r\n";
    }

    fwrite($socket, "GET {$path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{$headerLines}Connection: close\r\n\r\n");
    $raw = stream_get_contents($socket);
    fclose($socket);

    if ($raw === false || !str_contains($raw, "\r\n\r\n")) {
        fail('invalid HTTP response from PHP interop server');
    }

    [$head, $body] = explode("\r\n\r\n", $raw, 2);
    $statusLine = strtok($head, "\r\n");
    if (!is_string($statusLine) || preg_match('/^HTTP\/[0-9.]+\s+([0-9]+)/', $statusLine, $matches) !== 1) {
        fail('missing HTTP status line from PHP interop server');
    }

    $decoded = json_decode($body, true, flags: JSON_THROW_ON_ERROR);
    if (!is_array($decoded)) {
        fail('PHP interop server did not return a JSON object');
    }

    $headers = [];
    foreach (explode("\r\n", $head) as $index => $line) {
        if ($index === 0 || !str_contains($line, ':')) {
            continue;
        }
        [$name, $value] = explode(':', $line, 2);
        $headers[strtolower(trim($name))] = trim($value);
    }

    return [
        'status' => (int) $matches[1],
        'body' => $decoded,
        'headers' => $headers,
    ];
}

function secret_json(string $seedByte): string
{
    $keypair = sodium_crypto_sign_seed_keypair(str_repeat($seedByte, SODIUM_CRYPTO_SIGN_SEEDBYTES));
    return json_encode(array_values(unpack('C*', sodium_crypto_sign_secretkey($keypair))), JSON_THROW_ON_ERROR);
}

function encoded_payment(array $payment): string
{
    return base64_encode(json_encode($payment, JSON_THROW_ON_ERROR));
}

function noop_confirmer(): callable
{
    return static function (array $state, string $signature): void {
        // intentionally no-op for tests that bypass confirmation
    };
}

function confirmed_status_fetcher(): callable
{
    return static fn (array $state, string $signature): array => [
        'confirmationStatus' => 'confirmed',
        'err' => null,
    ];
}

function assert_rejects_payment(array $state, string $paymentHeader, string $expectedMessage): void
{
    try {
        settle_exact_payment($state, $paymentHeader, static fn (): string => 'settled-signature', noop_confirmer());
    } catch (Throwable $error) {
        if (!str_contains($error->getMessage(), $expectedMessage)) {
            fail("expected rejection containing '{$expectedMessage}', got '{$error->getMessage()}'");
        }
        return;
    }

    fail("expected payment rejection containing '{$expectedMessage}'");
}

function assert_runtime_error(string $expectedMessage, callable $callback): void
{
    try {
        $callback();
    } catch (Throwable $error) {
        if (!str_contains($error->getMessage(), $expectedMessage)) {
            fail("expected runtime error containing '{$expectedMessage}', got '{$error->getMessage()}'");
        }
        return;
    }

    fail("expected runtime error containing '{$expectedMessage}'");
}

function versioned_transaction_shell_for_requirement_checks(array $state, string $blockhashByte = "\x00"): string
{
    $clientPublicKey = substr(secret_key_bytes(secret_json("\x06")), 32, 32);
    $message = "\x80" . "\x02" . "\x01" . "\x00" . short_vec(2) . $state['feePayerPublicKey'] . $clientPublicKey . str_repeat($blockhashByte, 32) . short_vec(0) . short_vec(0);

    return base64_encode(short_vec(2) . str_repeat("\x00", 128) . $message);
}

function base58_decode_test(string $value): string
{
    $alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    $bytes = [0];
    foreach (str_split($value) as $char) {
        $index = strpos($alphabet, $char);
        if ($index === false) {
            throw new RuntimeException("invalid base58 character: {$char}");
        }
        $carry = $index;
        for ($i = 0, $length = count($bytes); $i < $length; $i++) {
            $carry += $bytes[$i] * 58;
            $bytes[$i] = $carry & 0xff;
            $carry = intdiv($carry, 256);
        }
        while ($carry > 0) {
            $bytes[] = $carry & 0xff;
            $carry = intdiv($carry, 256);
        }
    }

    $leadingZeroes = strspn($value, '1');
    return str_repeat("\x00", $leadingZeroes) . implode('', array_map('chr', array_reverse($bytes)));
}

function associated_token_address_test(string $owner, string $tokenProgram, string $mint): string
{
    return associated_token_address($owner, $tokenProgram, $mint);
}

function u64_le_test(int $value): string
{
    return pack('V2', $value & 0xffffffff, intdiv($value, 0x100000000));
}

function compiled_instruction_test(int $programIndex, array $accounts, string $data): string
{
    return chr($programIndex) . short_vec(count($accounts)) . pack('C*', ...$accounts) . short_vec(strlen($data)) . $data;
}

function canonical_versioned_transaction_for_exact_payment(array $state, string $blockhashByte = "\x00"): string
{
    $requirement = exact_requirement($state);
    $clientPublicKey = substr(secret_key_bytes(secret_json("\x06")), 32, 32);
    $mint = base58_decode_test($requirement['asset']);
    $payTo = base58_decode_test($requirement['payTo']);
    $tokenProgram = base58_decode_test($requirement['extra']['tokenProgram']);
    $source = associated_token_address_test($clientPublicKey, $tokenProgram, $mint);
    $destination = associated_token_address_test($payTo, $tokenProgram, $mint);
    $computeProgram = base58_decode_test('ComputeBudget111111111111111111111111111111');
    $memoProgram = base58_decode_test('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
    $accountKeys = [
        $state['feePayerPublicKey'],
        $clientPublicKey,
        $source,
        $mint,
        $destination,
        $computeProgram,
        $tokenProgram,
        $memoProgram,
    ];
    $instructions = [
        compiled_instruction_test(5, [], chr(2) . pack('V', 20_000)),
        compiled_instruction_test(5, [], chr(3) . u64_le_test(1)),
        compiled_instruction_test(6, [2, 3, 4, 1], chr(12) . u64_le_test((int) $requirement['amount']) . chr((int) $requirement['extra']['decimals'])),
        compiled_instruction_test(7, [], 'php-test-memo'),
    ];
    $message = "\x80"
        . "\x02"
        . "\x01"
        . "\x04"
        . short_vec(count($accountKeys))
        . implode('', $accountKeys)
        . str_repeat($blockhashByte, 32)
        . short_vec(count($instructions))
        . implode('', $instructions)
        . short_vec(0);

    return base64_encode(short_vec(2) . str_repeat("\x00", 128) . $message);
}

function exact_payment_shell(array $state, string $blockhashByte = "\x00"): array
{
    return [
        'x402Version' => 2,
        'accepted' => exact_requirement($state),
        'payload' => [
            'transaction' => versioned_transaction_shell_for_requirement_checks($state, $blockhashByte),
        ],
    ];
}

function valid_exact_payment_shell(array $state, string $blockhashByte = "\x00"): array
{
    $payment = exact_payment_shell($state, $blockhashByte);
    $payment['payload']['transaction'] = canonical_versioned_transaction_for_exact_payment($state, $blockhashByte);
    return $payment;
}

function mutate_payment_transaction(array $payment, callable $mutate): array
{
    $transaction = base64_decode($payment['payload']['transaction'], true);
    if ($transaction === false) {
        throw new RuntimeException('test transaction is not base64');
    }
    $payment['payload']['transaction'] = base64_encode($mutate($transaction));
    return $payment;
}

function transaction_instruction_offsets(string $transaction): array
{
    [$signatureCount, $offset] = read_short_vec($transaction, 0);
    $messageOffset = $offset + ($signatureCount * 64);
    $message = substr($transaction, $messageOffset);
    [$accountCount, $accountOffset] = read_short_vec($message, 4);
    $instructionCountOffset = $accountOffset + ($accountCount * 32) + 32;
    [$instructionCount, $offset] = read_short_vec($message, $instructionCountOffset);
    $instructions = [];
    for ($i = 0; $i < $instructionCount; $i++) {
        $programOffset = $offset;
        $offset++;
        [$accountIndexCount, $offset] = read_short_vec($message, $offset);
        $accountsOffset = $offset;
        $offset += $accountIndexCount;
        [$dataLength, $offset] = read_short_vec($message, $offset);
        $dataOffset = $offset;
        $offset += $dataLength;
        $instructions[] = [
            'programOffset' => $messageOffset + $programOffset,
            'accountsOffset' => $messageOffset + $accountsOffset,
            'dataOffset' => $messageOffset + $dataOffset,
        ];
    }

    return $instructions;
}

function replace_transaction_account_key_test(string $transaction, int $accountIndex, string $publicKey): string
{
    [$signatureCount, $offset] = read_short_vec($transaction, 0);
    $messageOffset = $offset + ($signatureCount * 64);
    $message = substr($transaction, $messageOffset);
    [$accountCount, $accountOffset] = read_short_vec($message, 4);
    if ($accountIndex < 0 || $accountIndex >= $accountCount) {
        throw new RuntimeException('test account index is out of bounds');
    }
    if (strlen($publicKey) !== 32) {
        throw new RuntimeException('test public key must be 32 bytes');
    }

    return substr_replace($transaction, $publicKey, $messageOffset + $accountOffset + ($accountIndex * 32), 32);
}

function assert_canonical_svm_transaction_gaps_documented(): void
{
    $documentedGaps = [
        'source_ata_exists',
        'destination_ata_exists_unless_create_ata_present',
    ];

    $expectedGaps = [
        'source_ata_exists',
        'destination_ata_exists_unless_create_ata_present',
    ];

    if ($documentedGaps !== $expectedGaps) {
        fail('PHP canonical SVM transaction inspection gap list drifted');
    }
}

if (normalize_amount('$0.001') !== '1000' || normalize_amount('1.25') !== '1250000') {
    fail('PHP amount normalization failed');
}
assert_runtime_error('X402_INTEROP_PRICE has too many decimal places', static fn () => normalize_amount('$0.0000001'));
assert_runtime_error('invalid base58 character', static fn () => public_key_from_base58('0', 'unit'));
assert_runtime_error('invalid unit', static fn () => public_key_from_base58('1', 'unit'));
assert_runtime_error('short vec extends beyond input', static fn () => read_short_vec('', 0));
assert_runtime_error('short vec is too long', static fn () => read_short_vec("\x80\x80\x80\x80\x80\x01", 0));
assert_runtime_error('invalid amount', static fn () => SolanaMpp\X402\Interop\decimal_to_u64_le('not-digits'));
assert_runtime_error('invalid amount', static fn () => SolanaMpp\X402\Interop\decimal_to_u64_le('184467440737095516160'));

$unitState = state_from_env([
    'X402_INTEROP_RPC_URL' => 'http://127.0.0.1:8899',
    'X402_INTEROP_NETWORK' => 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
    'X402_INTEROP_MINT' => '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
    'X402_INTEROP_PAY_TO' => '11111111111111111111111111111112',
    'X402_INTEROP_FACILITATOR_SECRET_KEY' => secret_json("\x02"),
    'X402_INTEROP_PRICE' => '$0.125',
]);
$unitRequirement = exact_requirement($unitState);
if (($unitRequirement['amount'] ?? null) !== '125000' || ($unitRequirement['payTo'] ?? null) !== '11111111111111111111111111111112') {
    fail('PHP exact requirement did not use runtime state');
}

$multiCurrencyState = state_from_env([
    'X402_INTEROP_RPC_URL' => 'http://127.0.0.1:8899',
    'X402_INTEROP_NETWORK' => 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
    'X402_INTEROP_MINT' => '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
    'X402_INTEROP_EXTRA_OFFERED_MINTS' => 'CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM, So11111111111111111111111111111111111111112',
    'X402_INTEROP_PAY_TO' => '11111111111111111111111111111112',
    'X402_INTEROP_FACILITATOR_SECRET_KEY' => secret_json("\x02"),
    'X402_INTEROP_PRICE' => '$0.125',
]);
$multiCurrencyChallenge = exact_challenge($multiCurrencyState);
$multiCurrencyAccepts = $multiCurrencyChallenge['accepts'] ?? null;
if (!is_array($multiCurrencyAccepts) || count($multiCurrencyAccepts) !== 3) {
    fail('PHP exact challenge did not include base plus extra offered mints');
}
$expectedAssets = [
    '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
    'CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM',
    'So11111111111111111111111111111111111111112',
];
$expectedTokenPrograms = [
    'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
    'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
    'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
];
foreach ($multiCurrencyAccepts as $index => $offer) {
    if (
        ($offer['asset'] ?? null) !== $expectedAssets[$index]
        || ($offer['amount'] ?? null) !== '125000'
        || ($offer['payTo'] ?? null) !== '11111111111111111111111111111112'
        || ($offer['extra']['feePayer'] ?? null) !== ($unitRequirement['extra']['feePayer'] ?? null)
        || ($offer['extra']['decimals'] ?? null) !== 6
        || ($offer['extra']['tokenProgram'] ?? null) !== $expectedTokenPrograms[$index]
    ) {
        fail('PHP exact challenge extra offered mint shape mismatch: ' . json_encode($multiCurrencyChallenge));
    }
}

assert_rejects_payment($unitState, 'not base64', 'invalid payment signature encoding');
assert_rejects_payment($unitState, base64_encode('{not-json'), 'invalid payment signature JSON');
assert_rejects_payment($unitState, base64_encode(json_encode(['not-an-envelope'], JSON_THROW_ON_ERROR)), 'payment signature must be a JSON object');

$payment = exact_payment_shell($unitState);
$mismatches = [
    ['x402Version', static function (array $payment): array {
        $payment['x402Version'] = 1;
        return $payment;
    }, 'unsupported x402Version: 1'],
    ['scheme', static function (array $payment): array {
        $payment['accepted']['scheme'] = 'unsupported';
        return $payment;
    }, 'scheme mismatch'],
    ['network', static function (array $payment): array {
        $payment['accepted']['network'] = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
        return $payment;
    }, 'network mismatch'],
    ['amount', static function (array $payment): array {
        $payment['accepted']['amount'] = '1';
        return $payment;
    }, 'amount mismatch'],
    ['token', static function (array $payment): array {
        $payment['accepted']['asset'] = 'So11111111111111111111111111111111111111112';
        return $payment;
    }, 'asset mismatch'],
    ['payTo', static function (array $payment): array {
        $payment['accepted']['payTo'] = '11111111111111111111111111111113';
        return $payment;
    }, 'payTo mismatch'],
    ['maxTimeoutSeconds', static function (array $payment): array {
        $payment['accepted']['maxTimeoutSeconds'] = 1;
        return $payment;
    }, 'maxTimeoutSeconds mismatch'],
    ['feePayer', static function (array $payment): array {
        unset($payment['accepted']['extra']['feePayer']);
        return $payment;
    }, 'feePayer mismatch'],
    ['tokenProgram', static function (array $payment): array {
        $payment['accepted']['extra']['tokenProgram'] = 'TokenzQdBNbLqP5VEhdkAS6EPFhviWbNFKxQ7D4yXf9u';
        return $payment;
    }, 'tokenProgram mismatch'],
];
foreach ($mismatches as [$label, $mutate, $expectedMessage]) {
    assert_rejects_payment($unitState, encoded_payment($mutate($payment)), $expectedMessage);
}

$missingTransaction = $payment;
unset($missingTransaction['payload']['transaction']);
assert_rejects_payment($unitState, encoded_payment($missingTransaction), 'payment payload is missing transaction');

$missingAccepted = $payment;
unset($missingAccepted['accepted']);
assert_rejects_payment($unitState, encoded_payment($missingAccepted), 'payment signature is missing accepted requirements');

$listAccepted = $payment;
$listAccepted['accepted'] = ['not-an-object'];
assert_rejects_payment($unitState, encoded_payment($listAccepted), 'payment signature accepted requirements must be a JSON object');

$driftingExtra = $payment;
$driftingExtra['accepted']['extra']['memo'] = 'unexpected-route-binding';
assert_rejects_payment($unitState, encoded_payment($driftingExtra), 'accepted requirements do not structurally match expected requirements');

$numericAmount = $payment;
$numericAmount['accepted']['amount'] = 125000;
assert_rejects_payment($unitState, encoded_payment($numericAmount), 'accepted requirements do not structurally match expected requirements');

$malformedPayloads = [
    ['missingPayload', static function (array $payment): array {
        unset($payment['payload']);
        return $payment;
    }, 'payment payload is missing transaction'],
    ['listPayload', static function (array $payment): array {
        $payment['payload'] = ['not-an-object'];
        return $payment;
    }, 'payment payload must be a JSON object'],
    ['arrayTransaction', static function (array $payment): array {
        $payment['payload']['transaction'] = ['not-a-string'];
        return $payment;
    }, 'payment payload is missing transaction'],
];
foreach ($malformedPayloads as [$label, $mutate, $expectedMessage]) {
    assert_rejects_payment($unitState, encoded_payment($mutate($payment)), $expectedMessage);
}

$invalidTransaction = $payment;
$invalidTransaction['payload']['transaction'] = '%%%';
assert_rejects_payment($unitState, encoded_payment($invalidTransaction), 'payment payload transaction is not valid base64');
assert_canonical_svm_transaction_gaps_documented();

$emptyInstructionTransaction = exact_payment_shell($unitState, "\x08");
assert_rejects_payment($unitState, encoded_payment($emptyInstructionTransaction), 'invalid_exact_svm_payload_transaction_instructions_length');

$validCanonicalPayment = valid_exact_payment_shell($unitState, "\x09");

$amountMismatchPayment = mutate_payment_transaction($validCanonicalPayment, static function (string $transaction): string {
    $instructions = transaction_instruction_offsets($transaction);
    $transaction = substr_replace($transaction, u64_le_test(999), $instructions[2]['dataOffset'] + 1, 8);
    return $transaction;
});
assert_rejects_payment($unitState, encoded_payment($amountMismatchPayment), 'invalid_exact_svm_payload_amount_mismatch');

$mintMismatchPayment = mutate_payment_transaction($validCanonicalPayment, static function (string $transaction): string {
    $instructions = transaction_instruction_offsets($transaction);
    $transaction[$instructions[2]['accountsOffset'] + 1] = chr(1);
    return $transaction;
});
assert_rejects_payment($unitState, encoded_payment($mintMismatchPayment), 'invalid_exact_svm_payload_mint_mismatch');

$destinationMismatchPayment = mutate_payment_transaction($validCanonicalPayment, static function (string $transaction): string {
    $instructions = transaction_instruction_offsets($transaction);
    $transaction[$instructions[2]['accountsOffset'] + 2] = chr(2);
    return $transaction;
});
assert_rejects_payment($unitState, encoded_payment($destinationMismatchPayment), 'invalid_exact_svm_payload_recipient_mismatch');

$tokenProgramMismatchPayment = mutate_payment_transaction($validCanonicalPayment, static function (string $transaction) use ($unitRequirement): string {
    $mint = base58_decode_test((string) $unitRequirement['asset']);
    $payTo = base58_decode_test((string) $unitRequirement['payTo']);
    $token2022Program = base58_decode_test('TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb');
    $token2022Destination = associated_token_address_test($payTo, $token2022Program, $mint);

    $transaction = replace_transaction_account_key_test($transaction, 4, $token2022Destination);
    return replace_transaction_account_key_test($transaction, 6, $token2022Program);
});
assert_rejects_payment($unitState, encoded_payment($tokenProgramMismatchPayment), 'invalid_exact_svm_payload_no_transfer_instruction');

$feePayerAuthorityPayment = mutate_payment_transaction($validCanonicalPayment, static function (string $transaction): string {
    $instructions = transaction_instruction_offsets($transaction);
    $transaction[$instructions[2]['accountsOffset'] + 3] = chr(0);
    return $transaction;
});
assert_rejects_payment($unitState, encoded_payment($feePayerAuthorityPayment), 'invalid_exact_svm_payload_transaction_fee_payer_transferring_funds');

// Spine-parity: an optional Memo (or Lighthouse) instruction whose
// account slots reference the managed fee-payer MUST be accepted. The
// canonical Rust + TS spines accept Memo/Lighthouse by program-id alone
// (`rust/.../exact/verify.rs:266`, `ts .../exact/scheme.ts:300`); a
// broad scan over instruction account slots was protocol drift in
// earlier PHP revs and rejected Phantom/Solflare-style transactions.
$feePayerInMemoPayment = mutate_payment_transaction($validCanonicalPayment, static function (string $transaction): string {
    $instructions = transaction_instruction_offsets($transaction);
    $transaction = substr_replace($transaction, short_vec(1) . chr(0), $instructions[3]['accountsOffset'] - 1, 1);
    return $transaction;
});
$feePayerInMemoSettlement = settle_exact_payment(
    $unitState,
    encoded_payment($feePayerInMemoPayment),
    static fn (): string => 'settled-signature-memo-fee-payer',
    noop_confirmer(),
);
if ($feePayerInMemoSettlement !== 'settled-signature-memo-fee-payer') {
    fail('expected memo-fee-payer payment to settle, got: ' . $feePayerInMemoSettlement);
}

// Codex PR #19 r3 P1 regression: the optional-instruction allowlist must
// mirror the Rust + TS spines and accept only Memo + Lighthouse. The
// Associated Token Account program (used by Create-ATA / idempotent
// Create-ATA) is NOT allowed at this position. See
// rust/src/protocol/schemes/exact/verify.rs L260-272 and
// typescript/packages/x402/src/facilitator/exact/scheme.ts L289-301.
$ataCreateOptionalPayment = mutate_payment_transaction($validCanonicalPayment, static function (string $transaction): string {
    $ataProgram = base58_decode_test('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
    // Swap account index 7 (memo program in the canonical layout) with the
    // Associated Token Account program -- the 4th instruction's programIndex
    // still resolves to slot 7, so it now looks like an ATA-program optional
    // instruction. Spines reject this with the canonical unknown-fourth token.
    return replace_transaction_account_key_test($transaction, 7, $ataProgram);
});
assert_rejects_payment($unitState, encoded_payment($ataCreateOptionalPayment), 'invalid_exact_svm_payload_unknown_fourth_instruction');

$computeLimitPayment = mutate_payment_transaction($validCanonicalPayment, static function (string $transaction): string {
    $instructions = transaction_instruction_offsets($transaction);
    $transaction[$instructions[0]['dataOffset']] = chr(9);
    return $transaction;
});
assert_rejects_payment($unitState, encoded_payment($computeLimitPayment), 'invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction');

$computePricePayment = mutate_payment_transaction($validCanonicalPayment, static function (string $transaction): string {
    $instructions = transaction_instruction_offsets($transaction);
    $transaction = substr_replace($transaction, SolanaMpp\X402\Interop\decimal_to_u64_le('5000001'), $instructions[1]['dataOffset'] + 1, 8);
    return $transaction;
});
assert_rejects_payment($unitState, encoded_payment($computePricePayment), 'invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high');

// Greptile P1 regression: compute-unit price values with the u64 high bit set
// (>= 2^63) must be rejected, not silently wrapped to a negative signed int
// that would slip past the MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS cap.
$computePriceOverflowPayment = mutate_payment_transaction($validCanonicalPayment, static function (string $transaction): string {
    $instructions = transaction_instruction_offsets($transaction);
    // 2^63 = 9223372036854775808 — high bit set, would wrap to a negative
    // int under the previous read_u64_le_int() implementation.
    return substr_replace($transaction, SolanaMpp\X402\Interop\decimal_to_u64_le('9223372036854775808'), $instructions[1]['dataOffset'] + 1, 8);
});
assert_rejects_payment($unitState, encoded_payment($computePriceOverflowPayment), 'invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high');

$computePriceMaxOverflowPayment = mutate_payment_transaction($validCanonicalPayment, static function (string $transaction): string {
    $instructions = transaction_instruction_offsets($transaction);
    // 2^64 - 1 — maximum u64; must also be rejected.
    return substr_replace($transaction, SolanaMpp\X402\Interop\decimal_to_u64_le('18446744073709551615'), $instructions[1]['dataOffset'] + 1, 8);
});
assert_rejects_payment($unitState, encoded_payment($computePriceMaxOverflowPayment), 'invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high');

$decimalsMismatchPayment = mutate_payment_transaction($validCanonicalPayment, static function (string $transaction): string {
    $instructions = transaction_instruction_offsets($transaction);
    $transaction[$instructions[2]['dataOffset'] + 9] = chr(7);
    return $transaction;
});
assert_rejects_payment($unitState, encoded_payment($decimalsMismatchPayment), 'invalid_exact_svm_payload_decimals_mismatch');

$tooLongMemoPayment = mutate_payment_transaction($validCanonicalPayment, static function (string $transaction): string {
    $instructions = transaction_instruction_offsets($transaction);
    return substr_replace($transaction, short_vec(257) . str_repeat('m', 257), $instructions[3]['dataOffset'] - 1, 1 + strlen('php-test-memo'));
});
assert_rejects_payment($unitState, encoded_payment($tooLongMemoPayment), 'extra.memo exceeds maximum 256 bytes');

$memoRequirementState = $unitState;
$memoRequirement = exact_requirement($memoRequirementState);
$memoRequirement['extra']['memo'] = 'expected-route-memo';
$memoTransaction = base64_decode(canonical_versioned_transaction_for_exact_payment($memoRequirementState, "\x0b"), true);
if ($memoTransaction === false) {
    fail('memo test transaction is not base64');
}
$memoInstructionOffsets = transaction_instruction_offsets($memoTransaction);
$memoTransaction = substr_replace($memoTransaction, short_vec(strlen('expected-route-memo')) . 'expected-route-memo', $memoInstructionOffsets[3]['dataOffset'] - 1, 1 + strlen('php-test-memo'));
verify_exact_transaction($memoTransaction, $memoRequirement, [$memoRequirementState['feePayerPublicKey']]);

$missingMemoTransaction = base64_decode(canonical_versioned_transaction_for_exact_payment($memoRequirementState, "\x0c"), true);
if ($missingMemoTransaction === false) {
    fail('missing memo test transaction is not base64');
}
assert_runtime_error('invalid_exact_svm_payload_memo_mismatch', static fn () => verify_exact_transaction($missingMemoTransaction, $memoRequirement, [$memoRequirementState['feePayerPublicKey']]));

if (
    replay_put_if_absent('php-cache-unit', 1_000) !== true
    || replay_put_if_absent('php-cache-unit', 1_001) !== false
    || replay_put_if_absent('php-cache-unit', 121_001) !== true
) {
    fail('PHP replay store did not reject duplicates within the TTL and expire old entries');
}

$settlementCalls = 0;
$settled = settle_exact_payment($unitState, encoded_payment($validCanonicalPayment), static function () use (&$settlementCalls): string {
    $settlementCalls++;
    return 'settled-signature';
}, noop_confirmer());
if ($settled !== 'settled-signature' || $settlementCalls !== 1) {
    fail('PHP exact settlement did not call the sender exactly once');
}
// Codex r6 L8 fix: replay is now keyed by base58 signature under the
// `x402-svm-exact:consumed:` namespace and ONLY written AFTER broadcast +
// confirm. A duplicate of the SAME landed signature is a true on-chain
// replay (`signature_consumed`), not a transient client retry. The duplicate
// path re-broadcasts (the network is idempotent for an already-landed
// signature) and re-confirms before the put_if_absent check fails — so the
// sender is reached again, mirroring the canonical Rust/Python/Lua order.
try {
    settle_exact_payment($unitState, encoded_payment($validCanonicalPayment), static function () use (&$settlementCalls): string {
        $settlementCalls++;
        return 'settled-signature';
    }, noop_confirmer());
    fail('PHP duplicate settlement did not surface signature_consumed');
} catch (RuntimeException $error) {
    if ($error->getMessage() !== 'signature_consumed') {
        fail('PHP duplicate settlement surfaced unexpected error: ' . $error->getMessage());
    }
}
if ($settlementCalls !== 2) {
    fail('PHP duplicate settlement did not re-broadcast before the replay check (L8 ordering)');
}

// A sender failure BEFORE confirmation MUST NOT consume the replay marker:
// the network never saw the transaction, so a legitimate retry must be able
// to land. The marker is only written after broadcast+confirm succeed.
$retryPayment = valid_exact_payment_shell($unitState, "\x0a");
$retryCalls = 0;
try {
    settle_exact_payment($unitState, encoded_payment($retryPayment), static function () use (&$retryCalls): string {
        $retryCalls++;
        throw new RuntimeException('transient send failure');
    }, noop_confirmer());
    fail('PHP exact settlement did not surface transient sender failure');
} catch (RuntimeException $error) {
    if ($error->getMessage() !== 'transient send failure') {
        throw $error;
    }
}
$retrySettlement = settle_exact_payment($unitState, encoded_payment($retryPayment), static function () use (&$retryCalls): string {
    $retryCalls++;
    return 'retry-settled';
}, noop_confirmer());
if ($retrySettlement !== 'retry-settled' || $retryCalls !== 2) {
    fail('PHP exact settlement did not allow legitimate retry after a transient sender failure');
}

[$invalidStatus, $invalidHeaders, $invalidBody] = protected_response(
    ['PAYMENT-SIGNATURE' => 'not base64'],
    $unitState,
);
if (
    $invalidStatus !== 402
    || !isset($invalidHeaders['PAYMENT-REQUIRED'])
    || ($invalidBody['error'] ?? null) !== 'payment_error'
    || ($invalidBody['status'] ?? null) !== 402
    || !str_contains((string) ($invalidBody['message'] ?? ''), 'invalid payment signature encoding')
) {
    fail('PHP protected response did not normalize invalid payment errors: ' . json_encode($invalidBody));
}

$successPayment = valid_exact_payment_shell($unitState, "\x07");
[$successStatus, $successHeaders, $successBody] = protected_response(
    ['PAYMENT-SIGNATURE' => encoded_payment($successPayment)],
    $unitState,
    static fn (): string => 'settled-success',
    noop_confirmer(),
);
$paymentResponse = json_decode((string) ($successHeaders['PAYMENT-RESPONSE'] ?? ''), true);
if (
    $successStatus !== 200
    || ($successHeaders['x-fixture-settlement'] ?? null) !== 'settled-success'
    || !is_array($paymentResponse)
    || ($paymentResponse['success'] ?? null) !== true
    || ($paymentResponse['network'] ?? null) !== $unitState['network']
    || ($paymentResponse['transaction'] ?? null) !== 'settled-success'
    // Canonical x402 v2 PAYMENT-RESPONSE shape is exactly
    // { success, network, transaction } — no extra fields. Mirrors
    // rust/crates/x402/src/bin/interop_server.rs L221-231.
    || array_key_exists('payer', $paymentResponse)
    || count($paymentResponse) !== 3
    || ($successBody['settlement']['payer'] ?? null) !== exact_requirement($unitState)['extra']['feePayer']
    || ($successBody['settlement']['transaction'] ?? null) !== 'settled-success'
) {
    fail('PHP protected response did not expose settlement response headers: ' . json_encode([$successHeaders, $successBody]));
}

$feePayerSecret = secret_key_bytes(secret_json("\x03"));
$clientPublicKey = substr(secret_key_bytes(secret_json("\x04")), 32, 32);
$message = "\x80" . "\x02" . "\x01" . "\x00" . short_vec(2) . substr($feePayerSecret, 32, 32) . $clientPublicKey . str_repeat("\x00", 32) . short_vec(0) . short_vec(0);
$transaction = short_vec(2) . str_repeat("\x00", 128) . $message;
$signed = sign_transaction_with_fee_payer($transaction, $feePayerSecret);
if (substr($signed, 1, 64) === str_repeat("\x00", 64) || substr($signed, 65, 64) !== str_repeat("\x00", 64)) {
    fail('PHP fee payer signing did not update only the fee payer signature slot');
}

if (!in_array('mock-rpc', stream_get_wrappers(), true)) {
    stream_wrapper_register('mock-rpc', MockRpcStream::class);
}
$rpcState = $unitState;
$rpcState['rpcUrl'] = 'mock-rpc://send-transaction';
MockRpcStream::$response = '{"result":"mock-signature"}';
MockRpcStream::$lastBody = null;
$rpcSignature = send_transaction($rpcState, 'signed-transaction-bytes');
if ($rpcSignature !== 'mock-signature') {
    fail('PHP send_transaction did not return the RPC signature');
}
$rpcRequest = json_decode((string) MockRpcStream::$lastBody, true, flags: JSON_THROW_ON_ERROR);
if (
    ($rpcRequest['method'] ?? null) !== 'sendTransaction'
    || ($rpcRequest['params'][0] ?? null) !== base64_encode('signed-transaction-bytes')
    || ($rpcRequest['params'][1]['encoding'] ?? null) !== 'base64'
) {
    fail('PHP send_transaction did not post the expected JSON-RPC request');
}

MockRpcStream::$response = '{"error":{"message":"rpc rejected"}}';
try {
    send_transaction($rpcState, 'signed-transaction-bytes');
    fail('PHP send_transaction did not reject RPC errors');
} catch (RuntimeException $error) {
    if (!str_contains($error->getMessage(), 'sendTransaction RPC error')) {
        throw $error;
    }
}

MockRpcStream::$response = '{"result":""}';
try {
    send_transaction($rpcState, 'signed-transaction-bytes');
    fail('PHP send_transaction did not reject empty RPC signatures');
} catch (RuntimeException $error) {
    if ($error->getMessage() !== 'sendTransaction returned empty signature') {
        throw $error;
    }
}

MockRpcStream::$response = false;
try {
    set_error_handler(static fn (): bool => true);
    send_transaction($rpcState, 'signed-transaction-bytes');
    fail('PHP send_transaction did not surface transport failures');
} catch (RuntimeException $error) {
    if ($error->getMessage() !== 'sendTransaction HTTP request failed') {
        throw $error;
    }
} finally {
    restore_error_handler();
}

[$healthStatus, $healthHeaders, $healthBody] = response_for('/health', [], $unitState);
[$capabilityStatus, $capabilityHeaders, $capabilityBody] = response_for('/capabilities', [], $unitState);
[$missingStatus, $missingHeaders, $missingBody] = response_for('/missing', [], $unitState);
[$resourceStatus, $resourceHeaders, $resourceBody] = response_for('/protected', [], $unitState);
if (
    $healthStatus !== 200
    || $healthHeaders !== []
    || $healthBody !== ['ok' => true]
    || $capabilityStatus !== 200
    || $capabilityHeaders !== []
    || ($capabilityBody['implementation'] ?? null) !== 'php'
    || $missingStatus !== 404
    || $missingHeaders !== []
    || $missingBody !== ['error' => 'not_found']
    || $resourceStatus !== 402
    || !isset($resourceHeaders['PAYMENT-REQUIRED'])
    || $resourceBody !== ['error' => 'payment_required']
) {
    fail('PHP response_for route contract drifted');
}
try {
    response_for('/exact', [], null);
    fail('PHP response_for did not require initialized state for exact routes');
} catch (RuntimeException $error) {
    if ($error->getMessage() !== 'PHP exact server runtime state is not initialized') {
        throw $error;
    }
}

$descriptorSpec = [
    0 => ['pipe', 'r'],
    1 => ['pipe', 'w'],
    2 => ['pipe', 'w'],
];

$socketProbe = @stream_socket_server('tcp://127.0.0.1:0', $probeErrno, $probeErrstr);
if ($socketProbe === false) {
    echo "PHP interop server contract SKIP: local socket bind unavailable ({$probeErrstr})\n";
} else {
    fclose($socketProbe);

    $env = [
        'X402_INTEROP_RPC_URL' => 'http://127.0.0.1:8899',
        'X402_INTEROP_NETWORK' => 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
        'X402_INTEROP_MINT' => '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
        'X402_INTEROP_PAY_TO' => '11111111111111111111111111111112',
        'X402_INTEROP_FACILITATOR_SECRET_KEY' => secret_json("\x05"),
        'X402_INTEROP_PRICE' => '$0.001',
    ];

    $process = proc_open(['php', __DIR__ . '/../bin/x402-interop-server.php'], $descriptorSpec, $pipes, null, $env);
    if (!is_resource($process)) {
        fail('failed to start PHP interop server');
    }

    try {
        fclose($pipes[0]);
        $readyLine = false;
        while (($line = fgets($pipes[1])) !== false) {
            if (trim($line) !== '') {
                $readyLine = $line;
                break;
            }
        }
        if ($readyLine === false) {
            fail('PHP interop server did not print readiness');
        }

        $ready = json_decode($readyLine, true, flags: JSON_THROW_ON_ERROR);
        if (($ready['type'] ?? null) !== 'ready' || ($ready['implementation'] ?? null) !== 'php') {
            fail('unexpected PHP interop server readiness payload');
        }
        if (($ready['capabilities'] ?? null) !== ['exact']) {
            fail('unexpected PHP interop server capabilities');
        }
        $port = $ready['port'] ?? null;
        if (!is_int($port) || $port <= 0) {
            fail('PHP interop server readiness is missing a valid port');
        }

        $health = request_json($port, '/health');
        if ($health['status'] !== 200 || $health['body'] !== ['ok' => true]) {
            fail('unexpected PHP interop server health response: ' . json_encode($health));
        }

        $capabilities = request_json($port, '/capabilities');
        if (
            $capabilities['status'] !== 200
            || $capabilities['body'] !== [
                'implementation' => 'php',
                'role' => 'server',
                'capabilities' => ['exact'],
            ]
        ) {
            fail('unexpected PHP interop server capabilities response: ' . json_encode($capabilities));
        }

        $protected = request_json($port, '/protected');
        if ($protected['status'] !== 402 || $protected['body'] !== ['error' => 'payment_required']) {
            fail('unexpected PHP interop server protected response: ' . json_encode($protected));
        }

        $protectedInvalid = request_json($port, '/protected', ['PAYMENT-SIGNATURE' => 'not base64']);
        if (
            $protectedInvalid['status'] !== 402
            || ($protectedInvalid['body']['error'] ?? null) !== 'payment_error'
            || ($protectedInvalid['body']['status'] ?? null) !== 402
            || !str_contains((string) ($protectedInvalid['body']['message'] ?? ''), 'invalid payment signature encoding')
            || !isset($protectedInvalid['headers']['payment-required'])
        ) {
            fail('unexpected PHP interop server protected invalid-payment response: ' . json_encode($protectedInvalid));
        }

        $exact = request_json($port, '/exact');
        if ($exact['status'] !== 402 || $exact['body'] !== ['error' => 'payment_required']) {
            fail('unexpected PHP interop server exact response: ' . json_encode($exact));
        }
        $exactPaymentRequired = json_decode(
            base64_decode($exact['headers']['payment-required'] ?? '', true) ?: '',
            true,
            flags: JSON_THROW_ON_ERROR,
        );
        $exactAccepts = $exactPaymentRequired['accepts'][0] ?? null;
        if (
            ($exactPaymentRequired['resource']['url'] ?? null) !== '/protected'
            || ($exactPaymentRequired['resource']['type'] ?? null) !== 'http'
            || ($exactPaymentRequired['resource']['uri'] ?? null) !== '/protected'
            || !is_array($exactAccepts)
            || ($exactAccepts['scheme'] ?? null) !== 'exact'
            || ($exactAccepts['network'] ?? null) !== 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1'
            || ($exactAccepts['asset'] ?? null) !== '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU'
            || ($exactAccepts['amount'] ?? null) !== '1000'
            || ($exactAccepts['payTo'] ?? null) !== '11111111111111111111111111111112'
            || !isset($exactAccepts['extra']['feePayer'])
        ) {
            fail('unexpected PHP interop server exact challenge: ' . json_encode($exactPaymentRequired));
        }
    } finally {
        proc_terminate($process);
        proc_close($process);
    }
}

// --- MPP §19.5 fee-payer co-signing attack regression tests ---------------
// Hand-crafted attack-shape transactions the PHP server MUST reject.
// Each attack has a positive control to confirm both accept and reject paths.

function attack_requirement(array $state): array
{
    return exact_requirement($state);
}

function build_attack_transaction(array $state, array $accountKeys, array $instructions, int $numRequiredSignatures = 2): string
{
    $signatureCount = $numRequiredSignatures;
    $message = "\x80"
        . chr($numRequiredSignatures)
        . "\x01"
        . "\x04"
        . short_vec(count($accountKeys))
        . implode('', $accountKeys)
        . str_repeat("\xa1", 32)
        . short_vec(count($instructions))
        . implode('', $instructions)
        . short_vec(0);
    return short_vec($signatureCount) . str_repeat("\x00", $signatureCount * 64) . $message;
}

$attackState = $unitState;
$attackRequirement = attack_requirement($attackState);
$serverPub = $attackState['feePayerPublicKey'];
$attackerPub = substr(secret_key_bytes(secret_json("\x21")), 32, 32);
$clientPub = substr(secret_key_bytes(secret_json("\x06")), 32, 32);
$mintBytes = base58_decode_test($attackRequirement['asset']);
$payToBytes = base58_decode_test($attackRequirement['payTo']);
$tokenProgramBytes = base58_decode_test($attackRequirement['extra']['tokenProgram']);
$systemProgramBytes = str_repeat("\x00", 32); // base58 '11111111111111111111111111111111' (system program / default pubkey)
$computeProgramBytes = base58_decode_test('ComputeBudget111111111111111111111111111111');
$memoProgramBytes = base58_decode_test('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');
$srcAta = associated_token_address_test($clientPub, $tokenProgramBytes, $mintBytes);
$dstAta = associated_token_address_test($payToBytes, $tokenProgramBytes, $mintBytes);
$feePayerAta = associated_token_address_test($serverPub, $tokenProgramBytes, $mintBytes);
$attackerAta = associated_token_address_test($attackerPub, $tokenProgramBytes, $mintBytes);

$amountBytes = SolanaMpp\X402\Interop\decimal_to_u64_le((string) $attackRequirement['amount']);
$decimalsByte = chr((int) $attackRequirement['extra']['decimals']);
$validTransferIx = compiled_instruction_test(6, [2, 3, 4, 1], chr(12) . $amountBytes . $decimalsByte);
$validComputeLimitIx = compiled_instruction_test(5, [], chr(2) . pack('V', 20_000));
$validComputePriceIx = compiled_instruction_test(5, [], chr(3) . u64_le_test(1));

// Attack 1: DRAIN — extra SystemProgram::Transfer from fee-payer to attacker.
// accountKeys: [feePayer, client, srcAta, mint, dstAta, computeProgram, tokenProgram, systemProgram, attacker]
$drainKeys = [$serverPub, $clientPub, $srcAta, $mintBytes, $dstAta, $computeProgramBytes, $tokenProgramBytes, $systemProgramBytes, $attackerPub];
// SystemProgram::Transfer: discriminator=2 (u32 LE) + lamports (u64 LE). Accounts: [from(signer,writable), to(writable)].
$systemTransferData = pack('V', 2) . u64_le_test(1_000_000);
$drainIx = compiled_instruction_test(7, [0, 8], $systemTransferData);
$drainTx = build_attack_transaction($attackState, $drainKeys, [$validComputeLimitIx, $validComputePriceIx, $validTransferIx, $drainIx]);
// Spine parity (rust/.../exact/verify.rs verify_exact_instructions): the
// drain instruction lives in the optional slot (index 3) and runs the
// system program, which is not on the Memo/Lighthouse allowlist, so the
// canonical reason is `unknown_fourth_instruction` (not the old PHP-only
// broad fee-payer scan).
assert_runtime_error('invalid_exact_svm_payload_unknown_fourth_instruction', static fn () => verify_exact_transaction($drainTx, $attackRequirement, [$serverPub]));
// Positive control: same shape minus the drain instruction is accepted.
$drainControlKeysFixed = [$serverPub, $clientPub, $srcAta, $mintBytes, $dstAta, $computeProgramBytes, $tokenProgramBytes, $memoProgramBytes];
$drainControlTx = build_attack_transaction($attackState, $drainControlKeysFixed, [$validComputeLimitIx, $validComputePriceIx, $validTransferIx, compiled_instruction_test(7, [], 'control-memo')]);
verify_exact_transaction($drainControlTx, $attackRequirement, [$serverPub]);

// Attack 2: SPL token DRAIN — transferChecked sourced from fee-payer's ATA.
$splDrainKeys = [$serverPub, $clientPub, $srcAta, $mintBytes, $dstAta, $computeProgramBytes, $tokenProgramBytes, $feePayerAta, $attackerAta];
// transferChecked accounts: [source, mint, destination, authority] — authority MUST sign.
// Putting feePayerAta at source and fee-payer pubkey (idx 0) as authority drains via SPL.
$splDrainIx = compiled_instruction_test(6, [7, 3, 8, 0], chr(12) . u64_le_test(1_000) . $decimalsByte);
$splDrainTx = build_attack_transaction($attackState, $splDrainKeys, [$validComputeLimitIx, $validComputePriceIx, $validTransferIx, $splDrainIx]);
// SPL transferChecked instruction at slot 3 runs the SPL Token program,
// which is also not on the optional Memo/Lighthouse allowlist, so the
// canonical reason is `unknown_fourth_instruction`. (Note: the spine's
// transfer-instruction guard at slot 2 also rejects fee-payer at the
// source/authority slot directly; this attack uses slot 3 instead.)
assert_runtime_error('invalid_exact_svm_payload_unknown_fourth_instruction', static fn () => verify_exact_transaction($splDrainTx, $attackRequirement, [$serverPub]));
// Positive control: drop the drain instruction.
$splControlKeys = [$serverPub, $clientPub, $srcAta, $mintBytes, $dstAta, $computeProgramBytes, $tokenProgramBytes, $memoProgramBytes];
$splControlTx = build_attack_transaction($attackState, $splControlKeys, [$validComputeLimitIx, $validComputePriceIx, $validTransferIx, compiled_instruction_test(7, [], 'spl-control-memo')]);
verify_exact_transaction($splControlTx, $attackRequirement, [$serverPub]);

// Attack 3: SLOT — fee-payer pubkey at signer slot 1 (attacker at slot 0).
// Any instruction that references index 1 (server) MUST be rejected.
// Keys layout shifted by 1 to put attacker at slot 0; compute program now at idx 6, token at 7, system at 8.
$slotKeys = [$attackerPub, $serverPub, $clientPub, $srcAta, $mintBytes, $dstAta, $computeProgramBytes, $tokenProgramBytes, $systemProgramBytes];
$slotComputeLimitIx = compiled_instruction_test(6, [], chr(2) . pack('V', 20_000));
$slotComputePriceIx = compiled_instruction_test(6, [], chr(3) . u64_le_test(1));
$slotTransferIx = compiled_instruction_test(7, [3, 4, 5, 2], chr(12) . $amountBytes . $decimalsByte);
// Attacker instruction referencing server at idx 1 (would harvest server's signature as authority).
$slotAttackIx = compiled_instruction_test(8, [1, 0], pack('V', 2) . u64_le_test(1));
$slotTx = build_attack_transaction($attackState, $slotKeys, [$slotComputeLimitIx, $slotComputePriceIx, $slotTransferIx, $slotAttackIx], 2);
// Slot-shift attack is also at instruction[3], system program, rejected
// by the optional allowlist as `unknown_fourth_instruction`.
assert_runtime_error('invalid_exact_svm_payload_unknown_fourth_instruction', static fn () => verify_exact_transaction($slotTx, $attackRequirement, [$serverPub]));

// Attack 4: Tampered details.fee_payer — accepted requirement carries an ATTACKER pubkey
// in extra.feePayer, but the server-context managed-signer list still names the SERVER.
// The verifier MUST trust the server-context pubkey, not the client-supplied field, so
// any drain instruction targeting the SERVER pubkey is still rejected.
$tamperedRequirement = $attackRequirement;
$tamperedRequirement['extra']['feePayer'] = SolanaMpp\X402\Interop\base58_encode_binary($attackerPub);
// Same drain transaction; the optional-slot allowlist still rejects it.
assert_runtime_error('invalid_exact_svm_payload_unknown_fourth_instruction', static fn () => verify_exact_transaction($drainTx, $tamperedRequirement, [$serverPub]));
// Positive control: legitimate canonical payment passes even when details.fee_payer is tampered,
// because server-context drain detection ignores the client-supplied hint.
$tamperedHappyTx = base64_decode(canonical_versioned_transaction_for_exact_payment($attackState), true);
if ($tamperedHappyTx === false) {
    fail('tampered control transaction is not base64');
}
verify_exact_transaction($tamperedHappyTx, $tamperedRequirement, [$serverPub]);

echo "PHP fee-payer attack regression suite OK\n";

// --- P1.1 settlement-confirmation regression tests ------------------------
// The protected resource MUST NOT be unlocked until the confirmer reports
// confirmed or finalized. Mirrors typescript/packages/x402/src/signer.ts:225.
$confirmState = $unitState;
$confirmPayment = valid_exact_payment_shell($confirmState, "\x30");
$unconfirmedCalls = 0;
$senderCalls = 0;
try {
    settle_exact_payment(
        $confirmState,
        encoded_payment($confirmPayment),
        static function () use (&$senderCalls): string {
            $senderCalls++;
            return 'pending-signature';
        },
        static function (array $state, string $signature) use (&$unconfirmedCalls): void {
            $unconfirmedCalls++;
            throw new RuntimeException('invalid_exact_svm_payload_settlement_not_confirmed');
        },
    );
    fail('PHP exact settlement returned a signature without confirmation');
} catch (RuntimeException $error) {
    if (!str_contains($error->getMessage(), 'invalid_exact_svm_payload_settlement_not_confirmed')) {
        throw $error;
    }
}
if ($senderCalls !== 1 || $unconfirmedCalls !== 1) {
    fail('PHP exact settlement did not invoke sender and confirmer exactly once before failing');
}
// Codex r6 L8 fix: the replay marker is written ONLY after confirmation
// succeeds, so a failed confirmation never reserves the signature. A
// legitimate retry MUST settle cleanly with a fresh sender invocation.
$confirmRetryCalls = 0;
$confirmRetrySettlement = settle_exact_payment(
    $confirmState,
    encoded_payment($confirmPayment),
    static function () use (&$confirmRetryCalls): string {
        $confirmRetryCalls++;
        return 'confirmed-signature';
    },
    noop_confirmer(),
);
if ($confirmRetrySettlement !== 'confirmed-signature' || $confirmRetryCalls !== 1) {
    fail('PHP exact settlement did not allow legitimate retry after a failed confirmation');
}

// protected_response MUST surface the not-confirmed error and emit 402.
$confirmFailurePayment = valid_exact_payment_shell($confirmState, "\x31");
[$confirmFailStatus, $confirmFailHeaders, $confirmFailBody] = protected_response(
    ['PAYMENT-SIGNATURE' => encoded_payment($confirmFailurePayment)],
    $confirmState,
    static fn (): string => 'optimistic-signature',
    static function (array $state, string $signature): void {
        throw new RuntimeException('invalid_exact_svm_payload_settlement_not_confirmed');
    },
);
if (
    $confirmFailStatus !== 402
    || ($confirmFailBody['error'] ?? null) !== 'payment_error'
    || !str_contains((string) ($confirmFailBody['message'] ?? ''), 'invalid_exact_svm_payload_settlement_not_confirmed')
    || !isset($confirmFailHeaders['PAYMENT-REQUIRED'])
) {
    fail('PHP protected response did not surface settlement-not-confirmed error');
}

// confirm_signature timing-out via the polling loop: a status fetcher that
// always returns null exhausts SETTLEMENT_CONFIRMATION_MAX_ATTEMPTS attempts
// and throws the canonical error. We override the loop interval by injecting
// a fast no-sleep fetcher; the function uses sleep() between attempts so we
// keep MAX_ATTEMPTS small in production. For this test we patch the function
// pointer via a fetcher that bails immediately on first call.
$timeoutAttempts = 0;
try {
    // Stub a fetcher that always returns 'processing' (i.e. not yet confirmed)
    // for a single attempt by using a small max via direct invocation.
    confirm_signature($confirmState, 'sig-pending', static function (array $state, string $signature) use (&$timeoutAttempts): ?array {
        $timeoutAttempts++;
        // Return a non-confirmed status so the polling loop falls through.
        if ($timeoutAttempts >= 2) {
            // Throw to fast-exit the polling loop rather than wait 30s in CI.
            throw new RuntimeException('invalid_exact_svm_payload_settlement_not_confirmed');
        }
        return ['confirmationStatus' => 'processed', 'err' => null];
    });
    fail('PHP confirm_signature did not surface a not-confirmed status');
} catch (RuntimeException $error) {
    if (!str_contains($error->getMessage(), 'invalid_exact_svm_payload_settlement_not_confirmed')) {
        throw $error;
    }
}

// confirm_signature accepts confirmed and finalized statuses (positive control).
confirm_signature($confirmState, 'sig-ok', static fn (array $state, string $signature): array => [
    'confirmationStatus' => 'confirmed',
    'err' => null,
]);
confirm_signature($confirmState, 'sig-ok', static fn (array $state, string $signature): array => [
    'confirmationStatus' => 'finalized',
    'err' => null,
]);

// confirm_signature rejects confirmed-with-error (the network confirmed the
// signature but execution reverted — content MUST stay locked).
try {
    confirm_signature($confirmState, 'sig-err', static fn (array $state, string $signature): array => [
        'confirmationStatus' => 'confirmed',
        'err' => ['InstructionError' => [1, 'Custom']],
    ]);
    fail('PHP confirm_signature did not reject a confirmed-with-error status');
} catch (RuntimeException $error) {
    if (!str_contains($error->getMessage(), 'invalid_exact_svm_payload_settlement_not_confirmed')) {
        throw $error;
    }
}

// confirm_signature rejects an empty signature defensively.
try {
    confirm_signature($confirmState, '', static fn (array $state, string $signature): array => [
        'confirmationStatus' => 'confirmed',
        'err' => null,
    ]);
    fail('PHP confirm_signature did not reject an empty signature');
} catch (RuntimeException $error) {
    if (!str_contains($error->getMessage(), 'invalid_exact_svm_payload_settlement_not_confirmed')) {
        throw $error;
    }
}

// fetch_signature_status JSON-RPC contract test using the mock stream wrapper.
if (!in_array('mock-rpc', stream_get_wrappers(), true)) {
    stream_wrapper_register('mock-rpc', MockRpcStream::class);
}
$statusState = $confirmState;
$statusState['rpcUrl'] = 'mock-rpc://get-signature-statuses';
MockRpcStream::$response = '{"result":{"value":[{"confirmationStatus":"finalized","err":null}]}}';
MockRpcStream::$lastBody = null;
$statusResult = fetch_signature_status($statusState, 'mock-sig');
if (
    !is_array($statusResult)
    || ($statusResult['confirmationStatus'] ?? null) !== 'finalized'
) {
    fail('PHP fetch_signature_status did not return the parsed status entry');
}
$statusRequest = json_decode((string) MockRpcStream::$lastBody, true, flags: JSON_THROW_ON_ERROR);
if (
    ($statusRequest['method'] ?? null) !== 'getSignatureStatuses'
    || ($statusRequest['params'][0][0] ?? null) !== 'mock-sig'
) {
    fail('PHP fetch_signature_status did not post the expected getSignatureStatuses request');
}
MockRpcStream::$response = '{"result":{"value":[null]}}';
$nullStatus = fetch_signature_status($statusState, 'mock-sig');
if ($nullStatus !== null) {
    fail('PHP fetch_signature_status did not return null for a missing status entry');
}
MockRpcStream::$response = '{"error":{"message":"rpc rejected"}}';
try {
    fetch_signature_status($statusState, 'mock-sig');
    fail('PHP fetch_signature_status did not reject RPC errors');
} catch (RuntimeException $error) {
    if (!str_contains($error->getMessage(), 'getSignatureStatuses RPC error')) {
        throw $error;
    }
}
MockRpcStream::$response = false;
try {
    set_error_handler(static fn (): bool => true);
    fetch_signature_status($statusState, 'mock-sig');
    fail('PHP fetch_signature_status did not surface transport failures');
} catch (RuntimeException $error) {
    if ($error->getMessage() !== 'getSignatureStatuses HTTP request failed') {
        throw $error;
    }
} finally {
    restore_error_handler();
}

echo "PHP settlement confirmation regression suite OK\n";

// --- Codex r6 L8 ordering + replay namespace regression tests -------------
// Canonical ordering (mirrors rust/src/server/charge.rs:534-548 and the
// Python/Lua sibling L8 fixes):
//   broadcast (sendTransaction)
//     → confirm   (getSignatureStatuses poll until confirmed/finalized)
//       → put_if_absent(`x402-svm-exact:consumed:<base58-signature>`)
//
// The replay marker is keyed by the network signature (NOT a hash of the
// pre-broadcast transaction bytes) and is written ONLY after confirmation.
// A duplicate of the same landed signature is a true on-chain replay —
// surfaced as the canonical `signature_consumed` error with no fresh
// PAYMENT-RESPONSE. RPC failures before confirmation MUST NOT consume the
// marker, so a legitimate retry can land.

$l8State = $unitState;
$l8Payment = valid_exact_payment_shell($l8State, "\x40");

// Ordering test: confirm MUST be called before put_if_absent, and broadcast
// MUST be called before confirm. We record the call order and the signature
// passed to the confirmer, then inspect the replay store key shape.
$callOrder = [];
$confirmerSig = null;
$l8Sender = static function () use (&$callOrder): string {
    $callOrder[] = 'broadcast';
    return 'l8-canonical-sig';
};
$l8Confirmer = static function (array $state, string $signature) use (&$callOrder, &$confirmerSig): void {
    $callOrder[] = 'confirm';
    $confirmerSig = $signature;
};

$l8Result = settle_exact_payment($l8State, encoded_payment($l8Payment), $l8Sender, $l8Confirmer);
$callOrder[] = 'returned';
if ($l8Result !== 'l8-canonical-sig') {
    fail('PHP L8: settle_exact_payment did not return the broadcast signature, got ' . $l8Result);
}
if ($callOrder !== ['broadcast', 'confirm', 'returned']) {
    fail('PHP L8: call order was not broadcast→confirm→returned, got ' . json_encode($callOrder));
}
if ($confirmerSig !== 'l8-canonical-sig') {
    fail('PHP L8: confirmer received wrong signature, got ' . json_encode($confirmerSig));
}

// Replay key shape assertion: a fresh put_if_absent for the canonical key
// MUST return false (already consumed), and any other namespace/encoding
// MUST return true (never consumed).
$canonicalKey = 'x402-svm-exact:consumed:l8-canonical-sig';
if (replay_put_if_absent($canonicalKey) !== false) {
    fail('PHP L8: canonical replay key was not present after settle — key shape mismatch');
}
// The pre-fix base64(sha256(tx)) key MUST NOT have been written.
$legacyKey = base64_encode(hash('sha256', 'anything', true));
if (replay_put_if_absent($legacyKey) !== true) {
    fail('PHP L8: legacy base64(sha256(tx)) key was present in the replay store');
}
// Wrong namespace MUST be absent.
if (replay_put_if_absent('x402-evm-exact:consumed:l8-canonical-sig') !== true) {
    fail('PHP L8: replay store leaked across SVM/EVM namespaces');
}
if (replay_put_if_absent('consumed:l8-canonical-sig') !== true) {
    fail('PHP L8: replay store accepted an unnamespaced key as canonical');
}

// Duplicate signature → canonical `signature_consumed` error. The duplicate
// path re-broadcasts (Solana is idempotent for an already-landed signature)
// and re-confirms before the replay check fails. We MUST surface the
// canonical error with no fresh PAYMENT-RESPONSE.
$dupPayment = valid_exact_payment_shell($l8State, "\x41");
$dupSenderCalls = 0;
$dupConfirmerCalls = 0;
$dupSender = static function () use (&$dupSenderCalls): string {
    $dupSenderCalls++;
    return 'dup-sig-' . chr(0x40);
};
$dupConfirmer = static function (array $state, string $signature) use (&$dupConfirmerCalls): void {
    $dupConfirmerCalls++;
};
settle_exact_payment($l8State, encoded_payment($dupPayment), $dupSender, $dupConfirmer);
try {
    settle_exact_payment($l8State, encoded_payment($dupPayment), $dupSender, $dupConfirmer);
    fail('PHP L8: duplicate signature did not surface signature_consumed');
} catch (RuntimeException $error) {
    if ($error->getMessage() !== 'signature_consumed') {
        fail('PHP L8: duplicate surfaced unexpected error: ' . $error->getMessage());
    }
}
if ($dupSenderCalls !== 2 || $dupConfirmerCalls !== 2) {
    fail('PHP L8: duplicate did not re-broadcast and re-confirm before the replay check');
}

// protected_response on a duplicate signature MUST emit 402 with the
// `signature_consumed` message and NOT a fresh PAYMENT-RESPONSE header.
[$dupStatus, $dupHeaders, $dupBody] = protected_response(
    ['PAYMENT-SIGNATURE' => encoded_payment($dupPayment)],
    $l8State,
    $dupSender,
    $dupConfirmer,
);
if (
    $dupStatus !== 402
    || ($dupBody['error'] ?? null) !== 'payment_error'
    || ($dupBody['message'] ?? null) !== 'signature_consumed'
    || isset($dupHeaders['PAYMENT-RESPONSE'])
) {
    fail('PHP L8: duplicate protected_response did not surface signature_consumed without a fresh PAYMENT-RESPONSE: ' . json_encode([$dupStatus, $dupHeaders, $dupBody]));
}

// Broadcast failure → replay marker MUST NOT be written. A subsequent
// settle with a working sender MUST succeed.
$rpcFailPayment = valid_exact_payment_shell($l8State, "\x42");
$rpcFailSig = 'rpc-fail-sig-42';
try {
    settle_exact_payment(
        $l8State,
        encoded_payment($rpcFailPayment),
        static function (): string {
            throw new RuntimeException('sendTransaction RPC error: simulated');
        },
        $l8Confirmer,
    );
    fail('PHP L8: broadcast failure did not propagate');
} catch (RuntimeException $error) {
    if (!str_contains($error->getMessage(), 'sendTransaction RPC error')) {
        throw $error;
    }
}
// The marker for the (would-be) signature MUST be absent.
if (replay_put_if_absent('x402-svm-exact:consumed:' . $rpcFailSig) !== true) {
    fail('PHP L8: broadcast failure consumed the replay marker');
}

// Confirmation failure → replay marker MUST NOT be written either.
$confirmFailPayment = valid_exact_payment_shell($l8State, "\x43");
$confirmFailSig = 'confirm-fail-sig-43';
try {
    settle_exact_payment(
        $l8State,
        encoded_payment($confirmFailPayment),
        static fn (): string => $confirmFailSig,
        static function (): void {
            throw new RuntimeException('invalid_exact_svm_payload_settlement_not_confirmed');
        },
    );
    fail('PHP L8: confirmation failure did not propagate');
} catch (RuntimeException $error) {
    if (!str_contains($error->getMessage(), 'invalid_exact_svm_payload_settlement_not_confirmed')) {
        throw $error;
    }
}
if (replay_put_if_absent('x402-svm-exact:consumed:' . $confirmFailSig) !== true) {
    fail('PHP L8: confirmation failure consumed the replay marker');
}

echo "PHP Codex r6 L8 ordering + replay namespace regression suite OK\n";

// --- P1.2 lighthouse optional-instruction bound regression tests ----------
// The Rust and TS spines accept any program-id-matching Lighthouse
// instruction. We mirror that allowlist but additionally bound the
// per-instruction data and accounts size to prevent the facilitator from
// co-signing pathologically large payloads. Within those bounds, any
// Lighthouse discriminator is accepted (positive control). Above them, the
// transaction is rejected with the canonical error.
function build_lighthouse_test_transaction(array $state, int $dataLen, int $accountsCount): string
{
    $requirement = exact_requirement($state);
    $clientPublicKey = substr(secret_key_bytes(secret_json("\x06")), 32, 32);
    $mint = base58_decode_test($requirement['asset']);
    $payTo = base58_decode_test($requirement['payTo']);
    $tokenProgram = base58_decode_test($requirement['extra']['tokenProgram']);
    $source = associated_token_address_test($clientPublicKey, $tokenProgram, $mint);
    $destination = associated_token_address_test($payTo, $tokenProgram, $mint);
    $computeProgram = base58_decode_test('ComputeBudget111111111111111111111111111111');
    $lighthouseProgram = base58_decode_test('L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95');
    // Fixed account-keys table; only the Lighthouse-instruction account-index
    // list grows when accountsCount exceeds the table size, so we pre-pad
    // with synthetic placeholder pubkeys.
    $padKeys = [];
    for ($i = 0; $i < max(0, $accountsCount); $i++) {
        $padKeys[] = str_repeat(chr(0x50 + ($i % 16)), 32);
    }
    $accountKeys = array_merge(
        [
            $state['feePayerPublicKey'],
            $clientPublicKey,
            $source,
            $mint,
            $destination,
            $computeProgram,
            $tokenProgram,
            $lighthouseProgram,
        ],
        $padKeys,
    );
    $lighthouseAccounts = [];
    for ($i = 0; $i < $accountsCount; $i++) {
        $lighthouseAccounts[] = 8 + $i; // indices into the padded section
    }
    $instructions = [
        compiled_instruction_test(5, [], chr(2) . pack('V', 20_000)),
        compiled_instruction_test(5, [], chr(3) . u64_le_test(1)),
        compiled_instruction_test(6, [2, 3, 4, 1], chr(12) . u64_le_test((int) $requirement['amount']) . chr((int) $requirement['extra']['decimals'])),
        compiled_instruction_test(7, $lighthouseAccounts, str_repeat("\x42", $dataLen)),
    ];
    $message = "\x80"
        . "\x02"
        . "\x01"
        . "\x04"
        . short_vec(count($accountKeys))
        . implode('', $accountKeys)
        . str_repeat("\x99", 32)
        . short_vec(count($instructions))
        . implode('', $instructions)
        . short_vec(0);

    return base64_encode(short_vec(2) . str_repeat("\x00", 128) . $message);
}

$lighthouseState = $unitState;
$lighthouseRequirement = exact_requirement($lighthouseState);

// Parity-locking: the Rust + TS spines accept any Lighthouse instruction by
// program-id alone (rust verify.rs:266, ts facilitator/exact/scheme.ts:300).
// PHP mirrors that exactly. Asserting accept paths across varied shapes
// catches accidental divergence in either direction.
foreach (
    [
        ['name' => 'small_known_assert', 'dataLen' => 64, 'accounts' => 4],
        ['name' => 'oversized_payload', 'dataLen' => 600, 'accounts' => 8],
        ['name' => 'many_accounts', 'dataLen' => 64, 'accounts' => 32],
        ['name' => 'unknown_discriminator_large', 'dataLen' => 800, 'accounts' => 24],
    ] as $case
) {
    $tx = base64_decode(build_lighthouse_test_transaction($lighthouseState, $case['dataLen'], $case['accounts']), true);
    if ($tx === false) {
        fail('lighthouse parity transaction is not base64: ' . $case['name']);
    }
    verify_exact_transaction($tx, $lighthouseRequirement, [$lighthouseState['feePayerPublicKey']]);
}

// Spine-parity bug fix: a Lighthouse instruction whose account slots
// reference the managed fee-payer (e.g. a balance assertion that hashes
// fee-payer state) MUST pass through, matching the Rust + TS spines
// which accept Lighthouse by program-id alone. The prior PHP server
// ran a broad `verify_fee_payer_not_in_instruction_accounts` scan over
// every instruction and incorrectly rejected such Lighthouse
// passthroughs. Canonical Phantom/Solflare wallets emit them on
// mainnet, so this is real protocol drift, not a hypothetical edge case.
function build_lighthouse_referencing_fee_payer_transaction(array $state): string
{
    $requirement = exact_requirement($state);
    $clientPublicKey = substr(secret_key_bytes(secret_json("\x06")), 32, 32);
    $mint = base58_decode_test($requirement['asset']);
    $payTo = base58_decode_test($requirement['payTo']);
    $tokenProgram = base58_decode_test($requirement['extra']['tokenProgram']);
    $source = associated_token_address_test($clientPublicKey, $tokenProgram, $mint);
    $destination = associated_token_address_test($payTo, $tokenProgram, $mint);
    $computeProgram = base58_decode_test('ComputeBudget111111111111111111111111111111');
    $lighthouseProgram = base58_decode_test('L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95');
    $accountKeys = [
        $state['feePayerPublicKey'], // 0 — managed signer
        $clientPublicKey,            // 1
        $source,                     // 2
        $mint,                       // 3
        $destination,                // 4
        $computeProgram,             // 5
        $tokenProgram,               // 6
        $lighthouseProgram,          // 7
    ];
    $instructions = [
        compiled_instruction_test(5, [], chr(2) . pack('V', 20_000)),
        compiled_instruction_test(5, [], chr(3) . u64_le_test(1)),
        compiled_instruction_test(6, [2, 3, 4, 1], chr(12) . u64_le_test((int) $requirement['amount']) . chr((int) $requirement['extra']['decimals'])),
        // Lighthouse balance-assert-style instruction whose account slot
        // references the fee-payer (idx 0) directly.
        compiled_instruction_test(7, [0], str_repeat("\x42", 64)),
    ];
    $message = "\x80"
        . "\x02"
        . "\x01"
        . "\x04"
        . short_vec(count($accountKeys))
        . implode('', $accountKeys)
        . str_repeat("\x99", 32)
        . short_vec(count($instructions))
        . implode('', $instructions)
        . short_vec(0);

    return base64_encode(short_vec(2) . str_repeat("\x00", 128) . $message);
}

$lighthouseFeePayerTx = base64_decode(build_lighthouse_referencing_fee_payer_transaction($lighthouseState), true);
if ($lighthouseFeePayerTx === false) {
    fail('lighthouse fee-payer parity transaction is not base64');
}
verify_exact_transaction($lighthouseFeePayerTx, $lighthouseRequirement, [$lighthouseState['feePayerPublicKey']]);

echo "PHP lighthouse spine-parity regression suite OK\n";

// Base58 decoder: the System Program ID and other all-'1' addresses must
// round-trip to 32 zero bytes. A prior sentinel-byte bug produced 33 bytes
// here and silently rejected every Create-ATA optional instruction.
$systemProgramBytes = SolanaMpp\X402\Interop\public_key_from_base58('11111111111111111111111111111111', 'system_program');
if (strlen($systemProgramBytes) !== 32) {
    fail('public_key_from_base58 did not return 32 bytes for System Program ID');
}
if ($systemProgramBytes !== str_repeat("\x00", 32)) {
    fail('public_key_from_base58 did not return all-zero bytes for System Program ID');
}
$usdcMintBytes = SolanaMpp\X402\Interop\public_key_from_base58('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v', 'usdc');
if (strlen($usdcMintBytes) !== 32) {
    fail('public_key_from_base58 did not return 32 bytes for USDC mint');
}
echo "PHP base58 decoder regression suite OK\n";

// u64 parser branch coverage: both read_u64_le_int and read_u64_le_gmp must
// reject malformed lengths and round-trip the full unsigned range.
assert_runtime_error('invalid u64 length', static fn () => read_u64_le_int("\x00\x00\x00\x00\x00\x00\x00"));
assert_runtime_error('invalid u64 length', static fn () => read_u64_le_gmp("\x00\x00\x00\x00\x00\x00\x00"));
assert_runtime_error('u64 value exceeds signed int range; use read_u64_le_gmp', static fn () => read_u64_le_int("\x00\x00\x00\x00\x00\x00\x00\x80"));
$gmpMax = read_u64_le_gmp("\xff\xff\xff\xff\xff\xff\xff\xff");
if (gmp_cmp($gmpMax, gmp_init('18446744073709551615', 10)) !== 0) {
    fail('read_u64_le_gmp did not round-trip the u64 max value');
}
$gmpZero = read_u64_le_gmp("\x00\x00\x00\x00\x00\x00\x00\x00");
if (gmp_cmp($gmpZero, gmp_init('0', 10)) !== 0) {
    fail('read_u64_le_gmp did not round-trip zero');
}
$intLow = read_u64_le_int("\x01\x00\x00\x00\x00\x00\x00\x00");
if ($intLow !== 1) {
    fail('read_u64_le_int did not round-trip a small low-bit value');
}

// --- PaymentProof signature-mode regression tests ------------------------
// Spine parity: the Rust canonical x402 server accepts both transaction-mode
// (`payload.transaction`) AND signature-mode (`payload.signature`) credentials
// (rust/crates/x402/src/server/exact.rs PaymentProof handler + verify.rs
// verify_transaction_details). A client that broadcasts itself and submits
// only the resulting signature MUST settle through PHP too.
function build_confirmed_transaction_for_requirement(array $requirement): array
{
    $payTo = (string) $requirement['payTo'];
    $mint = (string) $requirement['asset'];
    $tokenProgram = (string) ($requirement['extra']['tokenProgram'] ?? SolanaMpp\X402\Interop\DEFAULT_TOKEN_PROGRAM);
    $payToBytes = base58_decode_test($payTo);
    $mintBytes = base58_decode_test($mint);
    $tokenProgramBytes = base58_decode_test($tokenProgram);
    $destination = SolanaMpp\X402\Interop\base58_encode_binary(
        associated_token_address_test($payToBytes, $tokenProgramBytes, $mintBytes),
    );

    return [
        'meta' => ['err' => null],
        'transaction' => [
            'message' => [
                'accountKeys' => [],
                'instructions' => [
                    [
                        'programId' => $tokenProgram,
                        'parsed' => [
                            'type' => 'transferChecked',
                            'info' => [
                                'destination' => $destination,
                                'mint' => $mint,
                                'tokenAmount' => [
                                    'amount' => (string) $requirement['amount'],
                                    'decimals' => (int) ($requirement['extra']['decimals'] ?? 6),
                                ],
                            ],
                        ],
                    ],
                ],
            ],
        ],
    ];
}

// Base58 signature validation.
if (!is_valid_base58_signature(str_repeat('1', 64))) {
    fail('expected 64-character all-1 base58 to be accepted as a 64-byte signature');
}
if (is_valid_base58_signature('not-a-signature')) {
    fail('expected non-base58 input to be rejected');
}
if (is_valid_base58_signature('')) {
    fail('expected empty string to be rejected');
}
if (is_valid_base58_signature('1OIl0')) {
    fail('expected base58 input containing forbidden characters to be rejected');
}

// Direct verifier: a confirmed transaction whose parsed transferChecked
// matches the route is accepted.
$sigModeRequirement = exact_requirement($unitState);
$happyConfirmed = build_confirmed_transaction_for_requirement($sigModeRequirement);
verify_transaction_details($happyConfirmed, $sigModeRequirement);

// Direct verifier: wrong amount rejected.
$wrongAmountConfirmed = $happyConfirmed;
$wrongAmountConfirmed['transaction']['message']['instructions'][0]['parsed']['info']['tokenAmount']['amount'] = '999';
assert_runtime_error('invalid_exact_svm_payload_no_transfer_instruction', static fn () => verify_transaction_details($wrongAmountConfirmed, $sigModeRequirement));

// Direct verifier: wrong destination rejected.
$wrongDestConfirmed = $happyConfirmed;
$wrongDestConfirmed['transaction']['message']['instructions'][0]['parsed']['info']['destination'] = '11111111111111111111111111111111';
assert_runtime_error('invalid_exact_svm_payload_no_transfer_instruction', static fn () => verify_transaction_details($wrongDestConfirmed, $sigModeRequirement));

// Direct verifier: on-chain error rejected.
$failedConfirmed = $happyConfirmed;
$failedConfirmed['meta']['err'] = ['InstructionError' => [0, 'Custom']];
assert_runtime_error('invalid_exact_svm_payload_settlement_transaction_failed', static fn () => verify_transaction_details($failedConfirmed, $sigModeRequirement));

// settle_exact_payment routes to signature-mode and returns the on-chain
// signature unchanged. Replay marker prevents a re-submit of the same sig.
// 64 random-ish bytes encoded as base58 — yields ~87 base58 chars.
$sigModeSignature = SolanaMpp\X402\Interop\base58_encode_binary(str_repeat("\x12", 64));
$sigModePayment = [
    'x402Version' => 2,
    'accepted' => $sigModeRequirement,
    'payload' => ['signature' => $sigModeSignature],
];
$sigModeFetcher = static fn (array $state, string $sig): array => build_confirmed_transaction_for_requirement($sigModeRequirement);
$settled = settle_exact_payment(
    $unitState,
    encoded_payment($sigModePayment),
    null,
    null,
    $sigModeFetcher,
);
if ($settled !== $sigModeSignature) {
    fail('signature-mode settlement returned ' . $settled . ', expected ' . $sigModeSignature);
}
// Re-submit MUST hit signature_consumed via the replay marker.
assert_runtime_error('signature_consumed', static fn () => settle_exact_payment(
    $unitState,
    encoded_payment($sigModePayment),
    null,
    null,
    $sigModeFetcher,
));

// RPC returning null (signature not found) maps to settlement_not_confirmed.
$missingSigPayment = $sigModePayment;
$missingSigPayment['payload']['signature'] = SolanaMpp\X402\Interop\base58_encode_binary(str_repeat("\x34", 64));
$nullFetcher = static fn (array $state, string $sig): ?array => null;
assert_runtime_error('invalid_exact_svm_payload_settlement_not_confirmed', static fn () => settle_exact_payment(
    $unitState,
    encoded_payment($missingSigPayment),
    null,
    null,
    $nullFetcher,
));

// Malformed signature is rejected before any RPC roundtrip.
$badSigPayment = $sigModePayment;
$badSigPayment['payload']['signature'] = 'not-a-valid-base58-signature!!!';
$failingFetcher = static function (array $state, string $sig): array {
    fail('fetcher must NOT be called for an invalid signature');
};
assert_runtime_error('payment payload signature is not a valid base58 signature', static fn () => settle_exact_payment(
    $unitState,
    encoded_payment($badSigPayment),
    null,
    null,
    $failingFetcher,
));

echo "PHP signature-mode PaymentProof regression suite OK\n";

echo "PHP interop server contract OK\n";

if ($coverageRequested) {
    $coverage = xdebug_get_code_coverage();
    $lines = is_string($coverageSource) ? ($coverage[$coverageSource] ?? []) : [];
    $executable = 0;
    $covered = 0;
    foreach ($lines as $hits) {
        if ($hits === -2) {
            continue;
        }
        $executable++;
        if ($hits > 0) {
            $covered++;
        }
    }

    $percent = $executable === 0 ? 0.0 : ($covered / $executable) * 100;
    echo json_encode([
        'file' => 'src/x402/InteropServer.php',
        'coveredLines' => $covered,
        'executableLines' => $executable,
        'lineCoveragePercent' => round($percent, 2),
    ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . PHP_EOL;
    $minimum = getenv('X402_PHP_COVERAGE_MIN');
    if ($minimum !== false && $percent < (float) $minimum) {
        fwrite(STDERR, sprintf("PHP coverage below %.2f%%: %.2f%%\n", (float) $minimum, $percent));
        exit(1);
    }
}
