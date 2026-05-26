<?php

declare(strict_types=1);

namespace SolanaMpp\X402\Interop;

// Mints lives in the same namespace so a `use` is unnecessary; require the
// class file here so procedural callers (e.g. the standalone interop binary
// + the regression script in tests/x402_interop_server_test.php) that load
// `InteropServer.php` directly via `require_once` rather than through the
// Composer autoloader still resolve `Mints::*` constants used below.
require_once __DIR__ . '/Interop/Mints.php';

const CAPABILITY_PAYLOAD = [
    'implementation' => 'php',
    'role' => 'server',
    'capabilities' => ['exact'],
];
const DEFAULT_RESOURCE_PATH = '/protected';
const DEFAULT_PRICE = '$0.001';
const DEFAULT_SETTLEMENT_HEADER = 'x-fixture-settlement';
const PAYMENT_RESPONSE_HEADER = 'PAYMENT-RESPONSE';
const DEFAULT_TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const DEFAULT_TOKEN_DECIMALS = 6;
const DEFAULT_MAX_TIMEOUT_SECONDS = 60;
const DEFAULT_NETWORK = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
// These devnet defaults are the same literals exposed by the canonical
// `Mints` class (which mirrors the Rust spine
// `protocol::schemes::exact::types::mints` module byte-for-byte). They are
// duplicated as file-level `const` strings here because PHP `const` at file
// scope is limited to literal expressions on the lib's ^8.1 baseline. For
// any new symbol+network resolution, call `Mints::resolve()` — it is
// fail-closed (returns null on unknown pairs) so callers never silently
// mis-bind devnet challenges to mainnet mints.
const DEFAULT_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const SETTLEMENT_CACHE_TTL_MS = 120_000;
// Canonical x402-svm-exact replay namespace. The on-chain signature is the
// only identity the network signs over, so we key the replay marker by the
// base58 signature (NOT by hash(tx) or any pre-broadcast digest). The marker
// is only written AFTER getSignatureStatuses reports `confirmed`/`finalized`,
// mirroring the L8 ordering in rust/src/server/charge.rs:534-548 and the
// Python/Lua sibling fixes (broadcast → confirm → put_if_absent). Once
// written, it MUST NOT be released — a duplicate of the same landed
// signature is a true on-chain replay, not a transient client retry.
const REPLAY_KEY_PREFIX = 'x402-svm-exact:consumed:';
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111';
const MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
const LIGHTHOUSE_PROGRAM = 'L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95';
const ASSOCIATED_TOKEN_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const SYSTEM_PROGRAM = '11111111111111111111111111111111';
const TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
const PROGRAM_DERIVED_ADDRESS_MARKER = 'ProgramDerivedAddress';
const MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS = 5_000_000;
const MAX_MEMO_BYTES = 256;
// Lighthouse optional instructions pass through by program-id match alone,
// matching the canonical spines:
//   rust/src/protocol/schemes/exact/verify.rs:266
//   typescript/packages/x402/src/facilitator/exact/scheme.ts:300
// Both spines short-circuit on the program-id check with no discriminator,
// no account-count cap, and no data-length bound. Inventing a single-language
// PHP allowlist would reject real Phantom/Solflare mainnet transactions the
// canonical adapters accept, breaking cross-language interop. A protocol-wide
// allowlist must land in the Rust spine first; tracked at
// notes/lighthouse-allowlist-tracking.md.
// Canonical settlement confirmation policy mirrors the TS reference
// (typescript/packages/x402/src/signer.ts:225-246): poll getSignatureStatuses
// every SETTLEMENT_CONFIRMATION_INTERVAL_SECONDS until the signature reaches
// "confirmed" or "finalized", bounded by SETTLEMENT_CONFIRMATION_MAX_ATTEMPTS.
const SETTLEMENT_CONFIRMATION_MAX_ATTEMPTS = 30;
const SETTLEMENT_CONFIRMATION_INTERVAL_SECONDS = 1;

function normalize_amount(string $price): string
{
    $amount = explode(' ', ltrim(trim($price), '$'))[0];
    [$whole, $fraction] = array_pad(explode('.', $amount, 2), 2, '');
    if (strlen($fraction) > DEFAULT_TOKEN_DECIMALS) {
        throw new \RuntimeException("X402_INTEROP_PRICE has too many decimal places: {$price}");
    }

    $fraction = str_pad($fraction, DEFAULT_TOKEN_DECIMALS, '0');
    return (string) (((int) $whole * 1_000_000) + (int) $fraction);
}

function secret_key_bytes(string $raw): string
{
    $values = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
    if (!is_array($values) || count($values) !== 64) {
        throw new \RuntimeException('expected a 64-byte Solana secret key JSON array');
    }

    return pack('C*', ...array_map(static fn ($value): int => (int) $value, $values));
}

function base58_encode_binary(string $bytes): string
{
    $digits = [0];
    foreach (unpack('C*', $bytes) as $byte) {
        $carry = (int) $byte;
        for ($index = 0, $length = count($digits); $index < $length; $index++) {
            $carry += $digits[$index] << 8;
            $digits[$index] = $carry % 58;
            $carry = intdiv($carry, 58);
        }
        while ($carry > 0) {
            $digits[] = $carry % 58;
            $carry = intdiv($carry, 58);
        }
    }

    $leadingZeroes = 0;
    for ($index = 0, $length = strlen($bytes); $index < $length && $bytes[$index] === "\x00"; $index++) {
        $leadingZeroes++;
    }

    $encoded = str_repeat('1', $leadingZeroes);
    for ($index = count($digits) - 1; $index >= 0; $index--) {
        $encoded .= BASE58_ALPHABET[$digits[$index]];
    }

    return $encoded === '' ? '1' : $encoded;
}

function base58_decode_binary(string $value): string
{
    // No sentinel byte: an all-'1' input (e.g. the System Program ID
    // "11111111111111111111111111111111") otherwise leaves the seed [0] in
    // place, producing a 33-byte output that fails the 32-byte public-key
    // length check and rejects every transaction carrying a Create-ATA
    // optional instruction.
    $bytes = [];
    foreach (str_split($value) as $char) {
        $alphabetIndex = strpos(BASE58_ALPHABET, $char);
        if ($alphabetIndex === false) {
            throw new \RuntimeException("invalid base58 character {$char}");
        }

        $carry = $alphabetIndex;
        for ($index = 0, $length = count($bytes); $index < $length; $index++) {
            $carry += $bytes[$index] * 58;
            $bytes[$index] = $carry & 0xff;
            $carry = intdiv($carry, 256);
        }
        while ($carry > 0) {
            $bytes[] = $carry & 0xff;
            $carry = intdiv($carry, 256);
        }
    }

    return str_repeat("\x00", strspn($value, '1')) . implode('', array_map('chr', array_reverse($bytes)));
}

function public_key_from_base58(string $value, string $field): string
{
    $bytes = base58_decode_binary($value);
    if (strlen($bytes) !== 32) {
        throw new \RuntimeException("invalid {$field}");
    }

    return $bytes;
}

function state_from_env(array $env): array
{
    foreach (['X402_INTEROP_RPC_URL', 'X402_INTEROP_PAY_TO', 'X402_INTEROP_FACILITATOR_SECRET_KEY'] as $name) {
        if (($env[$name] ?? '') === '') {
            throw new \RuntimeException("{$name} is required");
        }
    }

    $secretKey = secret_key_bytes((string) $env['X402_INTEROP_FACILITATOR_SECRET_KEY']);
    return [
        'rpcUrl' => (string) $env['X402_INTEROP_RPC_URL'],
        'network' => (string) ($env['X402_INTEROP_NETWORK'] ?? DEFAULT_NETWORK),
        'mint' => (string) ($env['X402_INTEROP_MINT'] ?? DEFAULT_MINT),
        'extraOfferedMints' => offered_mints_from_env((string) ($env['X402_INTEROP_EXTRA_OFFERED_MINTS'] ?? '')),
        'payTo' => (string) $env['X402_INTEROP_PAY_TO'],
        'feePayerSecretKey' => $secretKey,
        'feePayerPublicKey' => substr($secretKey, 32, 32),
        'amount' => normalize_amount((string) ($env['X402_INTEROP_PRICE'] ?? DEFAULT_PRICE)),
    ];
}

function offered_mints_from_env(string $raw): array
{
    return array_values(array_filter(
        array_map(static fn (string $mint): string => trim($mint), explode(',', $raw)),
        static fn (string $mint): bool => $mint !== '',
    ));
}

/**
 * Resolve the token program (legacy SPL or Token-2022) for a given mint
 * address. Mirrors `rust/crates/x402/src/protocol/schemes/exact/types.rs`
 * (`stablecoin_uses_token_2022` + `default_token_program_for_currency`):
 * USDG, PYUSD, and CASH mints across mainnet/devnet/testnet use the SPL
 * Token-2022 program; everything else falls back to the legacy SPL Token
 * program. Hard-coding only PYUSD devnet (the prior behaviour) advertised
 * the wrong token program for USDG, CASH, and PYUSD mainnet/testnet paths
 * and broke honest payments for those accepted currencies.
 */
function token_program_for_mint(string $mint): string
{
    return mint_uses_token_2022($mint) ? TOKEN_2022_PROGRAM : DEFAULT_TOKEN_PROGRAM;
}

/**
 * Token-2022 mint allowlist mirroring the Rust spine's stablecoin mints
 * table (`mints::USDG_*`, `mints::PYUSD_*`, `mints::CASH_MAINNET`).
 */
function token_2022_mints(): array
{
    static $mints = null;
    if ($mints === null) {
        $mints = [
            Mints::USDG_MAINNET,
            Mints::USDG_DEVNET,
            // USDG_TESTNET aliases USDG_DEVNET in spine; included via dedupe.
            Mints::PYUSD_MAINNET,
            Mints::PYUSD_DEVNET,
            // PYUSD_TESTNET aliases PYUSD_DEVNET in spine; included via dedupe.
            Mints::CASH_MAINNET,
        ];
        $mints = array_values(array_unique($mints));
    }

    return $mints;
}

function mint_uses_token_2022(string $mint): bool
{
    return in_array($mint, token_2022_mints(), true);
}

function exact_requirement(array $state, ?string $mint = null): array
{
    $asset = $mint ?? $state['mint'];
    return [
        'scheme' => 'exact',
        'network' => $state['network'],
        'asset' => $asset,
        'amount' => $state['amount'],
        'payTo' => $state['payTo'],
        'maxTimeoutSeconds' => DEFAULT_MAX_TIMEOUT_SECONDS,
        'extra' => [
            'feePayer' => base58_encode_binary($state['feePayerPublicKey']),
            'decimals' => DEFAULT_TOKEN_DECIMALS,
            'tokenProgram' => token_program_for_mint($asset),
        ],
    ];
}

function exact_requirements(array $state): array
{
    $requirements = [exact_requirement($state)];
    foreach (($state['extraOfferedMints'] ?? []) as $mint) {
        $requirements[] = exact_requirement($state, (string) $mint);
    }

    return $requirements;
}

function exact_challenge(array $state): array
{
    return [
        'x402Version' => 2,
        'resource' => [
            'url' => DEFAULT_RESOURCE_PATH,
            'type' => 'http',
            'uri' => DEFAULT_RESOURCE_PATH,
        ],
        'accepts' => exact_requirements($state),
    ];
}

function find_matching_exact_requirement(array $accepted, array $state): array
{
    $firstError = null;
    foreach (exact_requirements($state) as $requirement) {
        try {
            assert_exact_requirement_matches($accepted, $requirement);
            return $requirement;
        } catch (\RuntimeException $error) {
            $firstError ??= $error;
        }
    }

    throw $firstError ?? new \RuntimeException('accepted requirements do not match any advertised exact requirement');
}

function assert_exact_requirement_matches(array $accepted, array $expected): void
{
    if (array_is_list($accepted)) {
        throw new \RuntimeException('payment signature accepted requirements must be a JSON object');
    }

    $acceptedExtra = is_array($accepted['extra'] ?? null) ? $accepted['extra'] : [];
    $expectedExtra = is_array($expected['extra'] ?? null) ? $expected['extra'] : [];

    $checks = [
        'scheme' => [($accepted['scheme'] ?? null), ($expected['scheme'] ?? null)],
        'network' => [($accepted['network'] ?? null), ($expected['network'] ?? null)],
        'asset' => [($accepted['asset'] ?? null), ($expected['asset'] ?? null)],
        'amount' => [(string) ($accepted['amount'] ?? ''), (string) ($expected['amount'] ?? '')],
        'payTo' => [($accepted['payTo'] ?? null), ($expected['payTo'] ?? null)],
        'maxTimeoutSeconds' => [(string) ($accepted['maxTimeoutSeconds'] ?? ''), (string) ($expected['maxTimeoutSeconds'] ?? '')],
        'feePayer' => [(string) ($acceptedExtra['feePayer'] ?? ''), (string) ($expectedExtra['feePayer'] ?? '')],
        'decimals' => [(string) ($acceptedExtra['decimals'] ?? ''), (string) ($expectedExtra['decimals'] ?? '')],
        'tokenProgram' => [(string) ($acceptedExtra['tokenProgram'] ?? ''), (string) ($expectedExtra['tokenProgram'] ?? '')],
    ];

    foreach ($checks as $field => [$actual, $expectedValue]) {
        if ($actual !== $expectedValue) {
            throw new \RuntimeException("{$field} mismatch");
        }
    }

    if (canonical_value($accepted) !== canonical_value($expected)) {
        throw new \RuntimeException('accepted requirements do not structurally match expected requirements');
    }
}

function canonical_value(mixed $value): mixed
{
    if (!is_array($value)) {
        return $value;
    }

    if (array_is_list($value)) {
        return array_map(__NAMESPACE__ . '\\canonical_value', $value);
    }

    ksort($value);
    foreach ($value as $key => $entry) {
        $value[$key] = canonical_value($entry);
    }

    return $value;
}

function decode_payment_signature(string $paymentHeader): array
{
    $decoded = base64_decode($paymentHeader, true);
    if ($decoded === false) {
        throw new \RuntimeException('invalid payment signature encoding');
    }

    try {
        $payment = json_decode($decoded, true, flags: JSON_THROW_ON_ERROR);
    } catch (\JsonException $error) {
        throw new \RuntimeException('invalid payment signature JSON: ' . $error->getMessage(), previous: $error);
    }

    if (!is_array($payment) || array_is_list($payment)) {
        throw new \RuntimeException('payment signature must be a JSON object');
    }

    return $payment;
}

function read_short_vec(string $bytes, int $offset): array
{
    $value = 0;
    $shift = 0;
    while (true) {
        if ($offset >= strlen($bytes)) {
            throw new \RuntimeException('short vec extends beyond input');
        }
        $byte = ord($bytes[$offset]);
        $value |= ($byte & 0x7f) << $shift;
        $offset++;
        if (($byte & 0x80) === 0) {
            return [$value, $offset];
        }
        $shift += 7;
        if ($shift > 28) {
            throw new \RuntimeException('short vec is too long');
        }
    }
}

function short_vec(int $length): string
{
    $out = '';
    do {
        $byte = $length & 0x7f;
        $length >>= 7;
        if ($length > 0) {
            $byte |= 0x80;
        }
        $out .= chr($byte);
    } while ($length > 0);

    return $out;
}

function required_signer_index(string $message, string $publicKey): int
{
    if (ord($message[0] ?? "\x00") !== 0x80) {
        throw new \RuntimeException('expected versioned transaction message');
    }

    $requiredSignatures = ord($message[1]);
    [$accountCount, $offset] = read_short_vec($message, 4);
    for ($index = 0; $index < $accountCount; $index++) {
        $key = substr($message, $offset, 32);
        if ($index < $requiredSignatures && $key === $publicKey) {
            return $index;
        }
        $offset += 32;
    }

    throw new \RuntimeException('fee payer not found in required signer accounts');
}

function sign_transaction_with_fee_payer(string $transaction, string $secretKey): string
{
    [$signatureCount, $offset] = read_short_vec($transaction, 0);
    $signaturesOffset = $offset;
    $messageOffset = $signaturesOffset + ($signatureCount * 64);
    if ($messageOffset >= strlen($transaction)) {
        throw new \RuntimeException('transaction has no message bytes');
    }

    $message = substr($transaction, $messageOffset);
    $signerIndex = required_signer_index($message, substr($secretKey, 32, 32));
    if ($signerIndex >= $signatureCount) {
        throw new \RuntimeException('fee payer is not present in transaction signatures');
    }

    $signature = sodium_crypto_sign_detached($message, $secretKey);
    return substr_replace($transaction, $signature, $signaturesOffset + ($signerIndex * 64), 64);
}

function parse_versioned_transaction(string $transaction): array
{
    [$signatureCount, $offset] = read_short_vec($transaction, 0);
    $messageOffset = $offset + ($signatureCount * 64);
    if ($messageOffset >= strlen($transaction)) {
        throw new \RuntimeException('transaction has no message bytes');
    }

    $message = substr($transaction, $messageOffset);
    if (ord($message[0] ?? "\x00") !== 0x80) {
        throw new \RuntimeException('expected versioned transaction message');
    }
    if (strlen($message) < 4) {
        throw new \RuntimeException('transaction message header extends beyond input');
    }

    [$accountCount, $offset] = read_short_vec($message, 4);
    $accountKeys = [];
    for ($index = 0; $index < $accountCount; $index++) {
        if ($offset + 32 > strlen($message)) {
            throw new \RuntimeException('message account key extends beyond input');
        }
        $accountKeys[] = substr($message, $offset, 32);
        $offset += 32;
    }

    if ($offset + 32 > strlen($message)) {
        throw new \RuntimeException('message recent blockhash extends beyond input');
    }
    $offset += 32;

    [$instructionCount, $offset] = read_short_vec($message, $offset);
    $instructions = [];
    for ($index = 0; $index < $instructionCount; $index++) {
        if ($offset >= strlen($message)) {
            throw new \RuntimeException('instruction program index extends beyond input');
        }
        $programIndex = ord($message[$offset]);
        $offset++;

        [$accountIndexCount, $offset] = read_short_vec($message, $offset);
        if ($offset + $accountIndexCount > strlen($message)) {
            throw new \RuntimeException('instruction account indexes extend beyond input');
        }
        $accounts = array_values(unpack('C*', substr($message, $offset, $accountIndexCount)) ?: []);
        $offset += $accountIndexCount;

        [$dataLength, $offset] = read_short_vec($message, $offset);
        if ($offset + $dataLength > strlen($message)) {
            throw new \RuntimeException('instruction data extends beyond input');
        }
        $data = substr($message, $offset, $dataLength);
        $offset += $dataLength;
        $instructions[] = [
            'programIndex' => $programIndex,
            'accounts' => $accounts,
            'data' => $data,
        ];
    }

    if ($offset < strlen($message)) {
        read_short_vec($message, $offset);
    }

    return ['accountKeys' => $accountKeys, 'instructions' => $instructions];
}

function verify_exact_transaction(string $transaction, array $requirement, array $managedSigners): array
{
    $parsed = parse_versioned_transaction($transaction);
    $accountKeys = $parsed['accountKeys'];
    $instructions = $parsed['instructions'];
    if (count($instructions) < 3 || count($instructions) > 6) {
        throw new \RuntimeException('invalid_exact_svm_payload_transaction_instructions_length');
    }

    verify_compute_limit_instruction($instructions[0], $accountKeys);
    verify_compute_price_instruction($instructions[1], $accountKeys);
    $transfer = verify_transfer_instruction($instructions[2], $accountKeys, $requirement, $managedSigners);
    // No broad fee-payer-in-instruction-accounts scan: the Rust spine
    // (`rust/crates/x402/src/protocol/schemes/exact/verify.rs`,
    // verify_exact_instructions) only protects the fee-payer inside the
    // transfer instruction (source/authority slots, guarded above) and
    // otherwise accepts optional Lighthouse instructions by program-id
    // alone -- including ones whose account slots reference the managed
    // fee-payer (the canonical Phantom/Solflare emit Lighthouse account
    // assertions that hash fee-payer state). A broader scan rejected
    // those valid Lighthouse passthroughs and was protocol drift.
    verify_optional_instructions(array_slice($instructions, 3), $accountKeys, $requirement);

    return $transfer;
}

function verify_compute_limit_instruction(array $instruction, array $accountKeys): void
{
    $program = instruction_program($instruction, $accountKeys);
    $data = $instruction['data'];
    if ($program !== public_key_from_base58(COMPUTE_BUDGET_PROGRAM, 'compute budget program') || strlen($data) !== 5 || ord($data[0]) !== 2) {
        throw new \RuntimeException('invalid_exact_svm_payload_transaction_instructions_compute_limit_instruction');
    }
    // Intentional parity with Rust spine: rust/src/protocol/schemes/exact/verify.rs
    // (verify_compute_limit_instruction, ~line 317) validates the structure and
    // discriminant only — the compute-unit value itself is not bounded.
    // The Solana runtime clamps to MAX_COMPUTE_UNIT_LIMIT (1_400_000) so any
    // higher value is harmless to the facilitator; we mirror that behavior.
}

function verify_compute_price_instruction(array $instruction, array $accountKeys): void
{
    $program = instruction_program($instruction, $accountKeys);
    $data = $instruction['data'];
    if ($program !== public_key_from_base58(COMPUTE_BUDGET_PROGRAM, 'compute budget program') || strlen($data) !== 9 || ord($data[0]) !== 3) {
        throw new \RuntimeException('invalid_exact_svm_payload_transaction_instructions_compute_price_instruction');
    }
    // Use GMP for the price-cap comparison so values with the high bit set
    // (>= 2^63) are not silently wrapped to negative by PHP signed int math.
    if (gmp_cmp(read_u64_le_gmp(substr($data, 1, 8)), gmp_init((string) MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS, 10)) > 0) {
        throw new \RuntimeException('invalid_exact_svm_payload_transaction_instructions_compute_price_instruction_too_high');
    }
}

function verify_transfer_instruction(array $instruction, array $accountKeys, array $requirement, array $managedSigners): array
{
    $program = instruction_program($instruction, $accountKeys);
    $tokenProgram = public_key_from_base58((string) (($requirement['extra']['tokenProgram'] ?? DEFAULT_TOKEN_PROGRAM)), 'extra.tokenProgram');
    if ($program !== $tokenProgram) {
        throw new \RuntimeException('invalid_exact_svm_payload_no_transfer_instruction');
    }

    $accounts = $instruction['accounts'];
    $data = $instruction['data'];
    if (count($accounts) < 4 || strlen($data) !== 10 || ord($data[0]) !== 12) {
        throw new \RuntimeException('invalid_exact_svm_payload_no_transfer_instruction');
    }

    $source = account_key_for_index($accounts[0], $accountKeys);
    $mint = account_key_for_index($accounts[1], $accountKeys);
    $destination = account_key_for_index($accounts[2], $accountKeys);
    $authority = account_key_for_index($accounts[3], $accountKeys);
    foreach ($managedSigners as $managedSigner) {
        if ($source === $managedSigner || $authority === $managedSigner) {
            throw new \RuntimeException('invalid_exact_svm_payload_transaction_fee_payer_transferring_funds');
        }
    }

    $expectedMint = public_key_from_base58((string) $requirement['asset'], 'asset');
    if ($mint !== $expectedMint) {
        throw new \RuntimeException('invalid_exact_svm_payload_mint_mismatch');
    }

    $payTo = public_key_from_base58((string) $requirement['payTo'], 'payTo');
    $expectedDestination = associated_token_address($payTo, $tokenProgram, $expectedMint);
    if ($destination !== $expectedDestination) {
        throw new \RuntimeException('invalid_exact_svm_payload_recipient_mismatch');
    }

    if (substr($data, 1, 8) !== decimal_to_u64_le((string) $requirement['amount'])) {
        throw new \RuntimeException('invalid_exact_svm_payload_amount_mismatch');
    }

    $expectedDecimals = (int) ($requirement['extra']['decimals'] ?? DEFAULT_TOKEN_DECIMALS);
    if (ord($data[9]) !== $expectedDecimals) {
        throw new \RuntimeException('invalid_exact_svm_payload_decimals_mismatch');
    }

    return [
        'source' => $source,
        'mint' => $mint,
        'destination' => $destination,
        'tokenProgram' => $program,
    ];
}

function verify_optional_instructions(array $instructions, array $accountKeys, array $requirement): void
{
    $memoProgram = public_key_from_base58(MEMO_PROGRAM, 'memo program');
    $lighthouseProgram = public_key_from_base58(LIGHTHOUSE_PROGRAM, 'lighthouse program');
    // Optional-instruction allowlist mirrors the Rust + TS spines exactly:
    // only the Memo and Lighthouse programs are permitted. The Associated
    // Token Account program (including idempotent Create-ATA) is rejected
    // here -- both spines treat any non-{memo, lighthouse} program as an
    // unknown optional instruction.
    //   rust/src/protocol/schemes/exact/verify.rs L260-272
    //   typescript/packages/x402/src/facilitator/exact/scheme.ts L289-301
    $invalidReasonByIndex = [
        'invalid_exact_svm_payload_unknown_fourth_instruction',
        'invalid_exact_svm_payload_unknown_fifth_instruction',
        'invalid_exact_svm_payload_unknown_sixth_instruction',
    ];
    $memoInstructions = [];

    foreach ($instructions as $index => $instruction) {
        $program = instruction_program($instruction, $accountKeys);
        if ($program === $memoProgram) {
            if (strlen($instruction['data']) > MAX_MEMO_BYTES) {
                throw new \RuntimeException('extra.memo exceeds maximum 256 bytes');
            }
            $memoInstructions[] = $instruction;
            continue;
        }
        if ($program === $lighthouseProgram) {
            // Pass through by program-id match only, mirroring the spines
            // (rust verify.rs:263, ts facilitator/exact/scheme.ts:292).
            continue;
        }

        throw new \RuntimeException($invalidReasonByIndex[$index] ?? 'invalid_exact_svm_payload_unknown_optional_instruction');
    }

    $expectedMemo = $requirement['extra']['memo'] ?? null;
    if ($expectedMemo === null) {
        return;
    }
    if (count($memoInstructions) !== 1) {
        throw new \RuntimeException('invalid_exact_svm_payload_memo_count');
    }
    if ($memoInstructions[0]['data'] !== (string) $expectedMemo) {
        throw new \RuntimeException('invalid_exact_svm_payload_memo_mismatch');
    }
}

function instruction_program(array $instruction, array $accountKeys): string
{
    return account_key_for_index($instruction['programIndex'], $accountKeys);
}

function account_key_for_index(int $index, array $accountKeys): string
{
    if (!array_key_exists($index, $accountKeys)) {
        throw new \RuntimeException('invalid_exact_svm_payload_no_transfer_instruction');
    }

    return $accountKeys[$index];
}

function read_u64_le_int(string $bytes): int
{
    if (strlen($bytes) !== 8) {
        throw new \RuntimeException('invalid u64 length');
    }
    $parts = unpack('Vlow/Vhigh', $bytes);
    // Reject values with the high bit set: PHP's signed 64-bit int cannot
    // represent them, and silent overflow would bypass numeric bound checks.
    if (($parts['high'] & 0x80000000) !== 0) {
        throw new \RuntimeException('u64 value exceeds signed int range; use read_u64_le_gmp');
    }
    return ((int) $parts['low']) + ((int) $parts['high'] * 4_294_967_296);
}

function read_u64_le_gmp(string $bytes): \GMP
{
    if (strlen($bytes) !== 8) {
        throw new \RuntimeException('invalid u64 length');
    }
    $parts = unpack('Vlow/Vhigh', $bytes);
    $low = gmp_init(sprintf('%u', $parts['low']), 10);
    $high = gmp_init(sprintf('%u', $parts['high']), 10);
    return gmp_add($low, gmp_mul($high, gmp_init('4294967296', 10)));
}

function decimal_to_u64_le(string $value): string
{
    if (!preg_match('/^[0-9]+$/', $value)) {
        throw new \RuntimeException("invalid amount: {$value}");
    }

    $digits = ltrim($value, '0');
    $digits = $digits === '' ? '0' : $digits;
    $bytes = [];
    for ($index = 0; $index < 8; $index++) {
        [$digits, $remainder] = decimal_divmod($digits, 256);
        $bytes[] = $remainder;
    }
    if ($digits !== '0') {
        throw new \RuntimeException("invalid amount: {$value}");
    }

    return pack('C*', ...$bytes);
}

function decimal_divmod(string $digits, int $divisor): array
{
    $quotient = '';
    $remainder = 0;
    foreach (str_split($digits) as $digit) {
        $value = ($remainder * 10) + (int) $digit;
        $next = intdiv($value, $divisor);
        if ($quotient !== '' || $next !== 0) {
            $quotient .= (string) $next;
        }
        $remainder = $value % $divisor;
    }

    return [$quotient === '' ? '0' : $quotient, $remainder];
}

function associated_token_address(string $owner, string $tokenProgram, string $mint): string
{
    $programId = public_key_from_base58(ASSOCIATED_TOKEN_PROGRAM, 'associated token program');
    $seeds = $owner . $tokenProgram . $mint;
    for ($bump = 255; $bump >= 0; $bump--) {
        $candidate = hash('sha256', $seeds . chr($bump) . $programId . PROGRAM_DERIVED_ADDRESS_MARKER, true);
        if (!ed25519_on_curve($candidate)) {
            return $candidate;
        }
    }

    throw new \RuntimeException('unable to find associated token address');
}

function ed25519_on_curve(string $bytes): bool
{
    if (strlen($bytes) !== 32) {
        return false;
    }
    if (!function_exists('gmp_init')) {
        throw new \RuntimeException('gmp extension is required for associated token address validation');
    }

    static $p = null;
    static $d = null;
    static $i = null;
    if ($p === null) {
        $p = \gmp_sub(\gmp_pow(2, 255), 19);
        $d = positive_gmp_mod(\gmp_mul(-121665, \gmp_invert(\gmp_init(121666), $p)), $p);
        $i = \gmp_powm(2, \gmp_div_q(\gmp_sub($p, 1), 4), $p);
    }

    $raw = array_values(unpack('C*', $bytes) ?: []);
    $sign = $raw[31] >> 7;
    $raw[31] &= 0x7f;
    $y = gmp_from_little_endian($raw);
    if (\gmp_cmp($y, $p) >= 0) {
        return false;
    }

    $y2 = positive_gmp_mod(\gmp_mul($y, $y), $p);
    $numerator = positive_gmp_mod(\gmp_sub($y2, 1), $p);
    $denominator = positive_gmp_mod(\gmp_add(\gmp_mul($d, $y2), 1), $p);
    if (\gmp_cmp($denominator, 0) === 0) {
        return false;
    }

    $x2 = positive_gmp_mod(\gmp_mul($numerator, \gmp_invert($denominator, $p)), $p);
    $x = ed25519_mod_sqrt($x2, $p, $i);
    if ($x === null) {
        return false;
    }
    if (\gmp_intval(\gmp_mod($x, 2)) !== $sign) {
        $x = \gmp_sub($p, $x);
    }

    return \gmp_cmp(positive_gmp_mod(\gmp_sub(\gmp_mul($x, $x), $x2), $p), 0) === 0;
}

function ed25519_mod_sqrt(\GMP $value, \GMP $modulus, \GMP $sqrtMinusOne): ?\GMP
{
    if (\gmp_cmp($value, 0) === 0) {
        return \gmp_init(0);
    }

    $x = \gmp_powm($value, \gmp_div_q(\gmp_add($modulus, 3), 8), $modulus);
    if (\gmp_cmp(positive_gmp_mod(\gmp_sub(\gmp_mul($x, $x), $value), $modulus), 0) !== 0) {
        $x = positive_gmp_mod(\gmp_mul($x, $sqrtMinusOne), $modulus);
    }
    if (\gmp_cmp(positive_gmp_mod(\gmp_sub(\gmp_mul($x, $x), $value), $modulus), 0) !== 0) {
        return null;
    }

    return $x;
}

function gmp_from_little_endian(array $bytes): \GMP
{
    $value = \gmp_init(0);
    for ($index = count($bytes) - 1; $index >= 0; $index--) {
        $value = \gmp_add(\gmp_mul($value, 256), $bytes[$index]);
    }

    return $value;
}

function positive_gmp_mod(\GMP $value, \GMP $modulus): \GMP
{
    $result = \gmp_mod($value, $modulus);
    if (\gmp_cmp($result, 0) < 0) {
        $result = \gmp_add($result, $modulus);
    }

    return $result;
}

function settle_exact_payment(
    array $state,
    string $paymentHeader,
    ?callable $sender = null,
    ?callable $confirmer = null,
    ?callable $transactionFetcher = null,
): string {
    $decoded = decode_payment_signature($paymentHeader);
    if (($decoded['x402Version'] ?? null) !== 2) {
        throw new \RuntimeException('unsupported x402Version: ' . ($decoded['x402Version'] ?? 'null'));
    }

    $accepted = $decoded['accepted'] ?? null;
    if (!is_array($accepted)) {
        throw new \RuntimeException('payment signature is missing accepted requirements');
    }
    $requirement = find_matching_exact_requirement($accepted, $state);

    $payload = $decoded['payload'] ?? null;
    if ($payload !== null && (!is_array($payload) || ($payload !== [] && array_is_list($payload)))) {
        throw new \RuntimeException('payment payload must be a JSON object');
    }
    $payload = is_array($payload) ? $payload : [];

    // Canonical PaymentProof is an untagged enum (rust
    // `protocol::schemes::exact::types::PaymentProof`): the payload carries
    // either a base64 signed `transaction` for the facilitator to broadcast,
    // or a base58 `signature` whose confirmed on-chain transaction the
    // facilitator fetches and re-verifies. PHP must accept both shapes; only
    // accepting `transaction` rejects honest clients that broadcast the
    // transaction themselves and submit the resulting signature.
    $signatureProof = $payload['signature'] ?? null;
    if (is_string($signatureProof) && $signatureProof !== '') {
        return settle_exact_payment_signature_mode(
            $state,
            $requirement,
            $signatureProof,
            $transactionFetcher,
        );
    }

    $transaction = $payload['transaction'] ?? null;
    if (!is_string($transaction) || $transaction === '') {
        throw new \RuntimeException('payment payload is missing transaction');
    }

    $transactionBytes = base64_decode($transaction, true);
    if ($transactionBytes === false || $transactionBytes === '') {
        throw new \RuntimeException('payment payload transaction is not valid base64');
    }

    verify_exact_transaction($transactionBytes, $requirement, [$state['feePayerPublicKey']]);
    $signedTransaction = sign_transaction_with_fee_payer($transactionBytes, $state['feePayerSecretKey']);

    // Canonical L8 ordering (Codex r6 P1 fix): broadcast → confirm →
    // put_if_absent(replay_key). The replay key is keyed by the network's
    // base58 signature, namespaced under `x402-svm-exact:consumed:`, mirroring
    // rust/src/server/charge.rs:534-548 and the Python/Lua sibling fixes.
    //
    // 1. Broadcast: sendTransaction RPC. A failure here means the network
    //    never saw the transaction; we surface the error and DO NOT mark the
    //    signature consumed, so the client can retry.
    // 2. Confirm: getSignatureStatuses polling, bounded by RPC error or the
    //    confirmation attempt cap (a stand-in for blockhash expiry in a
    //    procedural runtime). A failure here means the transaction is in an
    //    indeterminate state; we surface the canonical
    //    `invalid_exact_svm_payload_settlement_not_confirmed` and DO NOT
    //    consume the marker. Some other lander may eventually pick it up;
    //    if a duplicate of the *same* signature lands twice the network
    //    itself rejects the second copy.
    // 3. put_if_absent(replay_key): only AFTER confirmation. A false return
    //    means the same on-chain signature has already been used — that is a
    //    true replay (signature_consumed), not a transient client retry, so
    //    we surface the canonical error and DO NOT emit a fresh
    //    PAYMENT-RESPONSE. The marker is durable for the cache TTL and is
    //    NEVER released on failure.
    $signature = ($sender ?? __NAMESPACE__ . '\\send_transaction')($state, $signedTransaction);
    ($confirmer ?? __NAMESPACE__ . '\\confirm_signature')($state, $signature);

    $replayKey = REPLAY_KEY_PREFIX . $signature;
    if (!replay_put_if_absent($replayKey)) {
        throw new \RuntimeException('signature_consumed');
    }

    return $signature;
}

/**
 * Signature-mode settlement: the client has already broadcast and
 * confirmed the payment transaction and submits only the resulting
 * base58 signature. The facilitator fetches the confirmed transaction
 * by signature, re-verifies the on-chain transferChecked instruction
 * against the route's expected requirements, then applies the same
 * replay marker as transaction-mode settlement.
 *
 * Mirrors the canonical Rust spine handler in
 * `rust/crates/x402/src/server/exact.rs` (`PaymentProof::Signature`
 * branch) plus `protocol::schemes::exact::verify::verify_transaction_details`.
 */
function settle_exact_payment_signature_mode(
    array $state,
    array $requirement,
    string $signature,
    ?callable $transactionFetcher = null,
): string {
    // The on-chain signature is what the network signs over; a syntactically
    // invalid signature can never name a real transaction so reject it before
    // a RPC roundtrip.
    if (!is_valid_base58_signature($signature)) {
        throw new \RuntimeException('payment payload signature is not a valid base58 signature');
    }

    $fetcher = $transactionFetcher ?? __NAMESPACE__ . '\\fetch_transaction_by_signature';
    $confirmedTransaction = $fetcher($state, $signature);
    if (!is_array($confirmedTransaction)) {
        throw new \RuntimeException('invalid_exact_svm_payload_settlement_not_confirmed');
    }

    verify_transaction_details($confirmedTransaction, $requirement);

    // Canonical L8 ordering: the transaction is already confirmed by virtue
    // of getTransaction returning a result, so apply the replay marker now.
    // Identical key namespace + non-release semantics as transaction-mode.
    $replayKey = REPLAY_KEY_PREFIX . $signature;
    if (!replay_put_if_absent($replayKey)) {
        throw new \RuntimeException('signature_consumed');
    }

    return $signature;
}

/**
 * Loose syntactic check for a base58-encoded Solana signature: 64 raw
 * bytes encodes to 86-88 base58 characters. Reject non-base58 input
 * before the RPC call.
 */
function is_valid_base58_signature(string $value): bool
{
    if ($value === '' || strlen($value) < 64 || strlen($value) > 96) {
        return false;
    }
    if (strspn($value, BASE58_ALPHABET) !== strlen($value)) {
        return false;
    }
    try {
        $bytes = base58_decode_binary($value);
    } catch (\Throwable $error) {
        return false;
    }

    return strlen($bytes) === 64;
}

/**
 * Re-verify a confirmed on-chain transaction against the route's
 * payment requirements. Mirrors
 * `rust/crates/x402/src/protocol/schemes/exact/verify.rs`
 * (`verify_transaction_details` -> `verify_on_chain_transfer` /
 * `matches_parsed_transfer` / `matches_raw_transfer`).
 *
 * Accepts the canonical `getTransaction` response under both
 * `jsonParsed` and `json` (raw compiled) encodings.
 */
function verify_transaction_details(array $transaction, array $requirement): void
{
    // Reject explicit on-chain failures.
    $meta = $transaction['meta'] ?? null;
    if (is_array($meta) && ($meta['err'] ?? null) !== null) {
        throw new \RuntimeException('invalid_exact_svm_payload_settlement_transaction_failed');
    }

    $expectedAmount = (string) ($requirement['amount'] ?? '');
    if ($expectedAmount === '') {
        throw new \RuntimeException('invalid_exact_svm_payload_amount_mismatch');
    }
    $expectedMint = (string) ($requirement['asset'] ?? '');
    $expectedRecipient = (string) ($requirement['payTo'] ?? '');
    $tokenProgram = (string) ($requirement['extra']['tokenProgram'] ?? DEFAULT_TOKEN_PROGRAM);

    $expectedRecipientBytes = public_key_from_base58($expectedRecipient, 'payTo');
    $expectedMintBytes = public_key_from_base58($expectedMint, 'asset');
    $tokenProgramBytes = public_key_from_base58($tokenProgram, 'extra.tokenProgram');
    $expectedDestination = base58_encode_binary(
        associated_token_address($expectedRecipientBytes, $tokenProgramBytes, $expectedMintBytes),
    );

    $message = $transaction['transaction']['message'] ?? null;
    if (!is_array($message)) {
        throw new \RuntimeException('invalid_exact_svm_payload_no_transfer_instruction');
    }
    $instructions = $message['instructions'] ?? [];
    if (!is_array($instructions)) {
        throw new \RuntimeException('invalid_exact_svm_payload_no_transfer_instruction');
    }

    $accountKeys = [];
    foreach (($message['accountKeys'] ?? []) as $key) {
        // jsonParsed encoding may return objects (`{pubkey, signer, writable}`)
        // or plain strings; raw encoding always returns strings.
        if (is_array($key)) {
            $accountKeys[] = (string) ($key['pubkey'] ?? '');
        } else {
            $accountKeys[] = (string) $key;
        }
    }

    $matched = false;
    foreach ($instructions as $instruction) {
        if (!is_array($instruction)) {
            continue;
        }
        if (matches_parsed_transfer($instruction, $expectedDestination, $expectedMint, $expectedAmount)
            || matches_raw_transfer($instruction, $accountKeys, $expectedDestination, $expectedMint, $expectedAmount)
        ) {
            $matched = true;
            break;
        }
    }

    if (!$matched) {
        throw new \RuntimeException('invalid_exact_svm_payload_no_transfer_instruction');
    }

    $expectedMemo = $requirement['extra']['memo'] ?? null;
    if ($expectedMemo !== null) {
        $memoInstructions = transaction_memo_strings($instructions, $accountKeys);
        if (count($memoInstructions) !== 1) {
            throw new \RuntimeException('invalid_exact_svm_payload_memo_count');
        }
        if ($memoInstructions[0] !== (string) $expectedMemo) {
            throw new \RuntimeException('invalid_exact_svm_payload_memo_mismatch');
        }
    }
}

/**
 * jsonParsed instruction match: spl-token / spl-token-2022 transferChecked
 * with destination, mint, and amount equal to the route's expectations.
 */
function matches_parsed_transfer(array $instruction, string $expectedDestination, string $expectedMint, string $expectedAmount): bool
{
    $programId = (string) ($instruction['programId'] ?? '');
    if ($programId !== DEFAULT_TOKEN_PROGRAM && $programId !== TOKEN_2022_PROGRAM) {
        return false;
    }
    $parsed = $instruction['parsed'] ?? null;
    if (!is_array($parsed)) {
        return false;
    }
    if (($parsed['type'] ?? null) !== 'transferChecked') {
        return false;
    }
    $info = $parsed['info'] ?? null;
    if (!is_array($info)) {
        return false;
    }
    $destination = (string) ($info['destination'] ?? '');
    $mint = (string) ($info['mint'] ?? '');
    $tokenAmount = $info['tokenAmount'] ?? null;
    $amount = is_array($tokenAmount) ? (string) ($tokenAmount['amount'] ?? '') : '';

    return $destination === $expectedDestination
        && $mint === $expectedMint
        && $amount === $expectedAmount;
}

/**
 * Raw (compiled) instruction match: program is an SPL token program,
 * data decodes to a transferChecked discriminator + u64 amount matching
 * the route's expectations, and accounts[1]=mint, accounts[2]=destination
 * resolve through `accountKeys` to the expected addresses.
 */
function matches_raw_transfer(array $instruction, array $accountKeys, string $expectedDestination, string $expectedMint, string $expectedAmount): bool
{
    $programIndex = $instruction['programIdIndex'] ?? null;
    if (!is_int($programIndex)) {
        return false;
    }
    $program = $accountKeys[$programIndex] ?? null;
    if (!is_string($program) || ($program !== DEFAULT_TOKEN_PROGRAM && $program !== TOKEN_2022_PROGRAM)) {
        return false;
    }
    $data = $instruction['data'] ?? null;
    if (!is_string($data) || $data === '') {
        return false;
    }
    // RPC returns the instruction data base58-encoded for raw encoding.
    try {
        $bytes = base58_decode_binary($data);
    } catch (\Throwable $error) {
        return false;
    }
    // transferChecked = discriminator 12 + u64 amount (8B) + decimals (1B) = 10 bytes.
    if (strlen($bytes) !== 10 || ord($bytes[0]) !== 12) {
        return false;
    }
    $amountBytes = substr($bytes, 1, 8);
    if ($amountBytes !== decimal_to_u64_le($expectedAmount)) {
        return false;
    }
    $accounts = $instruction['accounts'] ?? [];
    if (!is_array($accounts) || count($accounts) < 4) {
        return false;
    }
    $mint = $accountKeys[$accounts[1]] ?? null;
    $destination = $accountKeys[$accounts[2]] ?? null;

    return $mint === $expectedMint && $destination === $expectedDestination;
}

/**
 * Extract memo strings from the confirmed transaction's instruction
 * list. Mirrors the spine's memo extraction, which accepts both
 * `jsonParsed` (`parsed.info.string` or top-level data) and raw
 * (base58 program-data) shapes.
 */
function transaction_memo_strings(array $instructions, array $accountKeys): array
{
    $memos = [];
    foreach ($instructions as $instruction) {
        if (!is_array($instruction)) {
            continue;
        }
        $programId = (string) ($instruction['programId'] ?? '');
        if ($programId === MEMO_PROGRAM) {
            $parsed = $instruction['parsed'] ?? null;
            if (is_string($parsed)) {
                $memos[] = $parsed;
                continue;
            }
            if (is_array($parsed)) {
                $info = $parsed['info'] ?? null;
                if (is_array($info) && isset($info['string'])) {
                    $memos[] = (string) $info['string'];
                    continue;
                }
            }
        }
        // Raw encoding.
        $programIndex = $instruction['programIdIndex'] ?? null;
        if (is_int($programIndex)) {
            $program = $accountKeys[$programIndex] ?? null;
            if ($program === MEMO_PROGRAM) {
                $data = $instruction['data'] ?? null;
                if (is_string($data) && $data !== '') {
                    try {
                        $memos[] = base58_decode_binary($data);
                    } catch (\Throwable $error) {
                        // ignore undecodable memo data; spine rejects on mismatch later
                    }
                }
            }
        }
    }

    return $memos;
}

/**
 * Fetch a confirmed transaction by base58 signature. Wraps RPC
 * `getTransaction` with `jsonParsed` encoding and `confirmed`
 * commitment. Returns the canonical `result` object, or `null` if the
 * RPC could not locate the signature.
 */
function fetch_transaction_by_signature(array $state, string $signature): ?array
{
    $body = json_encode([
        'jsonrpc' => '2.0',
        'id' => 1,
        'method' => 'getTransaction',
        'params' => [
            $signature,
            [
                'encoding' => 'jsonParsed',
                'commitment' => 'confirmed',
                'maxSupportedTransactionVersion' => 0,
            ],
        ],
    ], JSON_THROW_ON_ERROR);

    $response = file_get_contents($state['rpcUrl'], false, stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "content-type: application/json\r\n",
            'content' => $body,
            'timeout' => 15,
        ],
    ]));
    if ($response === false) {
        throw new \RuntimeException('getTransaction HTTP request failed');
    }

    $payload = json_decode($response, true, flags: JSON_THROW_ON_ERROR);
    if (isset($payload['error'])) {
        throw new \RuntimeException('getTransaction RPC error: ' . json_encode($payload['error']));
    }

    $result = $payload['result'] ?? null;
    return is_array($result) ? $result : null;
}

function confirm_signature(array $state, string $signature, ?callable $statusFetcher = null): void
{
    if ($signature === '') {
        throw new \RuntimeException('invalid_exact_svm_payload_settlement_not_confirmed');
    }
    $fetcher = $statusFetcher ?? __NAMESPACE__ . '\\fetch_signature_status';
    for ($attempt = 0; $attempt < SETTLEMENT_CONFIRMATION_MAX_ATTEMPTS; $attempt++) {
        $status = $fetcher($state, $signature);
        $confirmationStatus = is_array($status) ? ($status['confirmationStatus'] ?? null) : null;
        if ($confirmationStatus === 'confirmed' || $confirmationStatus === 'finalized') {
            $err = is_array($status) ? ($status['err'] ?? null) : null;
            if ($err !== null) {
                throw new \RuntimeException('invalid_exact_svm_payload_settlement_not_confirmed');
            }
            return;
        }
        if ($attempt + 1 < SETTLEMENT_CONFIRMATION_MAX_ATTEMPTS) {
            sleep(SETTLEMENT_CONFIRMATION_INTERVAL_SECONDS);
        }
    }

    throw new \RuntimeException('invalid_exact_svm_payload_settlement_not_confirmed');
}

function fetch_signature_status(array $state, string $signature): ?array
{
    $body = json_encode([
        'jsonrpc' => '2.0',
        'id' => 1,
        'method' => 'getSignatureStatuses',
        'params' => [
            [$signature],
            ['searchTransactionHistory' => false],
        ],
    ], JSON_THROW_ON_ERROR);

    $response = file_get_contents($state['rpcUrl'], false, stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "content-type: application/json\r\n",
            'content' => $body,
            'timeout' => 15,
        ],
    ]));
    if ($response === false) {
        throw new \RuntimeException('getSignatureStatuses HTTP request failed');
    }

    $payload = json_decode($response, true, flags: JSON_THROW_ON_ERROR);
    if (isset($payload['error'])) {
        throw new \RuntimeException('getSignatureStatuses RPC error: ' . json_encode($payload['error']));
    }

    $entries = $payload['result']['value'] ?? null;
    if (!is_array($entries)) {
        return null;
    }
    $entry = $entries[0] ?? null;
    return is_array($entry) ? $entry : null;
}

/**
 * Atomic put-if-absent for the in-memory replay store. Returns true if the
 * marker was newly inserted, false if the signature had already been consumed
 * within the TTL window. NEVER call a corresponding release: a successful
 * insert is permanent for the marker's lifetime — that is what guarantees an
 * already-landed signature cannot be re-charged.
 *
 * Durability is a deploy concern. For interop-server.php the in-memory store
 * is sufficient because the canonical replay invariant (key shape + ordering)
 * is what gates correctness; production deployments swap the backing store
 * for Redis/etcd without changing the key namespace.
 */
function replay_put_if_absent(string $key, ?int $nowMs = null): bool
{
    $entries = &settlement_cache_entries();

    $nowMs ??= (int) floor(microtime(true) * 1000);
    $cutoff = $nowMs - SETTLEMENT_CACHE_TTL_MS;
    foreach ($entries as $entryKey => $timestamp) {
        if ($timestamp < $cutoff) {
            unset($entries[$entryKey]);
        }
    }

    if (isset($entries[$key])) {
        return false;
    }

    $entries[$key] = $nowMs;
    return true;
}

function &settlement_cache_entries(): array
{
    static $entries = [];
    return $entries;
}

function send_transaction(array $state, string $signedTransaction): string
{
    $body = json_encode([
        'jsonrpc' => '2.0',
        'id' => 1,
        'method' => 'sendTransaction',
        'params' => [
            base64_encode($signedTransaction),
            [
                'encoding' => 'base64',
                'skipPreflight' => false,
                'preflightCommitment' => 'processed',
                'maxRetries' => 3,
            ],
        ],
    ], JSON_THROW_ON_ERROR);

    $response = file_get_contents($state['rpcUrl'], false, stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "content-type: application/json\r\n",
            'content' => $body,
            'timeout' => 15,
        ],
    ]));
    if ($response === false) {
        throw new \RuntimeException('sendTransaction HTTP request failed');
    }

    $payload = json_decode($response, true, flags: JSON_THROW_ON_ERROR);
    if (isset($payload['error'])) {
        throw new \RuntimeException('sendTransaction RPC error: ' . json_encode($payload['error']));
    }
    if (!isset($payload['result']) || !is_string($payload['result']) || $payload['result'] === '') {
        throw new \RuntimeException('sendTransaction returned empty signature');
    }

    return $payload['result'];
}

function payment_required_header(array $challenge): string
{
    return base64_encode(json_encode($challenge, JSON_THROW_ON_ERROR));
}

function response_for(string $path, array $headers, ?array $state): array
{
    return match ($path) {
        '/health' => [200, [], ['ok' => true]],
        '/capabilities' => [200, [], CAPABILITY_PAYLOAD],
        '/exact' => [
            402,
            ['PAYMENT-REQUIRED' => payment_required_header(exact_challenge(require_state($state)))],
            ['error' => 'payment_required'],
        ],
        DEFAULT_RESOURCE_PATH => protected_response($headers, require_state($state)),
        default => [404, [], ['error' => 'not_found']],
    };
}

function protected_response(array $headers, array $state, ?callable $sender = null, ?callable $confirmer = null, ?callable $transactionFetcher = null): array
{
    $paymentSignature = header_value($headers, 'PAYMENT-SIGNATURE');
    if ($paymentSignature === null || $paymentSignature === '') {
        return [
            402,
            ['PAYMENT-REQUIRED' => payment_required_header(exact_challenge($state))],
            ['error' => 'payment_required'],
        ];
    }

    try {
        $settlement = settle_exact_payment($state, $paymentSignature, $sender, $confirmer, $transactionFetcher);
        // Canonical x402 v2 PaymentResponse shape: { success, network, transaction }
        // Mirrors rust/crates/x402/src/bin/interop_server.rs L221-231 and
        // harness/src/fixtures/typescript/exact-server.ts L322-331. Header value
        // is raw JSON (not base64). The body's `settlement` block can carry
        // richer fields (e.g. `payer`), but the header must match canonical.
        $paymentResponse = [
            'success' => true,
            'network' => $state['network'],
            'transaction' => $settlement,
        ];
        $settlementBody = $paymentResponse + [
            'payer' => base58_encode_binary($state['feePayerPublicKey']),
        ];

        return [
            200,
            [
                DEFAULT_SETTLEMENT_HEADER => $settlement,
                PAYMENT_RESPONSE_HEADER => json_encode($paymentResponse, JSON_THROW_ON_ERROR),
            ],
            [
                'ok' => true,
                'paid' => true,
                'settlement' => $settlementBody,
            ],
        ];
    } catch (\Throwable $error) {
        return [
            402,
            ['PAYMENT-REQUIRED' => payment_required_header(exact_challenge($state))],
            [
                'error' => 'payment_error',
                'status' => 402,
                'message' => $error->getMessage(),
            ],
        ];
    }
}

function header_value(array $headers, string $name): ?string
{
    $needle = strtolower($name);
    foreach ($headers as $key => $value) {
        if (strtolower((string) $key) === $needle) {
            return (string) $value;
        }
    }

    return null;
}

function require_state(?array $state): array
{
    if ($state === null) {
        throw new \RuntimeException('PHP exact server runtime state is not initialized');
    }

    return $state;
}
