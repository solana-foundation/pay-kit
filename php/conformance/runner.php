<?php

declare(strict_types=1);

/**
 * PHP cross-SDK conformance-vector runner.
 *
 * Honors the same stdin/stdout contract as the TypeScript reference runner
 * (harness/src/conformance/ts-runner.ts) and the Go runner
 * (go/cmd/conformance/main.go): read one conformance vector as JSON on
 * stdin, drive the real PayKit PHP SDK for the requested mode, and emit one
 * RunnerResult line as JSON on stdout.
 *
 * ROLE: PHP is a SERVER-only SDK. It ships the MPP charge pre-broadcast
 * verifier (SolanaChargeTransactionVerifier), the x402 exact server adapter
 * (PayKit\Protocols\X402\Adapter), and the canonical-JSON / base64url wire
 * encoders, but it has NO client-side transaction build path. Consequently:
 *
 *   - canonical-bytes        -> supported (JCS + base64url + fixed-width bytes)
 *   - verify-transaction     -> supported ONLY when input.transaction is
 *                               present (a server verifies a wire tx it is
 *                               given). A verify vector that omits the
 *                               transaction expects the runner to BUILD one
 *                               first, which a server-only SDK cannot do.
 *   - build-transaction      -> unsupported (no client build path)
 *
 * x402-exact (intent === "x402-exact"): the cross-SDK oracle is the decoded
 * ENVELOPE shape, not the signed Solana transaction inside
 * payload.transaction (that is the harness matrix's job). PHP is server-only,
 * so:
 *
 *   - build-transaction (x402)  -> unsupported (no client envelope builder)
 *   - verify-transaction (x402) -> supported: drive the x402 envelope verify
 *                                  (version dispatch + network gate + v2
 *                                  accepted-vs-route comparison) and emit
 *                                  accept (with x402EnvelopeShape) or reject
 *                                  (with rejectCode). Mirrors the PHP x402
 *                                  Adapter's parse/dispatch/gate
 *                                  (Protocols\X402\Adapter::verifyAndSettle)
 *                                  and the rust spine line-for-line. The
 *                                  inner-transaction 11-rule structural check
 *                                  and broadcast are out of scope here.
 *
 * For any mode this SDK cannot exercise, the runner emits a RunnerResult with
 * outcome "unsupported-mode" so the driver SKIPs that vector for PHP rather
 * than failing it.
 *
 * The run is deterministic and RPC-free: verify operates purely on the wire
 * transaction the vector pins, with no live validator, no RPC, and no HMAC
 * challenge round-trip.
 */

error_reporting(error_reporting() & ~E_DEPRECATED & ~E_USER_DEPRECATED);
ini_set('display_errors', 'stderr');

require __DIR__ . '/../vendor/autoload.php';

use PayKit\PayCore\Solana\Mints;
use PayKit\PayCore\Wire\Base64Url;
use PayKit\PayCore\Wire\Json;
use PayKit\Protocols\Mpp\Core\Challenge;
use PayKit\Protocols\Mpp\Core\ChallengeEcho;
use PayKit\Protocols\Mpp\Core\Credential;
use PayKit\Protocols\Mpp\Intent\ChargeRequest;
use PayKit\Protocols\Mpp\Server\SolanaChargeTransactionVerifier;
use PayKit\Protocols\X402\Exact\PaymentExtensions;
use SolanaPhpSdk\Keypair\PublicKey;
use SolanaPhpSdk\Programs\AssociatedTokenProgram;
use SolanaPhpSdk\Programs\MemoProgram;
use SolanaPhpSdk\Programs\SystemProgram;
use SolanaPhpSdk\Programs\TokenProgram;
use SolanaPhpSdk\Transaction\Transaction;
use SolanaPhpSdk\Transaction\VersionedTransaction;

const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111';
const DEFAULT_NETWORK = 'mainnet';

/**
 * Read the entire vector JSON from stdin.
 */
function read_stdin(): string
{
    $raw = stream_get_contents(STDIN);
    if (!is_string($raw)) {
        throw new RuntimeException('php conformance runner failed to read stdin');
    }
    $trimmed = trim($raw);
    if ($trimmed === '') {
        throw new RuntimeException('php conformance runner received empty stdin');
    }
    return $trimmed;
}

/**
 * @param array<string, mixed> $result
 */
function emit(array $result): void
{
    fwrite(STDOUT, json_encode($result, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n");
}

/**
 * Apply the precedence rules the vectors probe: top-level asset / payTo win
 * over currency / recipient. Returns a ChargeRequest the PHP verifier
 * consumes. tokenProgram / decimals resolution is left to the verifier
 * itself (Mints::tokenProgramFor by currency, decimals read from
 * methodDetails) so the runner injects no defaults the SDK would not.
 *
 * @param array<string, mixed> $request
 */
function flatten_request(array $request): ChargeRequest
{
    $currency = Json::optionalString($request['asset'] ?? null, 'asset')
        ?: Json::optionalString($request['currency'] ?? null, 'currency');
    $recipient = Json::optionalString($request['payTo'] ?? null, 'payTo')
        ?: Json::optionalString($request['recipient'] ?? null, 'recipient');
    if ($recipient === '') {
        throw new InvalidArgumentException('vector request is missing recipient/payTo');
    }

    $md = $request['methodDetails'] ?? null;
    $methodDetails = is_array($md) ? Json::object($md, 'methodDetails') : [];
    if (!isset($methodDetails['network']) || !is_string($methodDetails['network']) || $methodDetails['network'] === '') {
        $methodDetails['network'] = DEFAULT_NETWORK;
    }

    return new ChargeRequest(
        amount: Json::optionalString($request['amount'] ?? null, 'amount'),
        currency: $currency,
        recipient: $recipient,
        externalId: Json::optionalString($request['externalId'] ?? null, 'externalId'),
        methodDetails: $methodDetails,
    );
}

/**
 * Drive the PHP server's RPC-free pre-broadcast verify on a wire transaction.
 *
 * The pre-broadcast path lives behind SolanaChargeTransactionVerifier::verify
 * (Credential + Challenge), which runs runVerification(..., onChain: false) and
 * therefore enforces the compute-budget caps a pre-broadcast verifier must.
 * We synthesize a self-issued Challenge embedding the flattened request and a
 * pull-mode Credential carrying the transaction, with no HMAC round-trip: the
 * verifier never checks the challenge signature, only the transaction shape.
 */
function verify_transaction(ChargeRequest $request, string $transactionBase64): void
{
    $challenge = Challenge::withSecret(
        secretKey: 'conformance-runner',
        realm: 'conformance',
        method: 'solana',
        intent: 'charge',
        request: $request->toArray(),
    );
    $credential = new Credential(
        challenge: $challenge->toEcho(),
        payload: ['transaction' => $transactionBase64],
    );

    $verifier = new SolanaChargeTransactionVerifier();
    $result = $verifier->verify($credential, $challenge);
    if (!$result->ok) {
        throw new InvalidArgumentException($result->reason !== '' ? $result->reason : 'verification failed');
    }
}

/**
 * Decode a base64 wire transaction into the semantic shape the conformance
 * driver asserts against. Mirrors the TS reference decoder
 * (harness/src/conformance/decode.ts) and the Go shapeFromTransaction: fee
 * payer is account[0], SPL transfers come from transferChecked (discriminator
 * 12), SOL transfers from the System Program transfer (discriminator 2), memos
 * from the Memo Program, and compute caps from the ComputeBudget program.
 *
 * @return array<string, mixed>
 */
function shape_from_transaction(string $transactionBase64): array
{
    $wire = base64_decode($transactionBase64, true);
    if ($wire === false || $wire === '') {
        throw new InvalidArgumentException('invalid transaction payload');
    }

    $version = VersionedTransaction::peekVersion($wire);
    if ($version === 'legacy') {
        $tx = Transaction::deserialize($wire);
        // Legacy Message->instructions are already
        // {programIdIndex, accounts, data} arrays (see Message::deserialize).
        $accountKeys = $tx->message->accountKeys;
        $instructions = $tx->message->instructions;
    } elseif ($version === 0) {
        $tx = VersionedTransaction::deserialize($wire);
        if ($tx->message->addressTableLookups !== []) {
            throw new InvalidArgumentException('v0 address lookup tables are not supported');
        }
        $accountKeys = $tx->message->staticAccountKeys;
        $instructions = array_map(
            static fn (object $ix): array => [
                'programIdIndex' => $ix->programIdIndex,
                'accounts' => $ix->accountKeyIndexes,
                'data' => $ix->data,
            ],
            $tx->message->compiledInstructions,
        );
    } else {
        throw new InvalidArgumentException('unsupported transaction version');
    }

    if ($accountKeys === []) {
        throw new InvalidArgumentException('transaction has no account keys');
    }

    $accountAt = static function (int $index) use ($accountKeys): string {
        if (!isset($accountKeys[$index])) {
            throw new InvalidArgumentException('account index out of range');
        }
        return $accountKeys[$index]->toBase58();
    };

    $shape = [
        'feePayer' => $accountKeys[0]->toBase58(),
        'forbiddenPrograms' => [],
        'memo' => [],
        'transfers' => [],
    ];

    foreach ($instructions as $ix) {
        $program = $accountAt((int) $ix['programIdIndex']);
        $data = (string) $ix['data'];
        $accounts = $ix['accounts'];

        if ($program === COMPUTE_BUDGET_PROGRAM) {
            if (strlen($data) === 5 && ord($data[0]) === 2) {
                $shape['maxComputeUnitLimit'] = read_u32_le(substr($data, 1, 4));
            } elseif (strlen($data) === 9 && ord($data[0]) === 3) {
                $shape['maxComputeUnitPrice'] = (string) read_u64_le(substr($data, 1, 8));
            }
            continue;
        }

        if ($program === MemoProgram::PROGRAM_ID_V2) {
            $shape['memo'][] = $data;
            continue;
        }

        if ($program === SystemProgram::PROGRAM_ID) {
            if (strlen($data) >= 12 && read_u32_le(substr($data, 0, 4)) === 2 && isset($accounts[1])) {
                $shape['transfers'][] = [
                    'amount' => (string) read_u64_le(substr($data, 4, 8)),
                    'destination' => $accountAt((int) $accounts[1]),
                    'kind' => 'sol',
                ];
            }
            continue;
        }

        if ($program === TokenProgram::PROGRAM_ID || $program === TokenProgram::TOKEN_2022_PROGRAM_ID) {
            if (strlen($data) >= 10 && ord($data[0]) === 12 && count($accounts) >= 4) {
                $shape['transfers'][] = [
                    'amount' => (string) read_u64_le(substr($data, 1, 8)),
                    'decimals' => ord($data[9]),
                    'destination' => $accountAt((int) $accounts[2]),
                    'kind' => 'spl',
                    'mint' => $accountAt((int) $accounts[1]),
                    'tokenProgram' => $program,
                ];
            }
            continue;
        }
    }

    return $shape;
}

/**
 * Normalize a PHP SDK reject message onto the shared cross-SDK RejectCode
 * vocabulary. Mirrors harness/src/conformance/reject.ts and the Go runner's
 * classifyReject: the patterns are tuned against the real strings the PHP
 * verifier emits.
 *
 * For MPP charge, the only reject vector PHP actually processes is the
 * transferChecked decimals mismatch, which surfaces as "No matching SPL
 * transferChecked of ..." and so honestly classifies as the generic
 * no-matching-transfer category (the decimals field is enforced through the
 * transfer match key, exactly as in the reference). For x402-exact, the
 * server-verifiable rejects are an unsupported x402Version
 * (-> unsupported-version) and a credential whose network does not match the
 * server route (-> wrong-network). The remaining patterns are kept in
 * lockstep with the shared vocabulary so any future server-verifiable reject
 * reason classifies without further tuning.
 *
 * Returns null when no pattern matches so the harness can surface an
 * unclassified rejection instead of silently passing it.
 */
function classify_reject(string $message): ?string
{
    if ($message === '') {
        return null;
    }

    $patterns = [
        '/compute unit price .*exceeds (maximum|cap)/i' => 'compute-price-over-cap',
        '/compute unit limit .*exceeds (maximum|cap)/i' => 'compute-limit-over-cap',
        '/fee payer cannot authorize/i' => 'fee-payer-not-authority',
        '/fee payer .* (funding source|funds source)/i' => 'fee-payer-is-funds-source',
        '/splits consume the entire amount/i' => 'splits-exceed-amount',
        '/too many splits/i' => 'too-many-splits',
        '/no matching (spl )?(token )?(transfer|transferchecked|sol transfer)/i' => 'no-matching-transfer',
        '/unexpected .* (instruction|transfer)/i' => 'unexpected-instruction',
        '/amount .* (mismatch|does not match)/i' => 'amount-mismatch',
        // x402-exact reject vocabulary. Ordered before the generic
        // invalid/payload fallback so an unknown version or a network
        // mismatch classifies precisely (mirrors reject.ts).
        '/unsupported x402 version/i' => 'unsupported-version',
        '/network mismatch/i' => 'wrong-network',
        // x402-exact extensions: server required a payment-identifier id but
        // the credential echoed none / an invalid one. Checked before the
        // generic invalid/payload fallback (mirrors reject.ts).
        '/payment.identifier .*(required|missing|invalid)/i' => 'payment-identifier-required',
    ];

    foreach ($patterns as $pattern => $code) {
        if (preg_match($pattern, $message) === 1) {
            return $code;
        }
    }

    if (preg_match('/invalid|malformed|decode|payload/i', $message) === 1) {
        return 'invalid-payload';
    }

    return null;
}

function read_u32_le(string $bytes): int
{
    $unpacked = unpack('Vvalue', $bytes);
    if ($unpacked === false || !is_int($unpacked['value'])) {
        throw new InvalidArgumentException('expected 4 bytes');
    }
    return $unpacked['value'];
}

function read_u64_le(string $bytes): int
{
    if (strlen($bytes) !== 8) {
        throw new InvalidArgumentException('expected 8 bytes');
    }
    $value = 0;
    for ($i = 7; $i >= 0; $i -= 1) {
        $value = ($value << 8) + ord($bytes[$i]);
    }
    return $value;
}

/**
 * Encode an integer as `width` little-endian bytes.
 */
function encode_uint_le(int $value, int $width): string
{
    $out = '';
    for ($i = 0; $i < $width; $i += 1) {
        $out .= chr($value & 0xff);
        $value >>= 8;
    }
    if ($value !== 0) {
        throw new InvalidArgumentException('value does not fit in ' . $width . ' bytes');
    }
    return $out;
}

/**
 * Solana shortvec (compact-u16) length prefix.
 */
function compact_u16(int $value): string
{
    $out = '';
    while (true) {
        $byte = $value & 0x7f;
        $value >>= 7;
        if ($value === 0) {
            $out .= chr($byte);
            break;
        }
        $out .= chr($byte | 0x80);
    }
    return $out;
}

/**
 * Assemble a verify-transaction wire fixture from a flattened ChargeRequest
 * and the vector's 64-byte signer secret key, returning the base64 wire
 * transaction the PHP verifier (the system under test) then accepts.
 *
 * PHP is a server-only SDK: a verify vector that omits input.transaction
 * pins only the request + signer and expects the runner to assemble the
 * transaction itself, exactly as the Ruby runner does. The layout mirrors
 * the Rust client builder and matches what the PHP verifier reads:
 * transferChecked accounts (source, mint, dest, authority); idempotent ATA
 * create accounts (payer, ata, owner, mint, system, token program); memo
 * program data is the raw memo bytes. No RPC, no signature: the verifier
 * checks transaction shape, not signatures.
 *
 * @param array<int, int> $signerSecretKey
 */
function build_fixture(ChargeRequest $request, array $signerSecretKey): string
{
    if (count($signerSecretKey) !== 64) {
        throw new InvalidArgumentException('signerSecretKey must be 64 bytes');
    }
    // The ed25519 public key is the trailing 32 bytes of the secret key.
    $pubBytes = '';
    for ($i = 32; $i < 64; $i += 1) {
        $pubBytes .= chr($signerSecretKey[$i] & 0xff);
    }
    $signer = PublicKey::fromBytes($pubBytes)->toBase58();

    $md = $request->methodDetails;
    $network = is_string($md['network'] ?? null) ? $md['network'] : DEFAULT_NETWORK;
    $currency = (string) $request->currency;
    $recipient = (string) $request->recipient;
    $isSol = strtoupper($currency) === 'SOL';

    $total = (int) $request->amount;
    $splits = is_array($md['splits'] ?? null) ? $md['splits'] : [];
    $splitTotal = 0;
    foreach ($splits as $split) {
        $splitTotal += (int) $split['amount'];
    }
    $primary = $total - $splitTotal;

    /** @var array<int, array{program: string, accounts: array<int, string>, data: string}> $instructions */
    $instructions = [];
    $add = static function (string $program, array $accounts, string $data) use (&$instructions): void {
        $instructions[] = ['program' => $program, 'accounts' => $accounts, 'data' => $data];
    };

    if ($isSol) {
        $add(SystemProgram::PROGRAM_ID, [$signer, $recipient], encode_uint_le(2, 4) . encode_uint_le($primary, 8));
        foreach ($splits as $split) {
            $add(SystemProgram::PROGRAM_ID, [$signer, (string) $split['recipient']], encode_uint_le(2, 4) . encode_uint_le((int) $split['amount'], 8));
            if (isset($split['memo']) && $split['memo'] !== '') {
                $add(MemoProgram::PROGRAM_ID_V2, [], (string) $split['memo']);
            }
        }
    } else {
        $mint = Mints::resolve($currency, $network) ?? $currency;
        $tokenProgram = is_string($md['tokenProgram'] ?? null) && $md['tokenProgram'] !== ''
            ? $md['tokenProgram']
            : Mints::tokenProgramFor($currency, $network);
        $decimals = isset($md['decimals']) ? (int) $md['decimals'] : 6;
        $sourceAta = Mints::deriveAta($signer, $mint, $tokenProgram);
        $destAta = Mints::deriveAta($recipient, $mint, $tokenProgram);
        $add($tokenProgram, [$sourceAta, $mint, $destAta, $signer], chr(12) . encode_uint_le($primary, 8) . chr($decimals));
        foreach ($splits as $split) {
            $sr = (string) $split['recipient'];
            $sata = Mints::deriveAta($sr, $mint, $tokenProgram);
            if (($split['ataCreationRequired'] ?? false) === true) {
                $add(AssociatedTokenProgram::PROGRAM_ID, [$signer, $sata, $sr, $mint, SystemProgram::PROGRAM_ID, $tokenProgram], chr(1));
            }
            $add($tokenProgram, [$sourceAta, $mint, $sata, $signer], chr(12) . encode_uint_le((int) $split['amount'], 8) . chr($decimals));
            if (isset($split['memo']) && $split['memo'] !== '') {
                $add(MemoProgram::PROGRAM_ID_V2, [], (string) $split['memo']);
            }
        }
    }

    // Account key set: signer (lone signer / fee payer) at index 0, then every
    // instruction account and program id in first-seen order. The verifier
    // reads layout by index, so a single read-only-unsigned tail suffices.
    $keys = [$signer];
    $seen = [$signer => true];
    foreach ($instructions as $ix) {
        foreach ($ix['accounts'] as $a) {
            if (!isset($seen[$a])) {
                $seen[$a] = true;
                $keys[] = $a;
            }
        }
        if (!isset($seen[$ix['program']])) {
            $seen[$ix['program']] = true;
            $keys[] = $ix['program'];
        }
    }
    $index = array_flip($keys);

    $blockhash = is_string($md['recentBlockhash'] ?? null) && $md['recentBlockhash'] !== ''
        ? $md['recentBlockhash']
        : str_repeat('1', 32);
    try {
        $blockhashBytes = PublicKey::fromBase58($blockhash)->toBytes();
    } catch (Throwable) {
        $blockhashBytes = PublicKey::fromBase58(str_repeat('1', 32))->toBytes();
    }

    $signerCount = 1;
    $readonlyUnsigned = count($keys) - 1;

    $message = chr($signerCount) . chr(0) . chr($readonlyUnsigned);
    $message .= compact_u16(count($keys));
    foreach ($keys as $k) {
        $message .= PublicKey::fromBase58($k)->toBytes();
    }
    $message .= $blockhashBytes;
    $message .= compact_u16(count($instructions));
    foreach ($instructions as $ix) {
        $message .= chr($index[$ix['program']]);
        $message .= compact_u16(count($ix['accounts']));
        foreach ($ix['accounts'] as $a) {
            $message .= chr($index[$a]);
        }
        $message .= compact_u16(strlen($ix['data']));
        $message .= $ix['data'];
    }

    $signatures = compact_u16($signerCount) . str_repeat(chr(0), 64 * $signerCount);
    return base64_encode($signatures . $message);
}

// ── x402-exact envelope oracle ───────────────────────────────────────────
//
// Canonical CAIP-2 chain identifiers (rust types.rs / PHP Adapter).
const X402_SOLANA_MAINNET = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp';
const X402_SOLANA_DEVNET  = 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1';
const X402_SOLANA_TESTNET = 'solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z';
const X402_VERSION_V1     = 1;
const X402_VERSION_V2     = 2;
const X402_EXACT_SCHEME   = 'exact';

/**
 * Normalize a legacy v1 network slug (or any cluster slug / CAIP-2 id) to its
 * canonical CAIP-2 chain identifier. Mirrors the rust spine
 * `caip2_network_for_cluster` and PHP Adapter::caip2NetworkForCluster
 * (localnet collapses to the devnet CAIP-2 id by convention).
 */
function x402_caip2_for_cluster(string $cluster): string
{
    return match ($cluster) {
        X402_SOLANA_MAINNET, 'solana', 'mainnet', 'mainnet-beta' => X402_SOLANA_MAINNET,
        X402_SOLANA_TESTNET, 'testnet', 'solana-testnet'         => X402_SOLANA_TESTNET,
        'devnet', 'localnet'                                     => X402_SOLANA_DEVNET,
        X402_SOLANA_DEVNET, 'solana-devnet'                      => X402_SOLANA_DEVNET,
        default                                                  => X402_SOLANA_MAINNET,
    };
}

/**
 * Decode a base64(JSON) x402 payment header into the conformance envelope
 * shape oracle. Mirrors the TS reference decodeEnvelopeShape: hasAccepted is
 * true iff a v2 `accepted` object is present, payloadHasTransaction is true
 * iff payload.transaction is a non-empty string, top-level scheme/network are
 * echoed only when present (v1), and accepted* echo the offer (v2).
 *
 * @param array<string, mixed> $envelope
 * @return array<string, mixed>
 */
function x402_envelope_shape(array $envelope): array
{
    $accepted = $envelope['accepted'] ?? null;
    $payload = $envelope['payload'] ?? null;
    $transaction = is_array($payload) ? ($payload['transaction'] ?? null) : null;

    $shape = [
        'x402Version' => $envelope['x402Version'] ?? null,
        'hasAccepted' => is_array($accepted),
        'payloadHasTransaction' => is_string($transaction) && $transaction !== '',
    ];

    if (array_key_exists('scheme', $envelope)) {
        $shape['scheme'] = $envelope['scheme'];
    }
    if (array_key_exists('network', $envelope)) {
        $shape['network'] = $envelope['network'];
    }
    if (is_array($accepted)) {
        if (array_key_exists('scheme', $accepted)) {
            $shape['acceptedScheme'] = $accepted['scheme'];
        }
        if (array_key_exists('network', $accepted)) {
            $shape['acceptedNetwork'] = $accepted['network'];
        }
        if (array_key_exists('asset', $accepted)) {
            $shape['acceptedAsset'] = $accepted['asset'];
        }
        if (array_key_exists('payTo', $accepted)) {
            $shape['acceptedPayTo'] = $accepted['payTo'];
        }
        if (array_key_exists('amount', $accepted)) {
            $shape['acceptedAmount'] = $accepted['amount'];
        }
    }

    // Surface the v2 `extensions` object (rust PaymentExtensions; TS reference
    // decodeEnvelopeShape). hasExtensions is false when the key is absent OR
    // present-but-empty (a conforming echo-and-omit build never emits `{}`,
    // but the decoder must still classify a stray `{}` as "no extensions").
    $extensions = $envelope['extensions'] ?? null;
    if (is_array($extensions)) {
        $keys = array_map('strval', array_keys($extensions));
        sort($keys);
        $shape['hasExtensions'] = $keys !== [];
        $shape['extensionKeys'] = $keys;
        $pid = $extensions[PaymentExtensions::PAYMENT_IDENTIFIER_KEY] ?? null;
        $shape['hasPaymentIdentifier'] = is_array($pid);
        if (is_array($pid)) {
            $info = is_array($pid['info'] ?? null) ? $pid['info'] : [];
            if (array_key_exists('required', $info)) {
                $shape['paymentIdentifierRequired'] = $info['required'];
            }
            if (array_key_exists('id', $info)) {
                $shape['paymentIdentifierId'] = $info['id'];
            }
        }
    } else {
        // No extensions object on the wire (conforming echo-and-omit). Pin the
        // absence explicitly so a vector can assert it.
        $shape['hasExtensions'] = false;
        $shape['hasPaymentIdentifier'] = false;
        $shape['extensionKeys'] = [];
    }

    return $shape;
}

/**
 * Decode and verify an x402 payment header against a server route, mirroring
 * the PHP x402 Adapter's envelope parse/dispatch/gate
 * (Protocols\X402\Adapter::verifyAndSettle) and the rust spine version
 * dispatch + network gate + v2 accepted-vs-route comparison. RPC-free: the
 * inner signed-transaction 11-rule structural check and broadcast are out of
 * scope for the envelope oracle (the harness matrix owns those), so a
 * structurally valid, route-matching envelope is accepted here.
 *
 * Throws InvalidArgumentException with a message classify_reject maps onto the
 * shared reject vocabulary (unsupported-version, wrong-network, invalid-payload).
 *
 * @param array<string, mixed> $route
 * @return array<string, mixed> the decoded envelope shape on accept
 */
function verify_x402_header(string $header, array $route): array
{
    $decoded = base64_decode($header, true);
    if ($decoded === false || $decoded === '') {
        throw new InvalidArgumentException('invalid payload: undecodable x402 payment header');
    }
    try {
        $envelope = json_decode($decoded, true, flags: JSON_THROW_ON_ERROR);
    } catch (Throwable) {
        throw new InvalidArgumentException('invalid payload: x402 payment header is not JSON');
    }
    if (!is_array($envelope)) {
        throw new InvalidArgumentException('invalid payload: x402 envelope must be a JSON object');
    }

    $version = $envelope['x402Version'] ?? null;
    $expectedNetwork = x402_caip2_for_cluster((string) ($route['network'] ?? ''));

    if ($version === X402_VERSION_V2) {
        // v2: `accepted` is required and structurally matched against the
        // server route (network/amount/payTo/asset), mirroring the Adapter
        // v2 identity-key match and the rust verify_envelope_payload.
        $accepted = $envelope['accepted'] ?? null;
        if (!is_array($accepted)) {
            throw new InvalidArgumentException('invalid payload: v2 envelope missing accepted');
        }
        $acceptedNetwork = is_string($accepted['network'] ?? null) ? $accepted['network'] : '';
        if ($acceptedNetwork !== $expectedNetwork) {
            throw new InvalidArgumentException(
                "Network mismatch: expected $expectedNetwork, got $acceptedNetwork",
            );
        }
        $acceptedAmount = is_string($accepted['amount'] ?? null) ? $accepted['amount'] : '';
        if ($acceptedAmount !== (string) ($route['amount'] ?? '')) {
            throw new InvalidArgumentException(
                'Amount mismatch: expected ' . ($route['amount'] ?? '') . ", got $acceptedAmount",
            );
        }
        $acceptedPayTo = is_string($accepted['payTo'] ?? null) ? $accepted['payTo'] : '';
        if ($acceptedPayTo !== (string) ($route['recipient'] ?? '')) {
            throw new InvalidArgumentException(
                'Recipient mismatch: credential claims a different recipient',
            );
        }
        $acceptedAsset = is_string($accepted['asset'] ?? null) ? $accepted['asset'] : '';
        if ($acceptedAsset !== (string) ($route['currency'] ?? '')) {
            throw new InvalidArgumentException(
                'Currency mismatch: expected ' . ($route['currency'] ?? '') . ", got $acceptedAsset",
            );
        }

        // Extensions reject gate: when the route requires a payment-identifier,
        // the echoed credential must carry a valid `pay_`-shaped id. Missing,
        // empty, or pattern-violating ids are rejected (coinbase spec: 400).
        // Mirrors the PHP Adapter::verifyAndSettle gate + rust
        // requires_payment_identifier reject-when-required-and-missing. This is
        // a v2-only concept, so it lives inside the v2 branch.
        if (($route['requiresPaymentIdentifier'] ?? false) === true) {
            $echoed = PaymentExtensions::fromArray(
                is_array($envelope['extensions'] ?? null) ? $envelope['extensions'] : null,
            );
            $info = $echoed?->paymentIdentifier?->info;
            if ($info === null || $info->id === null || $info->id === '') {
                throw new InvalidArgumentException(
                    'payment-identifier required but credential echoed no id',
                );
            }
            if (!$info->hasValidId()) {
                throw new InvalidArgumentException(
                    'payment-identifier id is invalid: ' . $info->id
                    . ' does not match ^[A-Za-z0-9_-]{16,128}$',
                );
            }
        }
    } elseif ($version === X402_VERSION_V1) {
        // v1 (legacy): no `accepted` object. The envelope commits only to a
        // top-level scheme + plain network slug (siblings of `payload`). Bind
        // scheme === "exact" and normalize the plain slug to a CAIP-2 chain id,
        // gating it against the server route. Mirrors the PHP Adapter
        // matchLegacyCredential + the rust v1 parse arm (server/exact.rs).
        $scheme = $envelope['scheme'] ?? null;
        if ($scheme !== X402_EXACT_SCHEME) {
            throw new InvalidArgumentException(
                'invalid payload: unsupported scheme ' . (is_scalar($scheme) ? (string) $scheme : 'unknown'),
            );
        }
        $network = is_string($envelope['network'] ?? null) ? $envelope['network'] : '';
        if ($network === '') {
            throw new InvalidArgumentException('invalid payload: v1 envelope missing network');
        }
        $normalized = x402_caip2_for_cluster($network);
        if ($normalized !== $expectedNetwork) {
            throw new InvalidArgumentException(
                "Network mismatch: expected $expectedNetwork, got $network",
            );
        }
    } else {
        // Genuinely-unknown versions are rejected (rust exact.rs / Adapter
        // unsupported_x402_version arm). Adding v1 support must not widen the
        // version gate.
        throw new InvalidArgumentException(
            'unsupported x402 version: ' . (is_scalar($version) ? (string) $version : 'unknown'),
        );
    }

    $payload = $envelope['payload'] ?? null;
    $transaction = is_array($payload) ? ($payload['transaction'] ?? null) : null;
    if (!is_string($transaction) || $transaction === '') {
        throw new InvalidArgumentException('invalid payload: missing transaction proof');
    }

    return x402_envelope_shape($envelope);
}

/**
 * Drive the x402-exact intent. PHP is server-only, so build vectors are
 * unsupported (no client envelope builder) and verify vectors run the
 * envelope-level verify against the vector's server route.
 *
 * @param array<string, mixed> $vector
 * @return array<string, mixed>
 */
function run_x402_vector(array $vector): array
{
    $id = Json::optionalString($vector['id'] ?? null, 'id');
    $mode = Json::optionalString($vector['mode'] ?? null, 'mode');
    $input = is_array($vector['input'] ?? null) ? Json::object($vector['input'], 'input') : [];

    if ($mode === 'build-transaction') {
        // PHP ships no client-side x402 envelope builder; build vectors are
        // out of scope for a server-only SDK.
        return [
            'id' => $id,
            'outcome' => 'unsupported-mode',
            'error' => 'php is server-only: x402 build-transaction is not supported (no client envelope builder)',
        ];
    }

    if ($mode !== 'verify-transaction') {
        return [
            'id' => $id,
            'outcome' => 'unsupported-mode',
            'error' => 'unsupported x402 mode: ' . $mode,
        ];
    }

    $header = Json::optionalString($input['x402PaymentHeader'] ?? null, 'x402PaymentHeader');
    if ($header === '') {
        throw new InvalidArgumentException('invalid payload: x402 verify vector missing input.x402PaymentHeader');
    }
    foreach (['x402ServerNetwork', 'x402ServerRecipient', 'x402ServerCurrency', 'x402ServerAmount'] as $key) {
        if (!array_key_exists($key, $input)) {
            throw new InvalidArgumentException('invalid payload: x402 verify vector missing server route');
        }
    }
    $route = [
        'network' => Json::optionalString($input['x402ServerNetwork'] ?? null, 'x402ServerNetwork'),
        'recipient' => Json::optionalString($input['x402ServerRecipient'] ?? null, 'x402ServerRecipient'),
        'currency' => Json::optionalString($input['x402ServerCurrency'] ?? null, 'x402ServerCurrency'),
        'amount' => Json::optionalString($input['x402ServerAmount'] ?? null, 'x402ServerAmount'),
        'requiresPaymentIdentifier' => ($input['x402ServerRequiresPaymentIdentifier'] ?? null) === true,
    ];

    $shape = verify_x402_header($header, $route);
    return [
        'id' => $id,
        'outcome' => 'accept',
        'x402EnvelopeShape' => $shape,
    ];
}

/**
 * @param array<string, mixed> $input
 * @return array<string, mixed>
 */
function run_canonical_bytes(array $input): array
{
    $exactBytes = [];

    if (array_key_exists('value', $input)) {
        $canonicalJson = Json::canonicalize($input['value']);
        $exactBytes['canonicalJson'] = $canonicalJson;
        $exactBytes['base64Url'] = Base64Url::encode($canonicalJson);
    }

    $enc = $input['encodeBase64Url'] ?? null;
    if (is_array($enc)) {
        $hex = $enc['hexBytes'] ?? null;
        $utf8 = $enc['utf8'] ?? null;
        if (is_string($hex) && $hex !== '') {
            $bytes = hex2bin($hex);
            if ($bytes === false) {
                throw new InvalidArgumentException('invalid hexBytes');
            }
            $ints = [];
            for ($i = 0, $n = strlen($bytes); $i < $n; $i += 1) {
                $ints[] = ord($bytes[$i]);
            }
            $exactBytes['bytes'] = $ints;
            $exactBytes['base64Url'] = Base64Url::encode($bytes);
        } elseif (is_string($utf8)) {
            $exactBytes['base64Url'] = Base64Url::encode($utf8);
        }
    }

    $cid = $input['challengeId'] ?? null;
    if (is_array($cid)) {
        // base64url(HMAC-SHA256(secret, realm|method|intent|request|expires|
        // digest|opaque)); absent optionals join as empty strings. Drives the
        // production SDK derivation (Challenge::computeId), mirroring rust
        // compute_challenge_id (protocol/core/challenge.rs).
        $exactBytes['base64Url'] = Challenge::computeId(
            Json::optionalString($cid['secretKey'] ?? null, 'challengeId.secretKey'),
            Json::optionalString($cid['realm'] ?? null, 'challengeId.realm'),
            Json::optionalString($cid['method'] ?? null, 'challengeId.method'),
            Json::optionalString($cid['intent'] ?? null, 'challengeId.intent'),
            Json::optionalString($cid['request'] ?? null, 'challengeId.request'),
            is_string($cid['expires'] ?? null) ? $cid['expires'] : '',
            is_string($cid['digest'] ?? null) ? $cid['digest'] : '',
            is_string($cid['opaque'] ?? null) ? $cid['opaque'] : null,
        );
    }

    return $exactBytes;
}

/**
 * @param array<string, mixed> $vector
 * @return array<string, mixed>
 */
function run_vector(array $vector): array
{
    $id = Json::optionalString($vector['id'] ?? null, 'id');
    $mode = Json::optionalString($vector['mode'] ?? null, 'mode');
    $intent = Json::optionalString($vector['intent'] ?? null, 'intent');
    $input = is_array($vector['input'] ?? null) ? Json::object($vector['input'], 'input') : [];

    // x402-exact: the oracle is the decoded envelope shape, not a tx shape.
    if ($intent === 'x402-exact') {
        return run_x402_vector($vector);
    }

    switch ($mode) {
        case 'canonical-bytes':
            return [
                'id' => $id,
                'outcome' => 'accept',
                'exactBytes' => run_canonical_bytes($input),
            ];

        case 'verify-transaction':
            $request = flatten_request(is_array($input['request'] ?? null) ? Json::object($input['request'], 'request') : []);
            $transaction = $input['transaction'] ?? null;
            if (!is_string($transaction) || $transaction === '') {
                // No wire transaction pinned: the verifier is the system
                // under test, so the runner assembles the wire fixture from
                // the request + signer (exactly as the Ruby runner does) and
                // verifies it. PHP ships no client build path, but a fixture
                // builder is not a client SDK surface; it only feeds the
                // server verifier deterministic, RPC-free input.
                $secret = $input['signerSecretKey'] ?? null;
                if (!is_array($secret)) {
                    return [
                        'id' => $id,
                        'outcome' => 'unsupported-mode',
                        'error' => 'php verify-transaction without a pinned input.transaction requires input.signerSecretKey to assemble the fixture',
                    ];
                }
                $transaction = build_fixture($request, array_map('intval', $secret));
            }
            verify_transaction($request, $transaction);
            return [
                'id' => $id,
                'outcome' => 'accept',
                'transactionShape' => shape_from_transaction($transaction),
            ];

        case 'build-transaction':
            // PHP ships no client-side transaction build path; build vectors
            // are out of scope for a server-only SDK.
            return [
                'id' => $id,
                'outcome' => 'unsupported-mode',
                'error' => 'php is server-only: build-transaction is not supported (no client build path)',
            ];

        default:
            return [
                'id' => $id,
                'outcome' => 'unsupported-mode',
                'error' => 'unsupported mode: ' . $mode,
            ];
    }
}

try {
    $vector = json_decode(read_stdin(), true, flags: JSON_THROW_ON_ERROR);
    if (!is_array($vector)) {
        throw new InvalidArgumentException('vector must be a JSON object');
    }
    $vector = Json::object($vector, 'vector');
    $id = Json::optionalString($vector['id'] ?? null, 'id');
    try {
        emit(run_vector($vector));
    } catch (Throwable $error) {
        $message = $error->getMessage();
        $result = [
            'id' => $id,
            'outcome' => 'reject',
            'error' => $message,
        ];
        $rejectCode = classify_reject($message);
        if ($rejectCode !== null) {
            $result['rejectCode'] = $rejectCode;
        }
        emit($result);
    }
} catch (Throwable $fatal) {
    fwrite(STDERR, 'php conformance runner fatal: ' . $fatal->getMessage() . "\n");
    exit(1);
}
