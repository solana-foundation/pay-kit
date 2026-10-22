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
 * (PayKit\Protocols\X402\Adapter) and the canonical-JSON / base64url wire
 * encoders, but NO client-side transaction builder. Consequently:
 *
 *   - canonical-bytes        -> JCS + base64url + challenge-id derivation.
 *   - verify-transaction     -> the real charge verifier over the vector's
 *                               pinned transaction, request passed verbatim.
 *                               A vector with no pinned transaction needs a
 *                               client build first: unsupported, the runner
 *                               never fabricates a transaction.
 *   - x402 verify            -> Adapter::verifyPaymentHeader, the SDK's
 *                               pre-broadcast verification (version dispatch,
 *                               offer binding, extensions gate, structural
 *                               transaction verifier) against a PayKit Config
 *                               built from the vector route and the fixture
 *                               RPC. Nothing is signed or broadcast.
 *   - build-transaction      -> unsupported-mode (no client build path).
 *
 * The runner fills no defaults, resolves no token programs or decimals and
 * applies no field precedence (harness/expectations/RULINGS.md).
 */

error_reporting(error_reporting() & ~E_DEPRECATED & ~E_USER_DEPRECATED);
ini_set('display_errors', 'stderr');

require __DIR__ . '/../vendor/autoload.php';

use Brick\Math\BigDecimal;
use Nyholm\Psr7\Factory\Psr17Factory;
use PayKit\Config;
use PayKit\Gate;
use PayKit\Operator;
use PayKit\PayCore\Network;
use PayKit\PayCore\Solana\Mints;
use PayKit\PayCore\Solana\TransactionWire;
use PayKit\PayCore\Stablecoin;
use PayKit\PayCore\Wire\Base64Url;
use PayKit\PayCore\Wire\Json;
use PayKit\Price;
use PayKit\Protocol;
use PayKit\Protocols\Mpp\Core\Challenge;
use PayKit\Protocols\Mpp\Core\Credential;
use PayKit\Protocols\Mpp\Intent\ChargeRequest;
use PayKit\Protocols\Mpp\MppConfig;
use PayKit\Protocols\Mpp\Server\SolanaChargeTransactionVerifier;
use PayKit\Protocols\X402\Adapter as X402Adapter;
use PayKit\Protocols\X402\Exact\PaymentExtensions;
use PayKit\Protocols\X402\X402Config;
use PayKit\Signer;
use SolanaPhpSdk\Programs\MemoProgram;
use SolanaPhpSdk\Programs\SystemProgram;
use SolanaPhpSdk\Programs\TokenProgram;

const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111';

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

    $tx = TransactionWire::deserialize($wire);
    if ($tx->addressTableLookups() !== []) {
        throw new InvalidArgumentException('v0 address lookup tables are not supported');
    }
    $accountKeys = $tx->staticAccountKeys();
    $instructions = array_map(
        static fn (object $ix): array => [
            'programIdIndex' => $ix->programIdIndex,
            'accounts' => $ix->accountKeyIndexes,
            'data' => $ix->data,
        ],
        $tx->compiledInstructions(),
    );

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
        // Charge verification policy and client challenge checks (mirrors
        // the block at the top of harness/src/conformance/reject.ts).
        '/fee payer (token account )?cannot fund/i' => 'fee-payer-is-funds-source',
        '/primary amount is zero after splits|split amounts exceed/i' => 'splits-exceed-amount',
        '/splits exceed maximum/i' => 'too-many-splits',
        '/ata creation owner is not authorized|unsupported compute budget|unexpected_signer/i' => 'unexpected-instruction',
        '/atacreationrequired requires|unsupported challenge network|invalid amount|requires feepayerkey/i' => 'invalid-challenge',
        '/ata creation|ata payer|transaction fee payer (must be|mismatch)|memo cannot exceed/i' => 'invalid-payload',
        // x402 v2: the credential's `accepted` matches no offered requirement.
        '/charge_request_mismatch|accepted payment requirement does not match/i' => 'accepted-mismatch',
        '/no memo instruction found|memo_mismatch|memo_count/i' => 'invalid-payload',
        '/compute unit price .*exceeds (maximum|cap)/i' => 'compute-price-over-cap',
        '/compute unit limit .*exceeds (maximum|cap)/i' => 'compute-limit-over-cap',
        '/fee payer cannot authorize/i' => 'fee-payer-not-authority',
        '/fee payer .* (funding source|funds source)/i' => 'fee-payer-is-funds-source',
        '/splits consume the entire amount/i' => 'splits-exceed-amount',
        '/too many splits/i' => 'too-many-splits',
        '/no matching (spl )?(token )?(transfer|transferchecked|sol transfer)/i' => 'no-matching-transfer',
        '/unexpected .* (instruction|transfer)/i' => 'unexpected-instruction',
        '/share one funding authority/i' => 'mixed-funding-authority',
        '/unexpected signer/i' => 'unexpected-signer',
        '/amount .* (mismatch|does not match)/i' => 'amount-mismatch',
        // x402 exact structural verifier tokens (invalid_exact_svm_payload_*).
        '/compute_price_instruction_too_high/' => 'compute-price-over-cap',
        '/fee_payer_transferring_funds|fee_payer_in_instruction_accounts/' => 'fee-payer-not-authority',
        '/no_transfer_instruction|recipient_mismatch|mint_mismatch/' => 'no-matching-transfer',
        '/amount_mismatch/' => 'amount-mismatch',
        '/unknown_(fourth|fifth|sixth|optional)_instruction/' => 'unexpected-instruction',
        // x402-exact reject vocabulary. Ordered before the generic
        // invalid/payload fallback so an unknown version or a network
        // mismatch classifies precisely (mirrors reject.ts).
        '/unsupported[ _]x402[ _]version/i' => 'unsupported-version',
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
    foreach (['x402ServerNetwork', 'x402ServerRecipient', 'x402ServerCurrency', 'x402ServerAmount', 'x402ServerFeePayerSecretKey', 'rpcUrl'] as $key) {
        if (!array_key_exists($key, $input)) {
            throw new InvalidArgumentException('x402 verify vector missing input.' . $key);
        }
    }

    // Configure the route the way a PayKit operator would. The SDK prices in
    // a Gate (human amount of a settlement stablecoin) and scales it by the
    // coin's decimals, so the route's atomic amount maps back with them;
    // the stablecoin is the table entry for the route's mint.
    $network = match (Json::optionalString($input['x402ServerNetwork'], 'x402ServerNetwork')) {
        'mainnet', 'mainnet-beta', 'solana' => Network::SolanaMainnet,
        'localnet' => Network::SolanaLocalnet,
        default => Network::SolanaDevnet,
    };
    $currency = Json::optionalString($input['x402ServerCurrency'], 'x402ServerCurrency');
    $symbol = Mints::symbolFor($currency, $network->mintsLabel());
    $coin = $symbol === null ? null : Stablecoin::tryFrom($symbol);
    if ($coin === null) {
        return [
            'id' => $id,
            'outcome' => 'unsupported-mode',
            'error' => 'php x402 server only settles built-in stablecoins; ' . $currency . ' is not one',
        ];
    }
    $amount = BigDecimal::ofUnscaledValue(Json::optionalString($input['x402ServerAmount'], 'x402ServerAmount'), $coin->decimals());
    $secret = json_encode($input['x402ServerFeePayerSecretKey'], JSON_THROW_ON_ERROR);
    $config = new Config(
        network: $network,
        accept: [Protocol::X402],
        stablecoins: [$coin],
        rpcUrl: Json::optionalString($input['rpcUrl'], 'rpcUrl'),
        operator: new Operator(
            recipient: Json::optionalString($input['x402ServerRecipient'], 'x402ServerRecipient'),
            signer: Signer::json($secret),
            feePayer: true,
        ),
        x402: new X402Config(
            advertisedExtensions: ($input['x402ServerRequiresPaymentIdentifier'] ?? null) === true
                ? [PaymentExtensions::PAYMENT_IDENTIFIER_KEY => ['info' => ['required' => true]]]
                : null,
        ),
        mpp: new MppConfig(challengeBindingSecret: 'unused-x402-conformance-secret-0123456789'),
        preflight: false,
    );
    $adapter = new X402Adapter($config, new \PayKit\Store\MemoryStore());
    $gate = new Gate(amount: Price::usd($amount, $coin));

    // Pre-broadcast verification only. The route's extra.memo is the SDK's
    // resource binding: advertised as extra.memo and enforced on the
    // transaction.
    $memo = array_key_exists('x402ServerMemo', $input)
        ? Json::optionalString($input['x402ServerMemo'], 'x402ServerMemo')
        : null;
    $adapter->verifyPaymentHeader($gate, $header, $memo);

    $decoded = json_decode((string) base64_decode($header, true), true, flags: JSON_THROW_ON_ERROR);
    return [
        'id' => $id,
        'outcome' => 'accept',
        'x402EnvelopeShape' => x402_envelope_shape(is_array($decoded) ? $decoded : []),
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
            $transaction = $input['transaction'] ?? null;
            if (!is_string($transaction) || $transaction === '') {
                return [
                    'id' => $id,
                    'outcome' => 'unsupported-mode',
                    'error' => 'php is server-only: this verify vector pins no transaction, so it needs a client build first and php has no client build path',
                ];
            }
            // The request is handed to the SDK verbatim.
            $request = ChargeRequest::fromArray(is_array($input['request'] ?? null) ? Json::object($input['request'], 'request') : []);
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

/**
 * One v1 vector to one RunnerResult; an SDK error is a classified reject.
 *
 * @param array<string, mixed> $vector
 * @return array<string, mixed>
 */
function result_for(array $vector): array
{
    $vector = Json::object($vector, 'vector');
    $id = Json::optionalString($vector['id'] ?? null, 'id');
    try {
        return run_vector($vector);
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
        return $result;
    }
}

/** Intents this runner implements; pkc checks them against harness/expectations/php.toml. */
const CONFORMANCE_INTENTS = ['charge', 'x402-exact'];

/**
 * Testee ABI v2 (harness/README.md): newline JSON {id, op, input} in,
 * {id, ok, result | error} out, one long-lived process. `input` is the v1
 * vector and `result` the v1 RunnerResult.
 */
function serve(): void
{
    while (($line = fgets(STDIN)) !== false) {
        if (trim($line) === '') {
            continue;
        }
        try {
            $request = json_decode($line, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $error) {
            emit(['id' => null, 'ok' => false, 'error' => 'bad-request', 'detail' => $error->getMessage()]);
            fflush(STDOUT);
            continue;
        }
        $requestId = is_array($request) ? ($request['id'] ?? null) : null;
        $op = is_array($request) ? ($request['op'] ?? null) : null;
        try {
            if ($op === 'capabilities') {
                $response = ['id' => $requestId, 'ok' => true, 'result' => [
                    'abi' => 2,
                    'language' => 'php',
                    'intents' => CONFORMANCE_INTENTS,
                    'honoursClock' => false,
                ]];
            } elseif (in_array($op, ['build', 'verify', 'canonical-bytes'], true)) {
                $input = $request['input'] ?? null;
                if (!is_array($input)) {
                    throw new InvalidArgumentException('input must be a JSON object');
                }
                $response = ['id' => $requestId, 'ok' => true, 'result' => result_for($input)];
            } else {
                $response = ['id' => $requestId, 'ok' => false, 'error' => 'unknown-op', 'detail' => (string) json_encode($op)];
            }
        } catch (Throwable $error) {
            $response = ['id' => $requestId, 'ok' => false, 'error' => 'bad-request', 'detail' => $error->getMessage()];
        }
        emit($response);
        fflush(STDOUT);
    }
}

try {
    $arguments = $_SERVER['argv'] ?? [];
    if (is_array($arguments) && in_array('--serve', $arguments, true)) {
        serve();
        exit(0);
    }
    $vector = json_decode(read_stdin(), true, flags: JSON_THROW_ON_ERROR);
    if (!is_array($vector)) {
        throw new InvalidArgumentException('vector must be a JSON object');
    }
    emit(result_for($vector));
} catch (Throwable $fatal) {
    fwrite(STDERR, 'php conformance runner fatal: ' . $fatal->getMessage() . "\n");
    exit(1);
}
