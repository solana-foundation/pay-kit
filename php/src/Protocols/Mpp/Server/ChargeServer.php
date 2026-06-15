<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp\Server;

use Closure;
use DateTimeImmutable;
use InvalidArgumentException;
use Throwable;
use PayKit\PayCore\Solana\Mints;
use PayKit\PayCore\Wire\Base64Url;
use PayKit\Protocols\Mpp\Core\Challenge;
use PayKit\Protocols\Mpp\Core\Credential;
use PayKit\Protocols\Mpp\Core\Headers;
use PayKit\PayCore\Wire\Json;
use PayKit\Protocols\Mpp\Core\Receipt;
use PayKit\Protocols\Mpp\Intent\ChargeRequest;
use SolanaPhpSdk\Keypair\PublicKey;

/**
 * Issues charge challenges and verifies Payment credentials for a PHP server.
 */
final class ChargeServer
{
    /**
     * Minimum HMAC challenge-binding secret length in bytes. 32 bytes matches
     * the SHA-256 output length (NIST SP 800-107 guidance for HMAC-SHA256) and
     * the Rust reference (`MIN_SECRET_KEY_BYTES`); a shorter secret weakens the
     * binding that prevents challenge forgery (audit #24).
     */
    public const MIN_SECRET_KEY_BYTES = 32;

    /**
     * Maximum number of splits a challenge may carry. Mirrors Rust
     * `MAX_SPLITS` and the verifier's pre-broadcast count cap.
     */
    public const MAX_SPLITS = 8;

    /**
     * Create a charge server for one realm and payment method.
     *
     * `$blockhashProvider` is an optional `Closure(): string` invoked when
     * issuing a charge challenge. When provided, the returned blockhash is
     * embedded as `methodDetails.recentBlockhash` so the client does not need
     * an extra RPC round-trip. Throwing or returning an empty string is
     * treated as best-effort failure — the challenge is still issued without
     * a pre-fetched blockhash, and the client falls back to fetching its own.
     *
     * `$secretKey` MUST be at least {@see MIN_SECRET_KEY_BYTES} bytes. This is
     * the single chokepoint every secret flows through — env, dotenv, or an
     * Adapter-supplied value — so the floor is enforced here once (audit #24).
     *
     * When `$pinnedCurrency` / `$pinnedRecipient` / `$pinnedNetwork` /
     * `$pinnedDecimals` are set they are also used to validate issued requests
     * against the server's configured route at issuance time (audit #19). The
     * in-SDK {@see \PayKit\Protocols\Mpp\Adapter} always supplies these from
     * route config so the match checks fire unconditionally on the real route,
     * matching Rust `validate_charge_request`. Callers constructing this server
     * directly may leave them null to keep the structural-only behavior.
     */
    public function __construct(
        private readonly string $secretKey,
        private readonly string $realm,
        private readonly string $method = 'solana',
        private readonly ?Closure $blockhashProvider = null,
        private readonly ?string $pinnedCurrency = null,
        private readonly ?string $pinnedRecipient = null,
        private readonly ?string $pinnedNetwork = null,
        private readonly ?int $pinnedDecimals = null,
    ) {
        self::assertStrongSecretKey($secretKey);
        if ($realm === '') {
            throw new InvalidArgumentException('realm is required');
        }
    }

    /**
     * Reject HMAC secrets below the {@see MIN_SECRET_KEY_BYTES} floor.
     *
     * Shared by every secret-entry path (env / dotenv / Adapter) so a weak
     * value cannot slip in regardless of where it originated (audit #24).
     */
    public static function assertStrongSecretKey(string $secretKey): void
    {
        if (strlen($secretKey) < self::MIN_SECRET_KEY_BYTES) {
            throw new InvalidArgumentException(sprintf(
                'mpp challenge-binding secret must be at least %d bytes of '
                . 'cryptographically-random data (e.g. `openssl rand -base64 32`); '
                . 'got %d bytes (audit #24)',
                self::MIN_SECRET_KEY_BYTES,
                strlen($secretKey),
            ));
        }
    }

    /**
     * Create a signed MPP charge challenge.
     *
     * Validates the request before signing (audit #19/#21/#38): `createChallenge`
     * is a public HMAC-signing oracle, so an un-vetted request would let a buggy
     * or hostile caller mint a cryptographically-valid challenge with off-route
     * or malformed contents. The validation mirrors Rust `validate_charge_request`.
     */
    public function createChallenge(ChargeRequest $request, string $expires = '', string $digest = '', ?string $opaque = null): Challenge
    {
        $this->validateChargeRequest($request);

        return Challenge::withSecret(
            secretKey: $this->secretKey,
            realm: $this->realm,
            method: $this->method,
            intent: 'charge',
            request: $this->injectRecentBlockhash($request)->toArray(),
            expires: $expires,
            digest: $digest,
            opaque: $opaque,
        );
    }

    /**
     * Validate a charge request before it is HMAC-signed at issuance.
     *
     * Mirrors Rust `validate_charge_request` (rust/crates/mpp/src/server/charge.rs):
     *
     *  - recipient is present and parses as a Solana pubkey;
     *  - when the server is pinned to a currency/recipient, the request matches
     *    it (audit #19 — the issuance-side counterpart of the verify-time pin);
     *  - methodDetails.network matches the pinned network when one is configured;
     *  - methodDetails.decimals matches the pinned decimals when both are present
     *    (Rust pins decimals too — charge.rs `validate_charge_request`);
     *  - splits are well-formed (audit #21): count <= MAX_SPLITS, each recipient
     *    parses as a pubkey, each amount is a positive base-unit integer, no
     *    duplicate recipients, and the split sum does not exceed the total;
     *  - no split both equals the primary recipient AND requires fee-sponsored
     *    ATA creation (audit #38 — the ATA-recreate slow-drain shape).
     *
     * `ChargeRequest::__construct` already guarantees a positive base-unit
     * `amount` and a non-empty `currency`, so those are not re-checked here.
     */
    private function validateChargeRequest(ChargeRequest $request): void
    {
        if ($request->recipient === '') {
            throw new InvalidArgumentException('recipient is required');
        }
        self::assertPubkey($request->recipient, 'recipient');

        if ($this->pinnedCurrency !== null && strcasecmp($request->currency, $this->pinnedCurrency) !== 0) {
            throw new InvalidArgumentException('charge request currency does not match server configuration');
        }
        if ($this->pinnedRecipient !== null && $request->recipient !== $this->pinnedRecipient) {
            throw new InvalidArgumentException('charge request recipient does not match server configuration');
        }

        $methodDetails = is_array($request->methodDetails) ? $request->methodDetails : [];
        if ($this->pinnedNetwork !== null) {
            $network = $methodDetails['network'] ?? null;
            if (is_string($network) && $network !== '' && $network !== $this->pinnedNetwork) {
                throw new InvalidArgumentException('charge request network does not match server configuration');
            }
        }
        if ($this->pinnedDecimals !== null) {
            $decimals = $methodDetails['decimals'] ?? null;
            if (is_int($decimals) && $decimals !== $this->pinnedDecimals) {
                throw new InvalidArgumentException('charge request decimals does not match server configuration');
            }
        }

        $this->validateSplits($methodDetails, $request);
    }

    /**
     * Validate the `methodDetails.splits` list at issuance (audit #21/#38).
     *
     * @param array<string, mixed> $methodDetails
     */
    private function validateSplits(array $methodDetails, ChargeRequest $request): void
    {
        $splits = $methodDetails['splits'] ?? null;
        if ($splits === null) {
            return;
        }
        if (!is_array($splits) || !array_is_list($splits)) {
            throw new InvalidArgumentException('splits must be an array');
        }
        if (count($splits) > self::MAX_SPLITS) {
            throw new InvalidArgumentException(sprintf('too many splits (max %d)', self::MAX_SPLITS));
        }

        $totalAmount = self::parseAmount($request->amount, 'amount');
        $splitTotal = 0;
        $seenRecipients = [];
        foreach ($splits as $split) {
            if (!is_array($split) || !isset($split['recipient'], $split['amount'])) {
                throw new InvalidArgumentException('split recipient and amount are required');
            }
            $recipient = $split['recipient'];
            $amount = $split['amount'];
            if (!is_string($recipient) || !is_string($amount)) {
                throw new InvalidArgumentException('split recipient and amount must be strings');
            }
            self::assertPubkey($recipient, 'split recipient');

            $value = self::parseAmount($amount, 'split amount');
            if ($value <= 0) {
                throw new InvalidArgumentException('split amount must be a positive base-unit integer');
            }
            if (isset($seenRecipients[$recipient])) {
                throw new InvalidArgumentException('duplicate split recipient: ' . $recipient);
            }
            $seenRecipients[$recipient] = true;
            $splitTotal += $value;

            // audit #38: a fee-sponsored ATA-create for the primary recipient
            // is a slow-drain shape (close + recreate the merchant's own ATA on
            // the server's dime). Reject the combination at issuance; a primary
            // recipient appearing as a plain split (no ATA create) stays allowed.
            if ($recipient === $request->recipient && ($split['ataCreationRequired'] ?? false) === true) {
                throw new InvalidArgumentException(
                    'primary recipient cannot appear in splits with ataCreationRequired=true (audit #38)',
                );
            }
        }

        if ($splitTotal > $totalAmount) {
            throw new InvalidArgumentException('split amounts exceed total amount');
        }
    }

    private static function assertPubkey(string $value, string $label): void
    {
        try {
            new PublicKey($value);
        } catch (Throwable) {
            throw new InvalidArgumentException(sprintf('%s must be a valid Solana pubkey', $label));
        }
    }

    private static function parseAmount(string $amount, string $field): int
    {
        if ($amount === '' || !ctype_digit($amount)) {
            throw new InvalidArgumentException($field . ' must be a base-unit integer');
        }
        // Compare digit strings to stay clear of PHP_INT_MAX before the cast.
        $normalized = ltrim($amount, '0');
        $max = (string) PHP_INT_MAX;
        $overflow = strlen($normalized) > strlen($max)
            || (strlen($normalized) === strlen($max) && strcmp($normalized, $max) > 0);
        if ($overflow) {
            throw new InvalidArgumentException($field . ' exceeds PHP integer range');
        }

        return (int) $amount;
    }

    /**
     * Pre-fetch a recent blockhash and merge it into the request's method
     * details. Best-effort: a missing provider, a provider exception, or an
     * empty value all leave the request untouched.
     */
    private function injectRecentBlockhash(ChargeRequest $request): ChargeRequest
    {
        if ($this->blockhashProvider === null) {
            return $request;
        }
        $methodDetails = $request->methodDetails ?? [];
        if (isset($methodDetails['recentBlockhash']) && $methodDetails['recentBlockhash'] !== '') {
            return $request;
        }
        try {
            $blockhash = ($this->blockhashProvider)();
        } catch (Throwable) {
            return $request;
        }
        if (!is_string($blockhash) || $blockhash === '') {
            return $request;
        }

        return new ChargeRequest(
            amount: $request->amount,
            currency: $request->currency,
            recipient: $request->recipient,
            description: $request->description,
            externalId: $request->externalId,
            methodDetails: [...$methodDetails, 'recentBlockhash' => $blockhash],
        );
    }

    /**
     * Create a WWW-Authenticate header for a signed charge challenge.
     */
    public function createChallengeHeader(ChargeRequest $request, string $expires = '', string $digest = '', ?string $opaque = null): string
    {
        return Headers::formatWwwAuthenticate($this->createChallenge($request, $expires, $digest, $opaque));
    }

    /**
     * Verify an Authorization header and optionally pin it to an expected request.
     */
    public function verifyAuthorizationHeader(
        string $authorizationHeader,
        PaymentVerifier $verifier,
        ?DateTimeImmutable $now = null,
        ?ChargeRequest $expectedRequest = null,
    ): VerificationResult {
        try {
            $credential = Credential::fromAuthorizationHeader($authorizationHeader);
            $challenge = $this->challengeFromEcho($credential);
        } catch (InvalidArgumentException $error) {
            return VerificationResult::failure($error->getMessage());
        } catch (Throwable) {
            return VerificationResult::failure('invalid payment credential');
        }

        if ($challenge->method !== $this->method || $challenge->intent !== 'charge') {
            return VerificationResult::failure('challenge method or intent mismatch');
        }
        if ($challenge->realm !== $this->realm) {
            return VerificationResult::failure('challenge realm mismatch');
        }
        if (!$challenge->verify($this->secretKey)) {
            return VerificationResult::failure('challenge verification failed');
        }
        if ($challenge->isExpired($now)) {
            return VerificationResult::failure('challenge expired');
        }

        try {
            $request = ChargeRequest::fromArray($challenge->decodeRequest());
        } catch (InvalidArgumentException $error) {
            return VerificationResult::failure($error->getMessage());
        } catch (Throwable) {
            return VerificationResult::failure('invalid charge request');
        }

        // Tier-2 pinned-field backstop. Runs unconditionally so even callers
        // who do not pass $expectedRequest are protected against cross-route
        // replay on the fields fixed at server construction. Mirrors Rust
        // verify_pinned_fields (rust/crates/mpp/src/server/charge.rs:457-468),
        // which always compares the credential currency/recipient against the
        // pinned server configuration.
        if ($this->pinnedCurrency !== null && $request->currency !== $this->pinnedCurrency) {
            return VerificationResult::failure('charge request mismatch');
        }
        if ($this->pinnedRecipient !== null && $request->recipient !== $this->pinnedRecipient) {
            return VerificationResult::failure('charge request mismatch');
        }

        if ($expectedRequest !== null && !$this->matchesExpectedRequest($request, $expectedRequest)) {
            return VerificationResult::failure('charge request mismatch');
        }

        try {
            $verifierResult = $verifier->verify($credential, $challenge);
        } catch (InvalidArgumentException $error) {
            return VerificationResult::failure($error->getMessage());
        } catch (Throwable) {
            return VerificationResult::failure('payment verification failed');
        }

        return $verifierResult->ok
            ? $verifierResult->withVerified($challenge, $credential)
            : $verifierResult;
    }

    /**
     * Build the canonical 402 Payment Required response payload.
     *
     * Composes the protocol-defined headers (`cache-control`, `content-type`,
     * `www-authenticate`) and `application/problem+json` body so callers do
     * not have to reconstruct them at every protected endpoint.
     */
    public function paymentRequiredResponse(ChargeRequest $request, string $reason = 'Payment is required.', string $expires = '', string $digest = '', ?string $opaque = null): PaymentRequiredResponse
    {
        return new PaymentRequiredResponse(
            status: 402,
            headers: [
                'cache-control' => 'no-store',
                'content-type' => 'application/problem+json',
                'www-authenticate' => $this->createChallengeHeader($request, $expires, $digest, $opaque),
            ],
            body: [
                'detail' => $reason !== '' ? $reason : 'Payment is required.',
                'status' => 402,
                'title' => 'Payment Required',
                'type' => 'https://paymentauth.org/problems/payment-required',
            ],
        );
    }

    /**
     * Create a payment-receipt header from a verified result.
     *
     * Requires the result to be a successful one produced by
     * {@see verifyAuthorizationHeader()} — i.e. carrying the verified
     * challenge. For external settlement flows (where the on-chain signature
     * is only known after broadcast), use {@see createReceiptHeaderForReference()}.
     */
    public function createReceiptHeader(VerificationResult $result): string
    {
        if (!$result->ok) {
            throw new InvalidArgumentException('Cannot create a receipt for a failed verification');
        }
        if ($result->challenge === null) {
            throw new InvalidArgumentException('Verification result is missing a challenge; use createReceiptHeaderForReference()');
        }

        return $this->createReceiptHeaderForReference(
            challenge: $result->challenge,
            reference: $result->reference,
            externalId: $result->externalId,
        );
    }

    /**
     * Create a payment-receipt header after an external settlement step.
     */
    public function createReceiptHeaderForReference(Challenge $challenge, string $reference, string $externalId = ''): string
    {
        if ($reference === '') {
            throw new InvalidArgumentException('Cannot create a receipt without a settlement reference');
        }

        return Headers::formatReceipt(Receipt::success(
            method: $challenge->method,
            reference: $reference,
            challengeId: $challenge->id,
            externalId: $externalId,
        ));
    }

    private function challengeFromEcho(Credential $credential): Challenge
    {
        $echo = $credential->challenge;
        return new Challenge(
            id: $echo->id,
            realm: $echo->realm,
            method: $echo->method,
            intent: $echo->intent,
            request: $echo->request,
            expires: $echo->expires,
            digest: $echo->digest,
            opaque: $echo->opaque,
        );
    }

    private function matchesExpectedRequest(ChargeRequest $request, ChargeRequest $expectedRequest): bool
    {
        return Base64Url::encodeJson($this->comparableRequest($request->toArray())) ===
            Base64Url::encodeJson($this->comparableRequest($expectedRequest->toArray()));
    }

    /**
     * @param array<string, mixed> $request
     * @return array<string, mixed>
     */
    private function comparableRequest(array $request): array
    {
        if (isset($request['methodDetails']) && is_array($request['methodDetails'])) {
            unset($request['methodDetails']['recentBlockhash']);
        }

        return Json::object($this->canonicalizeArray($request), 'request');
    }

    /**
     * @param array<mixed> $value
     * @return array<mixed>
     */
    private function canonicalizeArray(array $value): array
    {
        if (array_is_list($value)) {
            return array_map(
                fn (mixed $nested): mixed => is_array($nested) ? $this->canonicalizeArray($nested) : $nested,
                $value,
            );
        }

        ksort($value, SORT_STRING);
        foreach ($value as $key => $nested) {
            unset($value[$key]);
            $value[(string)$key] = is_array($nested) ? $this->canonicalizeArray($nested) : $nested;
        }

        return $value;
    }
}
