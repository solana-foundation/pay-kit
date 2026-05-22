<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

use Closure;
use DateTimeImmutable;
use InvalidArgumentException;
use Throwable;
use SolanaMpp\Core\Base64Url;
use SolanaMpp\Core\Challenge;
use SolanaMpp\Core\Credential;
use SolanaMpp\Core\Headers;
use SolanaMpp\Core\Json;
use SolanaMpp\Core\Receipt;
use SolanaMpp\Intent\ChargeRequest;

/**
 * Issues charge challenges and verifies Payment credentials for a PHP server.
 */
final class ChargeServer
{
    /**
     * Create a charge server for one realm and payment method.
     *
     * `$blockhashProvider` is an optional `Closure(): string` invoked when
     * issuing a charge challenge. When provided, the returned blockhash is
     * embedded as `methodDetails.recentBlockhash` so the client does not need
     * an extra RPC round-trip. Throwing or returning an empty string is
     * treated as best-effort failure — the challenge is still issued without
     * a pre-fetched blockhash, and the client falls back to fetching its own.
     */
    public function __construct(
        private readonly string $secretKey,
        private readonly string $realm,
        private readonly string $method = 'solana',
        private readonly ?Closure $blockhashProvider = null,
    ) {
    }

    /**
     * Create a signed MPP charge challenge.
     */
    public function createChallenge(ChargeRequest $request, string $expires = '', string $digest = '', ?string $opaque = null): Challenge
    {
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
