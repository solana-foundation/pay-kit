<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

use DateTimeImmutable;
use InvalidArgumentException;
use SolanaMpp\Core\Base64Url;
use SolanaMpp\Core\Challenge;
use SolanaMpp\Core\Credential;
use SolanaMpp\Core\Headers;
use SolanaMpp\Core\Receipt;
use SolanaMpp\Intent\ChargeRequest;

final class ChargeServer
{
    public function __construct(
        private readonly string $secretKey,
        private readonly string $realm,
        private readonly string $method = 'solana',
    ) {
    }

    public function createChallenge(ChargeRequest $request, string $expires = '', string $digest = '', ?string $opaque = null): Challenge
    {
        return Challenge::withSecret(
            secretKey: $this->secretKey,
            realm: $this->realm,
            method: $this->method,
            intent: 'charge',
            request: $request->toArray(),
            expires: $expires,
            digest: $digest,
            opaque: $opaque,
        );
    }

    public function createChallengeHeader(ChargeRequest $request, string $expires = '', string $digest = '', ?string $opaque = null): string
    {
        return Headers::formatWwwAuthenticate($this->createChallenge($request, $expires, $digest, $opaque));
    }

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
        }

        if ($expectedRequest !== null && !$this->matchesExpectedRequest($request, $expectedRequest)) {
            return VerificationResult::failure('charge request mismatch');
        }

        return $verifier->verify($credential, $challenge);
    }

    public function createReceiptHeader(Challenge $challenge, VerificationResult $result): string
    {
        if (!$result->ok) {
            throw new InvalidArgumentException('Cannot create a receipt for a failed verification');
        }

        return Headers::formatReceipt(Receipt::success(
            method: $challenge->method,
            reference: $result->reference,
            challengeId: $challenge->id,
            externalId: $result->externalId,
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

        return $this->canonicalizeArray($request);
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
