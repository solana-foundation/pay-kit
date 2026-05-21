<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

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
     */
    public function __construct(
        private readonly string $secretKey,
        private readonly string $realm,
        private readonly string $method = 'solana',
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
            request: $request->toArray(),
            expires: $expires,
            digest: $digest,
            opaque: $opaque,
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
            return $verifier->verify($credential, $challenge);
        } catch (InvalidArgumentException $error) {
            return VerificationResult::failure($error->getMessage());
        } catch (Throwable) {
            return VerificationResult::failure('payment verification failed');
        }
    }

    /**
     * Create a payment-receipt header from a verifier that already settled.
     */
    public function createReceiptHeader(Challenge $challenge, VerificationResult $result): string
    {
        if (!$result->ok) {
            throw new InvalidArgumentException('Cannot create a receipt for a failed verification');
        }

        return $this->createReceiptHeaderForReference(
            challenge: $challenge,
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
