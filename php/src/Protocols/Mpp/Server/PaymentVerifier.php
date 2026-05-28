<?php

declare(strict_types=1);

namespace PayKit\Protocols\Mpp\Server;

use PayKit\Protocols\Mpp\Core\Challenge;
use PayKit\Protocols\Mpp\Core\Credential;

/**
 * Verifies the payment payload embedded in a credential.
 */
interface PaymentVerifier
{
    /**
     * Verify the credential payload against the decoded challenge.
     */
    public function verify(Credential $credential, Challenge $challenge): VerificationResult;
}
