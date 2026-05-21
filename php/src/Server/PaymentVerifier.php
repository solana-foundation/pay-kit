<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

use SolanaMpp\Core\Challenge;
use SolanaMpp\Core\Credential;

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
