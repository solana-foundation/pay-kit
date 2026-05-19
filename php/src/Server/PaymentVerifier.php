<?php

declare(strict_types=1);

namespace SolanaMpp\Server;

use SolanaMpp\Core\Challenge;
use SolanaMpp\Core\Credential;

interface PaymentVerifier
{
    public function verify(Credential $credential, Challenge $challenge): VerificationResult;
}
