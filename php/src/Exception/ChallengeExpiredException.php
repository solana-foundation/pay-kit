<?php

declare(strict_types=1);

namespace PayKit\Exception;

/**
 * Thrown when a credential's challenge has aged past
 * `MppConfig::$expiresIn`. Subclass of InvalidProofException so the
 * generic "bad proof, re-issue challenge" handler still catches it.
 */
final class ChallengeExpiredException extends InvalidProofException
{
}
