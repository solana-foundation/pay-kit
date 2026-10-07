<?php

declare(strict_types=1);

/**
 * Mirror the consumed-signature rules in harness/src/canonical-codes.ts.
 * Pull-mode duplicate broadcasts can fail at the RPC before the replay store.
 * Other RPC/verification failures must not be reported as consumed signatures.
 */
function is_signature_consumed(string $message): bool
{
    return preg_match('/already consumed|signature.*consumed|already been processed|transaction.*already.*processed/i', $message) === 1;
}
