// GOOD: constant-time comparison of secret material via timingSafeEqual.

import { createHmac, timingSafeEqual } from 'crypto';

function checkMac(payload: string, secretKey: string, providedMac: string): boolean {
    const expectedMac = createHmac('sha256', secretKey).update(payload).digest();
    const provided = Buffer.from(providedMac, 'hex');
    if (expectedMac.length !== provided.length) {
        return false;
    }
    return timingSafeEqual(expectedMac, provided);
}

// Comparing public, non-secret values (a Solana signature is public) with ===
// is fine and intentionally NOT flagged: this is an idempotency check.
function isReplayOfVoucher(highestVoucherSignature: string, incoming: string): boolean {
    return highestVoucherSignature === incoming;
}
