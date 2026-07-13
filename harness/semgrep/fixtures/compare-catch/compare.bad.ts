// BAD: non-constant-time comparison of secret material.

import { createHmac } from 'crypto';

function checkMac(payload: string, secretKey: string, providedMac: string): boolean {
    const expectedMac = createHmac('sha256', secretKey).update(payload).digest('hex');
    // timing-variable compare of a MAC
    return expectedMac === providedMac;
}

function checkSecret(userSecret: string, storedSecret: string): boolean {
    if (userSecret !== storedSecret) {
        return false;
    }
    return true;
}

function checkDigest(computedDigest: Buffer, providedDigest: Buffer): boolean {
    return computedDigest.equals(providedDigest);
}
