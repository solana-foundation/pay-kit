// GOOD: verification errors fail closed — the catch returns/propagates failure.

async function verifyToken(token: string): Promise<boolean> {
    try {
        await assertSignatureValid(token);
        return true;
    } catch (e) {
        return false;
    }
}

async function verifyProof(proof: string): Promise<{ valid: boolean }> {
    try {
        await checkProofOnChain(proof);
        return { valid: true };
    } catch (err) {
        return { valid: false };
    }
}
