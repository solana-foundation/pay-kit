// BAD: verification errors are swallowed and treated as success (fails open).

async function verifyToken(token: string): Promise<boolean> {
    try {
        await assertSignatureValid(token);
        return true;
    } catch (e) {
        // any verification error is swallowed as "valid"
        return true;
    }
}

async function verifyProof(proof: string): Promise<{ valid: boolean }> {
    try {
        await checkProofOnChain(proof);
        return { valid: true };
    } catch (err) {
        return { valid: true };
    }
}
