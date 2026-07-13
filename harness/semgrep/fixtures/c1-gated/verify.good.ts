// GOOD: presence is asserted FIRST (throw when the field is missing), then the
// on-chain proof runs unconditionally. Omitting the field fails CLOSED.

interface Credential {
    signature?: string;
    payload: unknown;
}

async function verifyCredential(cred: Credential): Promise<boolean> {
    if (!cred.signature) {
        throw new Error('signature is required');
    }
    await verifyOnChain(cred.signature, cred.payload);
    return true;
}

async function verifyBare(signature: string | undefined, payload: unknown) {
    if (!signature) {
        throw new Error('missing signature');
    }
    await checkOnChainProof(signature, payload);
    return true;
}
