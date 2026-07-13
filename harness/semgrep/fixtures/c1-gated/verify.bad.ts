// BAD (C1): the on-chain proof only runs when `signature` is present, so an
// empty/omitted signature skips verification entirely => bypass.

interface Credential {
    signature?: string;
    payload: unknown;
}

async function verifyCredential(cred: Credential): Promise<boolean> {
    if (cred.signature) {
        await verifyOnChain(cred.signature, cred.payload);
    }
    // falls through as "accepted" when signature is absent
    return true;
}

async function verifyBare(signature: string | undefined, payload: unknown) {
    if (signature) {
        await checkOnChainProof(signature, payload);
    }
    return true;
}
