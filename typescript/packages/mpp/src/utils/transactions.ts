import {
    type Address,
    type Base64EncodedWireTransaction,
    getBase64Codec,
    getBase64EncodedWireTransaction,
    getCompiledTransactionMessageDecoder,
    getPublicKeyFromAddress,
    getSignatureFromTransaction,
    getTransactionDecoder,
    type Signature,
    type TransactionPartialSigner,
    verifySignature,
} from '@solana/kit';

/** Rejection text when `getTransaction` omits `version`; shared verbatim with the Rust kit. */
export const MISSING_TRANSACTION_VERSION_ERROR = 'RPC did not report the transaction version';

/** Versions the servers accept on RPC read-back: 0 and 1, plus legacy policed as 0. */
const ACCEPTED_TRANSACTION_VERSIONS: readonly number[] = [0, 1];

/**
 * Version policy for a transaction read back from the RPC by signature.
 * `maxSupportedTransactionVersion` only bounds what the node returns; the
 * server still applies the same policy as at the decode boundary: version 0,
 * version 1 and legacy (unversioned, policed as version 0, kept for existing
 * clients) are accepted. A missing version is refused, since nodes report one
 * for every transaction once asked.
 */
export function assertReportedTransactionVersion(version: unknown): void {
    if (version === 'legacy') return;
    if (version === undefined || version === null) throw new Error(MISSING_TRANSACTION_VERSION_ERROR);
    if (typeof version !== 'number' || !ACCEPTED_TRANSACTION_VERSIONS.includes(version)) {
        throw new Error(
            `transaction version ${JSON.stringify(version)} is not accepted; accepted versions: ${ACCEPTED_TRANSACTION_VERSIONS.join(', ')}`,
        );
    }
}

/**
 * Throw unless a base64 wire transaction carries exactly one signature slot
 * per required signer (`header.num_required_signatures`) and every slot holds
 * a signature that verifies against the message for that signer. An empty
 * slot does not verify.
 *
 * `unsignedSigner` names the server's own fee-payer key on a transaction the
 * server has not co-signed yet: its slot may still be empty (a signature
 * there must verify). Every other slot must verify. Pass nothing once the
 * transaction is fully signed.
 *
 * The one signature check for charge pull mode: the verification step runs
 * it before co-signing, and settlement again on the co-signed transaction
 * before anything is claimed or sent.
 */
export async function assertTransactionSignaturesVerify(
    transaction: string,
    options: { unsignedSigner?: string } = {},
): Promise<void> {
    let decoded: ReturnType<ReturnType<typeof getTransactionDecoder>['decode']>;
    let requiredSignatures: number;
    try {
        decoded = getTransactionDecoder().decode(getBase64Codec().encode(transaction));
        requiredSignatures = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes).header
            .numSignerAccounts;
    } catch {
        throw new Error('transaction signature slots do not match its required signers');
    }
    const entries = Object.entries(decoded.signatures);
    if (entries.length === 0 || entries.length !== requiredSignatures) {
        throw new Error('transaction signature slots do not match its required signers');
    }
    for (const [address, signature] of entries) {
        if (!signature) {
            if (address === options.unsignedSigner) continue;
            throw new Error('transaction signature verification failed');
        }
        const key = await getPublicKeyFromAddress(address as Address);
        if (!(await verifySignature(key, signature, decoded.messageBytes))) {
            throw new Error('transaction signature verification failed');
        }
    }
}

/** Return the deterministic transaction signature from a base64 wire transaction. */
export function transactionSignatureFromBase64(transaction: string): Signature {
    return getSignatureFromTransaction(getTransactionDecoder().decode(getBase64Codec().encode(transaction)));
}

/**
 * Decode a base64 wire transaction, co-sign it with a TransactionPartialSigner,
 * and return the co-signed base64 wire transaction.
 *
 * Uses the signer's `signTransactions()` to obtain the signature, then merges
 * it into the decoded transaction. This bridges decoded wire transactions with
 * any signer interface (Keychain, Privy, Turnkey, AWS KMS, etc.).
 */
export async function coSignBase64Transaction(
    signer: TransactionPartialSigner,
    clientTxBase64: string,
): Promise<Base64EncodedWireTransaction> {
    const txBytes = getBase64Codec().encode(clientTxBase64);
    const decoded = getTransactionDecoder().decode(txBytes);

    // The signer must already be listed in the transaction's signatures map.
    if (decoded.signatures[signer.address] === undefined) {
        throw new Error(`Signer ${signer.address} is not an expected signer for this transaction`);
    }

    // Use the TransactionPartialSigner interface to sign.
    // Cast needed: decoded wire transaction lacks Kit's branded nominal types
    // but is structurally identical (messageBytes + signatures).
    const [signatureMap] = await signer.signTransactions([decoded as Parameters<typeof signer.signTransactions>[0][0]]);
    const signature = signatureMap[signer.address];
    if (!signature) {
        throw new Error(`Signer ${signer.address} did not return a signature`);
    }

    // Create a new transaction with the merged signature.
    // Force-cast to preserve Kit's branded nominal types that getBase64EncodedWireTransaction requires.
    const cosigned = {
        ...decoded,
        signatures: Object.freeze({ ...decoded.signatures, [signer.address]: signature }),
    } as Parameters<typeof getBase64EncodedWireTransaction>[0];

    return getBase64EncodedWireTransaction(cosigned);
}
