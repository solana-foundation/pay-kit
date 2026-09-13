import {
    type Base64EncodedWireTransaction,
    getBase64Codec,
    getBase64EncodedWireTransaction,
    getSignatureFromTransaction,
    getTransactionDecoder,
    type Signature,
    type TransactionPartialSigner,
    type TransactionVersion,
} from '@solana/kit';

/** Rejection text for a legacy (unversioned) message; shared verbatim with the Rust kit. */
export const LEGACY_TRANSACTION_ERROR = 'legacy transactions are not supported; use a version 0 or version 1 message';

/**
 * Reject a legacy (unversioned) compiled message at a server decode boundary.
 * Version 0 and version 1 messages pass through.
 */
export function assertVersionedTransactionMessage(message: { readonly version: TransactionVersion }): void {
    if (message.version === 'legacy') throw new Error(LEGACY_TRANSACTION_ERROR);
}

/** Rejection text when `getTransaction` omits `version`; shared verbatim with the Rust kit. */
export const MISSING_TRANSACTION_VERSION_ERROR = 'RPC did not report the transaction version';

/** Versions the servers accept, at the decode boundary and on RPC read-back alike. */
const ACCEPTED_TRANSACTION_VERSIONS: readonly number[] = [0, 1];

/**
 * Version policy for a transaction read back from the RPC by signature.
 * `maxSupportedTransactionVersion` only bounds what the node returns; the
 * server still accepts only version 0 and version 1, exactly as for a
 * transaction credential. Legacy is refused, and so is a missing version.
 */
export function assertReportedTransactionVersion(version: unknown): void {
    if (version === 'legacy') throw new Error(LEGACY_TRANSACTION_ERROR);
    if (version === undefined || version === null) throw new Error(MISSING_TRANSACTION_VERSION_ERROR);
    if (typeof version !== 'number' || !ACCEPTED_TRANSACTION_VERSIONS.includes(version)) {
        throw new Error(
            `transaction version ${JSON.stringify(version)} is not accepted; accepted versions: ${ACCEPTED_TRANSACTION_VERSIONS.join(', ')}`,
        );
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
