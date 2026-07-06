import {
    type Base64EncodedWireTransaction,
    getBase64Codec,
    getBase64EncodedWireTransaction,
    getCompiledTransactionMessageDecoder,
    getTransactionDecoder,
    type TransactionPartialSigner,
} from '@solana/kit';

/**
 * Reject any compiled-message version beyond legacy / v0. A v1 (or later)
 * message decodes to a shape that carries neither `.instructions` nor
 * `.addressTableLookups`, so verifiers that read those fields would silently
 * skip the address-lookup-table guard and then crash with a `TypeError` on
 * hostile input. Callers invoke this immediately after
 * `getCompiledTransactionMessageDecoder().decode()` and before touching any
 * instruction/ALT field, turning that class of input into a clean typed error.
 *
 * `context` is prefixed onto the message so the caller (activation, charge,
 * open/top-up) is identifiable in logs.
 */
export function assertLegacyOrV0Message(version: number | 'legacy', context: string): void {
    if (version === 'legacy' || version === 0) {
        return;
    }
    throw new Error(
        `${context}: unsupported transaction message version ${version} — only legacy and v0 messages are accepted`,
    );
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

    // Pin the signer to the fee-payer slot (account index 0). This helper only
    // ever co-signs as the sponsored fee payer; signing wherever the key
    // happens to appear would let a client place the server key at a non-zero
    // signer index — as the authority/source of an attacker-inserted
    // instruction — and still collect the server's signature, draining the
    // fee-payer wallet. Mirrors the Rust `co_sign_as_fee_payer` index-0 pin.
    const message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes) as unknown as {
        staticAccounts: readonly string[];
        version: number | 'legacy';
    };
    assertLegacyOrV0Message(message.version, 'Co-sign transaction');
    if (message.staticAccounts[0] !== signer.address) {
        throw new Error(`Signer ${signer.address} must be the transaction fee payer (account index 0) to be co-signed`);
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
