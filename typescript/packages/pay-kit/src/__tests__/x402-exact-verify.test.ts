import {
    AccountRole,
    address,
    appendTransactionMessageInstructions,
    type Address,
    type Blockhash,
    compileTransaction,
    createTransactionMessage,
    getBase64Decoder,
    getBase64EncodedWireTransaction,
    getBase64Encoder,
    getCompiledTransactionMessageDecoder,
    getCompiledTransactionMessageEncoder,
    getTransactionDecoder,
    getTransactionEncoder,
    type Instruction,
    pipe,
    setTransactionMessageFeePayer,
    setTransactionMessageLifetimeUsingBlockhash,
} from '@solana/kit';
import { describe, expect, it } from 'vitest';

import {
    assertX402AcceptedMatchesRoute,
    assertX402FeePayerIsolated,
    verifyX402ExactCredential,
    X402_ACCEPTED_MISMATCH,
    X402_FEE_PAYER_IN_INSTRUCTION_ACCOUNTS,
} from '../adapters/x402-exact-verify.js';
import { InvalidProofError } from '../errors.js';

const FEE_PAYER = address('J2xccRtuG43drESLYznHhLhQkLTdfepcKYbiQ9BsJVaf');
const CLIENT = address('CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY');
const MEMO_PROGRAM = address('MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr');

const ROUTE = {
    amount: '1000',
    asset: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
    extra: { feePayer: FEE_PAYER as string },
    maxTimeoutSeconds: 300,
    network: 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
    payTo: 'CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY',
    scheme: 'exact',
};

function memo(accounts: readonly { address: Address; role: AccountRole }[] = []): Instruction {
    return { accounts, data: new TextEncoder().encode('nonce'), programAddress: MEMO_PROGRAM };
}

function wire(instructions: readonly Instruction[], feePayer: Address = FEE_PAYER): string {
    const message = pipe(
        createTransactionMessage({ version: 0 }),
        m => setTransactionMessageFeePayer(feePayer, m),
        m =>
            setTransactionMessageLifetimeUsingBlockhash(
                { blockhash: 'EkSnNWid2cvwEVnVx9aBqawnmiCNiDgp3gUdkDPTKN1N' as Blockhash, lastValidBlockHeight: 1n },
                m,
            ),
        m => appendTransactionMessageInstructions(instructions, m),
    );
    return getBase64EncodedWireTransaction(compileTransaction(message));
}

function codeOf(fn: () => void): string | undefined {
    try {
        fn();
        return undefined;
    } catch (error) {
        expect(error).toBeInstanceOf(InvalidProofError);
        return (error as InvalidProofError).code;
    }
}

describe('assertX402AcceptedMatchesRoute', () => {
    it('accepts the honest echo, with transient hints and unknown fields', () => {
        const echo = {
            ...ROUTE,
            extra: { ...ROUTE.extra, lastValidBlockHeight: '9', recentBlockhash: 'x', unknown: 1 },
            protocol: 'x402',
        };
        expect(codeOf(() => assertX402AcceptedMatchesRoute(echo, ROUTE))).toBeUndefined();
    });

    it('tolerates a non-spec server hint the client did not echo', () => {
        const route = { ...ROUTE, extra: { ...ROUTE.extra, decimals: 6, tokenProgram: 'T' } };
        expect(codeOf(() => assertX402AcceptedMatchesRoute(ROUTE, route))).toBeUndefined();
        expect(
            codeOf(() => assertX402AcceptedMatchesRoute({ ...ROUTE, extra: { ...ROUTE.extra, decimals: 9 } }, route)),
        ).toBe(X402_ACCEPTED_MISMATCH);
    });

    // x402-specification-v2.md §5.2.2: `accepted` is the chosen requirement.
    it.each([
        ['scheme', 'upto'],
        ['network', 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'],
        ['amount', '1'],
        ['asset', 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'],
        ['payTo', 'Stake11111111111111111111111111111111111111'],
    ])('rejects an accepted.%s that differs from the route', (field, value) => {
        expect(codeOf(() => assertX402AcceptedMatchesRoute({ ...ROUTE, [field]: value }, ROUTE))).toBe(
            X402_ACCEPTED_MISMATCH,
        );
    });

    it('compares structured extra values by content after a JSON round trip', () => {
        const route = { ...ROUTE, extra: { ...ROUTE.extra, transactionVersions: [0, 1], policy: { a: 1, b: [2] } } };
        const echo = JSON.parse(JSON.stringify({ ...ROUTE, extra: { ...route.extra, policy: { b: [2], a: 1 } } }));
        expect(codeOf(() => assertX402AcceptedMatchesRoute(echo, route))).toBeUndefined();
        expect(
            codeOf(() =>
                assertX402AcceptedMatchesRoute({ ...echo, extra: { ...echo.extra, transactionVersions: [0] } }, route),
            ),
        ).toBe(X402_ACCEPTED_MISMATCH);
        expect(
            codeOf(() =>
                assertX402AcceptedMatchesRoute(
                    { ...echo, extra: { ...echo.extra, transactionVersions: [1, 0] } },
                    route,
                ),
            ),
        ).toBe(X402_ACCEPTED_MISMATCH);
    });

    it('rejects an issued extra field that differs or is dropped', () => {
        const route = { ...ROUTE, extra: { ...ROUTE.extra, memo: '/paid' } };
        expect(codeOf(() => assertX402AcceptedMatchesRoute({ ...ROUTE, extra: route.extra }, route))).toBeUndefined();
        expect(
            codeOf(() => assertX402AcceptedMatchesRoute({ ...ROUTE, extra: { ...route.extra, memo: '/x' } }, route)),
        ).toBe(X402_ACCEPTED_MISMATCH);
        expect(codeOf(() => assertX402AcceptedMatchesRoute(ROUTE, route))).toBe(X402_ACCEPTED_MISMATCH);
        expect(
            codeOf(() => assertX402AcceptedMatchesRoute({ ...ROUTE, extra: { feePayer: CLIENT as string } }, ROUTE)),
        ).toBe(X402_ACCEPTED_MISMATCH);
    });
});

// scheme_exact_svm.md §2.1.1: "The `feePayer` MUST NOT appear in the
// `accounts` list of any instruction ... and MUST NOT be invoked as a program."
describe('assertX402FeePayerIsolated', () => {
    it('accepts a transaction whose instructions never reference the fee payer', () => {
        const tx = wire([memo([{ address: CLIENT, role: AccountRole.READONLY_SIGNER }])]);
        expect(codeOf(() => assertX402FeePayerIsolated(tx, FEE_PAYER))).toBeUndefined();
    });

    it('rejects the fee payer as an instruction account', () => {
        const tx = wire([memo([{ address: FEE_PAYER, role: AccountRole.READONLY_SIGNER }])]);
        expect(codeOf(() => assertX402FeePayerIsolated(tx, FEE_PAYER))).toBe(X402_FEE_PAYER_IN_INSTRUCTION_ACCOUNTS);
    });

    it('rejects the fee payer invoked as a program', () => {
        // Kit refuses to compile this, so retarget a compiled memo at the fee
        // payer's account index (0).
        const { messageBytes, signatures } = getTransactionDecoder().decode(getBase64Encoder().encode(wire([memo()])));
        const message = getCompiledTransactionMessageDecoder().decode(messageBytes);
        if (message.version !== 0) throw new Error('expected a v0 message');
        const patched = {
            ...message,
            instructions: message.instructions.map(ix => ({ ...ix, programAddressIndex: 0 })),
        };
        const tx = getBase64Decoder().decode(
            getTransactionEncoder().encode({
                messageBytes: getCompiledTransactionMessageEncoder().encode(patched) as typeof messageBytes,
                signatures,
            }),
        );
        expect(codeOf(() => assertX402FeePayerIsolated(tx, FEE_PAYER))).toBe(X402_FEE_PAYER_IN_INSTRUCTION_ACCOUNTS);
    });

    it('rejects an undecodable transaction', () => {
        expect(codeOf(() => assertX402FeePayerIsolated('AA==', FEE_PAYER))).toBe(
            'invalid_exact_svm_payload_transaction_could_not_be_decoded',
        );
    });
});

describe('verifyX402ExactCredential', () => {
    it('binds accepted before inspecting the transaction', () => {
        const tx = wire([memo([{ address: FEE_PAYER, role: AccountRole.READONLY_SIGNER }])]);
        expect(
            codeOf(() =>
                verifyX402ExactCredential({ accepted: { ...ROUTE, amount: '1' }, payload: { transaction: tx } }, ROUTE),
            ),
        ).toBe(X402_ACCEPTED_MISMATCH);
        expect(codeOf(() => verifyX402ExactCredential({ accepted: ROUTE, payload: { transaction: tx } }, ROUTE))).toBe(
            X402_FEE_PAYER_IN_INSTRUCTION_ACCOUNTS,
        );
        expect(
            codeOf(() =>
                verifyX402ExactCredential({ accepted: ROUTE, payload: { transaction: wire([memo()]) } }, ROUTE),
            ),
        ).toBeUndefined();
    });
});
