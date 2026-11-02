/**
 * Tests for the shared method schemas (Methods.ts).
 *
 * Validates that `charge` method definition has the expected
 * structure, intent, name, and schema shape.
 */
import { charge, session } from '../Methods.js';

describe('charge method definition', () => {
    test('has correct intent and name', () => {
        expect(charge.intent).toBe('charge');
        expect(charge.name).toBe('solana');
    });

    test('has request and credential schemas', () => {
        expect(charge.schema).toBeDefined();
        expect(charge.schema.request).toBeDefined();
        expect(charge.schema.credential).toBeDefined();
        expect(charge.schema.credential.payload).toBeDefined();
    });
});

describe('session method definition', () => {
    test('has correct intent and name', () => {
        expect(session.intent).toBe('session');
        expect(session.name).toBe('solana');
    });

    test('has request and credential schemas', () => {
        expect(session.schema).toBeDefined();
        expect(session.schema.request).toBeDefined();
        expect(session.schema.credential).toBeDefined();
        expect(session.schema.credential.payload).toBeDefined();
    });
});

// draft-solana-session-00 Action open: "MUST NOT carry an initial voucher".
describe('session open payload', () => {
    const open = {
        action: 'open',
        authorizedSigner: 'Config1111111111111111111111111111111111111',
        channelId: 'cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN',
        depositAmount: '5000',
        gracePeriodSeconds: 900,
        mint: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
        openSlot: '250000000',
        payee: 'Stake11111111111111111111111111111111111111',
        payer: 'Vote111111111111111111111111111111111111111',
        salt: '7777',
        transaction: 'AQID',
    };

    test('accepts an open payload without a voucher', () => {
        expect(session.schema.credential.payload.safeParse(open).success).toBe(true);
    });

    test('rejects an open payload carrying a signed voucher', () => {
        const parsed = session.schema.credential.payload.safeParse({
            ...open,
            voucher: {
                signature: 'sig',
                signatureType: 'ed25519',
                signer: open.authorizedSigner,
                voucher: { channelId: open.channelId, cumulativeAmount: '250', expiresAt: 4102444800 },
            },
        });
        expect(parsed.success).toBe(false);
    });
});
