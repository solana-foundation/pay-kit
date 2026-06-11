import { getPublicKeyFromAddress, verifySignature } from '@solana/kit';
import { describe, expect, it } from 'vitest';

import { InvalidKeyError } from '../errors.js';
import { Signer } from '../signer.js';

/** Cross-SDK demo pubkey (Ruby / Python / PHP / Lua ship the same keypair). */
const DEMO_PUBKEY = 'ALtYSsZuYyKrNSe6GnVCzxj1T2RPMTPzXMe51xhbmXEq';

describe('Signer', () => {
    it('ships the cross-SDK demo keypair', async () => {
        const signer = await Signer.demo();
        expect(signer.pubkey).toBe(DEMO_PUBKEY);
        expect(signer.isDemo).toBe(true);
        expect(signer.isFeePayer).toBe(true);
    });

    it('caches the demo signer per process', async () => {
        expect(await Signer.demo()).toBe(await Signer.demo());
    });

    it('produces verifiable Ed25519 signatures', async () => {
        const signer = await Signer.generate();
        const message = new TextEncoder().encode('paykit');
        const signature = await signer.sign(message);
        expect(signature).toHaveLength(64);
        const publicKey = await getPublicKeyFromAddress(signer.signer.address);
        expect(await verifySignature(publicKey, signature as Parameters<typeof verifySignature>[1], message)).toBe(
            true,
        );
    });

    it('parses json, hex, and bytes encodings to the same key', async () => {
        const generated = await Signer.generate();
        // Round-trip is only possible for keys we know the bytes of; use demo.
        const demo = await Signer.demo();
        const demoBytes = [
            26, 61, 117, 192, 9, 232, 24, 51, 89, 135, 105, 182, 47, 9, 83, 244, 11, 214, 85, 170, 227, 83, 170, 26, 55,
            129, 58, 114, 89, 160, 195, 51, 138, 209, 127, 35, 54, 41, 202, 166, 199, 166, 97, 238, 181, 63, 254, 185,
            45, 16, 174, 102, 250, 198, 30, 191, 232, 236, 147, 167, 41, 178, 151, 26,
        ];
        const fromBytes = await Signer.bytes(demoBytes);
        const fromJson = await Signer.json(JSON.stringify(demoBytes));
        const fromHex = await Signer.hex(demoBytes.map(b => b.toString(16).padStart(2, '0')).join(''));
        expect(fromBytes.pubkey).toBe(demo.pubkey);
        expect(fromJson.pubkey).toBe(demo.pubkey);
        expect(fromHex.pubkey).toBe(demo.pubkey);
        expect(fromBytes.isDemo).toBe(false);
        expect(generated.pubkey).not.toBe(demo.pubkey);
    });

    it('reads from the environment with format auto-detection', async () => {
        process.env.PAY_KIT_TEST_KEY = '';
        expect(await Signer.env('PAY_KIT_TEST_KEY')).toBeUndefined();
        delete process.env.PAY_KIT_TEST_KEY;
        expect(await Signer.env('PAY_KIT_TEST_KEY')).toBeUndefined();

        const demoBytes = (await Signer.demo()).pubkey; // sanity anchor below
        process.env.PAY_KIT_TEST_KEY =
            '[26,61,117,192,9,232,24,51,89,135,105,182,47,9,83,244,11,214,85,170,227,83,170,26,55,129,58,114,89,160,195,51,138,209,127,35,54,41,202,166,199,166,97,238,181,63,254,185,45,16,174,102,250,198,30,191,232,236,147,167,41,178,151,26]';
        const signer = await Signer.env('PAY_KIT_TEST_KEY');
        expect(signer?.pubkey).toBe(demoBytes);
        delete process.env.PAY_KIT_TEST_KEY;
    });

    it('rejects malformed secrets with InvalidKeyError', async () => {
        await expect(Signer.json('[1,2,3]')).rejects.toThrow(InvalidKeyError);
        await expect(Signer.hex('abcd')).rejects.toThrow(InvalidKeyError);
        await expect(Signer.base58('not-base58-!!!')).rejects.toThrow(InvalidKeyError);
        await expect(Signer.file('/nonexistent/key.json')).rejects.toThrow(InvalidKeyError);
    });

    it('wraps external keychain signers via from()', async () => {
        const inner = (await Signer.generate()).signer;
        const wrapped = Signer.from(inner, { feePayer: false });
        expect(wrapped.pubkey).toBe(inner.address);
        expect(wrapped.isFeePayer).toBe(false);
        expect(wrapped.isDemo).toBe(false);
    });
});
