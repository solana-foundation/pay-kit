/**
 * Integration tests against a local Surfpool simnet.
 *
 * Runs a real HTTP server (mppx server) and a real HTTP client (mppx client)
 * with actual Solana transactions against surfpool on localhost:8899.
 *
 * Requires: `surfpool start --no-tui --offline` running on localhost:8899
 *
 * Run: npm run test:integration
 */
import { test, expect, beforeAll, afterAll } from 'vitest';
import http from 'node:http';
import { generateKeyPairSigner, address, lamports } from '@solana/kit';
import { createLocalClient } from '@solana/kit-client-rpc';
import { systemProgram } from '@solana-program/system';
import { Mppx as ServerMppx, solana as serverSolana, Store } from '../../src/server/index.js';
import { Mppx as ClientMppx, solana as clientSolana } from '../../src/client/index.js';

const RPC_URL = process.env.RPC_URL ?? 'http://localhost:8899';
const RPC_WS_URL = process.env.RPC_WS_URL ?? 'ws://127.0.0.1:8900';

type GeneratedSigner = Awaited<ReturnType<typeof generateKeyPairSigner>>;
type TestClient = Awaited<ReturnType<typeof createTestClient>>;

// ── Helpers ──

async function createTestClient(payer?: GeneratedSigner) {
    return await createLocalClient({ payer, rpcSubscriptionsConfig: { url: RPC_WS_URL }, url: RPC_URL }).use(
        systemProgram(),
    );
}

async function getBalance(client: TestClient, pubkey: string): Promise<bigint> {
    const { value } = await client.rpc.getBalance(address(pubkey)).send();
    return value;
}

async function isSurfpoolRunning(): Promise<boolean> {
    try {
        const res = await fetch(RPC_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getHealth', params: [] }),
        });
        return res.ok;
    } catch {
        return false;
    }
}

/** Convert an incoming Node request to a Web API Request. */
function toWebRequest(req: http.IncomingMessage, body: string): Request {
    const headers = new Headers();
    for (const [key, value] of Object.entries(req.headers)) {
        if (value) headers.set(key, Array.isArray(value) ? value[0] : value);
    }
    const url = `http://localhost${req.url}`;
    return new Request(url, { method: req.method, headers, body: body || undefined });
}

async function readBody(req: http.IncomingMessage): Promise<string> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    return Buffer.concat(chunks).toString();
}

// ── Test state ──

let client: TestClient;
let clientSigner: GeneratedSigner;
let recipientSigner: GeneratedSigner;
let server: http.Server;
let serverPort: number;
let surfpoolRunning = false;

beforeAll(async () => {
    surfpoolRunning = await isSurfpoolRunning();
    if (!surfpoolRunning) {
        console.log(`Surfpool not running at ${RPC_URL} — skipping integration tests.`);
        console.log('Start it with: surfpool start --no-tui --offline, or set RPC_URL.');
        return;
    }

    // Generate fresh keypairs
    clientSigner = await generateKeyPairSigner();
    recipientSigner = await generateKeyPairSigner();

    // Create kit client with systemProgram plugin
    client = await createTestClient(clientSigner);

    // Fund the client with 10 SOL
    await client.airdrop(clientSigner.address, lamports(10_000_000_000n));

    // Start a test HTTP server with the mppx charge handler
    // secretKey is required by mppx for signing challenge tokens
    const secretKey = 'test-secret-key-for-integration-tests';

    const mppx = ServerMppx.create({
        secretKey,
        methods: [
            serverSolana.charge({
                recipient: recipientSigner.address,
                network: 'localnet',
                rpcUrl: RPC_URL,
            }),
        ],
    });

    server = http.createServer(async (req, res) => {
        // Read body
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(chunk as Buffer);
        const body = Buffer.concat(chunks).toString();

        const webReq = toWebRequest(req, body);

        const result = await mppx.charge({
            amount: '1000000', // 0.001 SOL
            currency: 'sol',
            description: 'test charge',
        })(webReq);

        if (result.status === 402) {
            const challenge = result.challenge as Response;
            const headers = Object.fromEntries(challenge.headers);
            res.writeHead(challenge.status, headers);
            res.end(await challenge.text());
            return;
        }

        const response = result.withReceipt(Response.json({ paid: true })) as Response;
        res.writeHead(response.status, Object.fromEntries(response.headers));
        res.end(await response.text());
    });

    await new Promise<void>(resolve => {
        server.listen(0, () => {
            serverPort = (server.address() as any).port;
            resolve();
        });
    });
});

afterAll(() => {
    server?.close();
});

function hasSurfpool(): boolean {
    return surfpoolRunning;
}

// ── Tests ──

test('e2e: native SOL charge via pull mode (default)', async () => {
    if (!hasSurfpool()) return;

    const events: string[] = [];

    const clientMethod = clientSolana.charge({
        signer: clientSigner,
        rpcUrl: RPC_URL,
        // broadcast defaults to false (pull mode)
        onProgress(event) {
            events.push(event.type);
        },
    });

    const mppx = ClientMppx.create({ methods: [clientMethod] });

    const balanceBefore = await getBalance(client, recipientSigner.address);

    const response = await mppx.fetch(`http://localhost:${serverPort}/test`);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ paid: true });

    // Verify progress events
    expect(events).toContain('challenge');
    expect(events).toContain('signing');
    expect(events).toContain('signed');

    // Verify recipient received payment
    const balanceAfter = await getBalance(client, recipientSigner.address);
    expect(balanceAfter).toBeGreaterThan(balanceBefore);
    expect(balanceAfter - balanceBefore).toBeGreaterThanOrEqual(1_000_000n);
});

test('e2e: native SOL charge via push mode', async () => {
    if (!hasSurfpool()) return;

    const events: string[] = [];

    const clientMethod = clientSolana.charge({
        signer: clientSigner,
        rpcUrl: RPC_URL,
        broadcast: true,
        onProgress(event) {
            events.push(event.type);
        },
    });

    const mppx = ClientMppx.create({ methods: [clientMethod] });

    const response = await mppx.fetch(`http://localhost:${serverPort}/test`);
    const data = await response.json();

    expect(response.status).toBe(200);
    expect(data).toEqual({ paid: true });

    // Push mode should fire: challenge → signing → paying → confirming → paid
    expect(events).toContain('challenge');
    expect(events).toContain('signing');
    expect(events).toContain('paying');
    expect(events).toContain('paid');
});

test('e2e: multiple sequential charges succeed', async () => {
    if (!hasSurfpool()) return;

    const clientMethod = clientSolana.charge({
        signer: clientSigner,
        rpcUrl: RPC_URL,
    });

    const mppx = ClientMppx.create({ methods: [clientMethod] });

    // Three sequential charges should all succeed (no replay issues)
    for (let i = 0; i < 3; i++) {
        const response = await mppx.fetch(`http://localhost:${serverPort}/test`);
        expect(response.status).toBe(200);
        const data = await response.json();
        expect(data).toEqual({ paid: true });
    }
});

test('e2e: receipt header is present on success', async () => {
    if (!hasSurfpool()) return;

    const clientMethod = clientSolana.charge({
        signer: clientSigner,
        rpcUrl: RPC_URL,
    });

    const mppx = ClientMppx.create({ methods: [clientMethod] });

    const response = await mppx.fetch(`http://localhost:${serverPort}/test`);
    expect(response.status).toBe(200);

    // mppx attaches a receipt header
    const receiptHeader = response.headers.get('Payment-Receipt');
    expect(receiptHeader).toBeTruthy();
});

// ── Fee payer (server pays tx fees) ──

test('e2e: fee payer mode — server co-signs and pays fees', async () => {
    if (!hasSurfpool()) return;

    // Generate a dedicated fee payer keypair for the server
    const feePayerSigner = await generateKeyPairSigner();
    await client.airdrop(feePayerSigner.address, lamports(10_000_000_000n));

    // mppx >=0.8 enforces a 32-byte minimum secret key length.
    const secretKey = 'test-secret-key-feepayer-32-byte-pad';

    const feePayerMppx = ServerMppx.create({
        secretKey,
        methods: [
            serverSolana.charge({
                recipient: recipientSigner.address,
                network: 'localnet',
                rpcUrl: RPC_URL,
                signer: feePayerSigner, // Server pays fees
            }),
        ],
    });

    // Start a fee-payer server
    const fpServer = http.createServer(async (req, res) => {
        const chunks: Buffer[] = [];
        for await (const chunk of req) chunks.push(chunk as Buffer);
        const body = Buffer.concat(chunks).toString();
        const webReq = toWebRequest(req, body);

        const result = await feePayerMppx.charge({
            amount: '1000000',
            currency: 'sol',
        })(webReq);

        if (result.status === 402) {
            const challenge = result.challenge as Response;
            res.writeHead(challenge.status, Object.fromEntries(challenge.headers));
            res.end(await challenge.text());
            return;
        }

        const response = result.withReceipt(Response.json({ paid: true })) as Response;
        res.writeHead(response.status, Object.fromEntries(response.headers));
        res.end(await response.text());
    });

    const fpPort = await new Promise<number>(resolve => {
        fpServer.listen(0, () => resolve((fpServer.address() as any).port));
    });

    try {
        const clientBalanceBefore = await getBalance(client, clientSigner.address);

        const clientMethod = clientSolana.charge({
            signer: clientSigner,
            rpcUrl: RPC_URL,
            // broadcast defaults to false — required for fee payer
        });

        const mppx = ClientMppx.create({ methods: [clientMethod] });
        const response = await mppx.fetch(`http://localhost:${fpPort}/test`);
        const data = await response.json();

        expect(response.status).toBe(200);
        expect(data).toEqual({ paid: true });

        // Client should have paid exactly 1_000_000 lamports for the transfer,
        // but NOT the tx fee (the fee payer covered that).
        const clientBalanceAfter = await getBalance(client, clientSigner.address);
        const clientSpent = clientBalanceBefore - clientBalanceAfter;

        // The client should have spent exactly the transfer amount (1_000_000 lamports).
        // Without fee payer, they'd also spend ~5000 lamports for the tx fee.
        expect(clientSpent).toBe(1_000_000n);
    } finally {
        fpServer.close();
    }
});

// ── USDC charge (SPL token) ──

const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';

async function fundUsdc(ownerAddress: string, amount: number) {
    await fetch(RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method: 'surfnet_setTokenAccount',
            params: [ownerAddress, USDC_MINT, { amount, state: 'initialized' }, TOKEN_PROGRAM],
        }),
    });
}

test('e2e: USDC charge via pull mode with fee payer', async () => {
    if (!hasSurfpool()) return;

    const feePayerSigner = await generateKeyPairSigner();
    await client.airdrop(feePayerSigner.address, lamports(10_000_000_000n));
    await fundUsdc(clientSigner.address, 100_000_000); // 100 USDC
    await fundUsdc(recipientSigner.address, 0);

    const secretKey = 'test-secret-key-usdc-32-byte-padding';

    const usdcMppx = ServerMppx.create({
        secretKey,
        methods: [
            serverSolana.charge({
                recipient: recipientSigner.address,
                network: 'localnet',
                rpcUrl: RPC_URL,
                currency: USDC_MINT,
                decimals: 6,
                signer: feePayerSigner,
            }),
        ],
    });

    const usdcServer = http.createServer(async (req, res) => {
        const body = await readBody(req);
        const webReq = toWebRequest(req, body);

        const result = await usdcMppx.charge({
            amount: '10000', // 0.01 USDC
            currency: USDC_MINT,
        })(webReq);

        if (result.status === 402) {
            const challenge = result.challenge as Response;
            res.writeHead(challenge.status, Object.fromEntries(challenge.headers));
            res.end(await challenge.text());
            return;
        }

        const response = result.withReceipt(Response.json({ paid: true })) as Response;
        res.writeHead(response.status, Object.fromEntries(response.headers));
        res.end(await response.text());
    });

    const usdcPort = await new Promise<number>(resolve => {
        usdcServer.listen(0, () => resolve((usdcServer.address() as { port: number }).port));
    });

    try {
        const clientMethod = clientSolana.charge({
            signer: clientSigner,
            rpcUrl: RPC_URL,
        });

        const mppx = ClientMppx.create({ methods: [clientMethod] });
        const response = await mppx.fetch(`http://localhost:${usdcPort}/test`);

        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({ paid: true });

        const receiptHeader = response.headers.get('Payment-Receipt');
        expect(receiptHeader).toBeTruthy();
    } finally {
        usdcServer.close();
    }
});

test('e2e: USDC charge with splits (platform fee)', async () => {
    if (!hasSurfpool()) return;

    const feePayerSigner = await generateKeyPairSigner();
    const platformSigner = await generateKeyPairSigner();
    await client.airdrop(feePayerSigner.address, lamports(10_000_000_000n));
    await fundUsdc(clientSigner.address, 100_000_000); // 100 USDC
    await fundUsdc(recipientSigner.address, 0);
    await fundUsdc(platformSigner.address, 0);

    const secretKey = 'test-secret-key-splits-32-byte-padd';
    const splits = [{ recipient: platformSigner.address, amount: '5000', memo: 'platform fee' }];

    const splitsMppx = ServerMppx.create({
        secretKey,
        methods: [
            serverSolana.charge({
                recipient: recipientSigner.address,
                network: 'localnet',
                rpcUrl: RPC_URL,
                currency: USDC_MINT,
                decimals: 6,
                signer: feePayerSigner,
                splits,
            }),
        ],
    });

    const splitsServer = http.createServer(async (req, res) => {
        const body = await readBody(req);
        const webReq = toWebRequest(req, body);

        const result = await splitsMppx.charge({
            amount: '15000', // 0.015 USDC total (0.01 to recipient + 0.005 to platform)
            currency: USDC_MINT,
        })(webReq);

        if (result.status === 402) {
            const challenge = result.challenge as Response;
            res.writeHead(challenge.status, Object.fromEntries(challenge.headers));
            res.end(await challenge.text());
            return;
        }

        const response = result.withReceipt(Response.json({ paid: true })) as Response;
        res.writeHead(response.status, Object.fromEntries(response.headers));
        res.end(await response.text());
    });

    const splitsPort = await new Promise<number>(resolve => {
        splitsServer.listen(0, () => resolve((splitsServer.address() as { port: number }).port));
    });

    try {
        const clientMethod = clientSolana.charge({
            signer: clientSigner,
            rpcUrl: RPC_URL,
        });

        const mppx = ClientMppx.create({ methods: [clientMethod] });
        const response = await mppx.fetch(`http://localhost:${splitsPort}/test`);

        expect(response.status).toBe(200);
        expect(await response.json()).toEqual({ paid: true });
    } finally {
        splitsServer.close();
    }
});

test('e2e: native SOL charge with splits', async () => {
    if (!hasSurfpool()) return;

    const platformSigner = await generateKeyPairSigner();
    const referrerSigner = await generateKeyPairSigner();

    const secretKey = 'test-secret-key-sol-splits-32-byte-pad';
    // Split amounts must be >= rent-exempt minimum (~890_880 lamports)
    // because the recipient accounts are freshly generated keypairs that
    // don't yet exist on-chain, and Solana refuses to create system
    // accounts with sub-rent-exempt balances.
    const splits = [
        { recipient: platformSigner.address, amount: '1000000' },
        { recipient: referrerSigner.address, amount: '1000000' },
    ];

    const solSplitsMppx = ServerMppx.create({
        secretKey,
        methods: [
            serverSolana.charge({
                recipient: recipientSigner.address,
                network: 'localnet',
                rpcUrl: RPC_URL,
                splits,
            }),
        ],
    });

    const solSplitsServer = http.createServer(async (req, res) => {
        const body = await readBody(req);
        const webReq = toWebRequest(req, body);

        const result = await solSplitsMppx.charge({
            amount: '3000000', // 1M primary + 1M platform + 1M referrer
            currency: 'sol',
        })(webReq);

        if (result.status === 402) {
            const challenge = result.challenge as Response;
            res.writeHead(challenge.status, Object.fromEntries(challenge.headers));
            res.end(await challenge.text());
            return;
        }

        const response = result.withReceipt(Response.json({ paid: true })) as Response;
        res.writeHead(response.status, Object.fromEntries(response.headers));
        res.end(await response.text());
    });

    const solSplitsPort = await new Promise<number>(resolve => {
        solSplitsServer.listen(0, () => resolve((solSplitsServer.address() as { port: number }).port));
    });

    try {
        const clientMethod = clientSolana.charge({
            signer: clientSigner,
            rpcUrl: RPC_URL,
        });

        const mppx = ClientMppx.create({ methods: [clientMethod] });

        const platformBefore = await getBalance(client, platformSigner.address);
        const referrerBefore = await getBalance(client, referrerSigner.address);

        const response = await mppx.fetch(`http://localhost:${solSplitsPort}/test`);
        expect(response.status).toBe(200);

        // Verify split recipients received their shares
        const platformAfter = await getBalance(client, platformSigner.address);
        const referrerAfter = await getBalance(client, referrerSigner.address);

        expect(platformAfter - platformBefore).toBe(1_000_000n);
        expect(referrerAfter - referrerBefore).toBe(1_000_000n);
    } finally {
        solSplitsServer.close();
    }
});
