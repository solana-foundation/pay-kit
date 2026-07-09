import { afterEach, describe, expect, it } from "vitest";
import { Surfnet } from "@solana/surfpool";
import type { ImplementationDefinition } from "../src/implementations";
import { startServer, stopServer } from "../src/process";

const MINT = "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU";
const MPP_NETWORK = "localnet";
const X402_NETWORK = "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1";
const RESOURCE_PATH = "/protected";
const RPC_URL = "http://127.0.0.1:8899";
const SETTLEMENT_HEADER = "x-fixture-settlement";

type RunningServer = Awaited<ReturnType<typeof startServer>>;

const runningServers: RunningServer[] = [];

const chargeServer: ImplementationDefinition = {
  id: "typescript",
  label: "TypeScript MPP charge unpaid smoke server",
  role: "server",
  command: [
    "pnpm",
    "exec",
    "node",
    "--import",
    "tsx",
    "src/fixtures/typescript/charge-server.ts",
  ],
  enabled: true,
};

const exactServer: ImplementationDefinition = {
  id: "ts-x402-exact-smoke",
  label: "TypeScript x402 exact unpaid smoke server",
  role: "server",
  command: [
    "pnpm",
    "exec",
    "node",
    "--import",
    "tsx",
    "src/fixtures/typescript/exact-server.ts",
  ],
  enabled: true,
  reportsAs: "typescript",
};

const uptoServer: ImplementationDefinition = {
  id: "ts-x402-upto-smoke",
  label: "TypeScript x402 upto unpaid smoke server",
  role: "server",
  command: [
    "pnpm",
    "exec",
    "node",
    "--import",
    "tsx",
    "src/fixtures/typescript/upto-challenge-server.ts",
  ],
  enabled: true,
  reportsAs: "typescript",
};

afterEach(async () => {
  while (runningServers.length > 0) {
    const server = runningServers.pop();
    if (server) {
      await stopServer(server);
    }
  }
});

describe("unpaid protected-route challenge smoke", () => {
  it("MPP charge denies unpaid access and advertises a charge challenge", async () => {
    const env = makeMppEnv();
    const server = await startServer(chargeServer, env);
    runningServers.push(server);

    const response = await fetch(
      `http://127.0.0.1:${server.ready.port}${RESOURCE_PATH}`,
    );
    const body = await response.text();

    expect(response.status).toBe(402);
    expect(response.headers.get(SETTLEMENT_HEADER)).toBeNull();
    expect(body).not.toMatch(/"paid"\s*:\s*true/);
    const challenge = requireHeader(response, "www-authenticate");
    expect(challenge).toMatch(/^Payment\b/);
    expect(challenge).toContain('intent="charge"');
    expect(challenge).toContain('method="solana"');
  });

  it("x402 exact denies unpaid access and advertises an exact challenge", async () => {
    const env = makeX402Env();
    const server = await startServer(exactServer, env);
    runningServers.push(server);

    const response = await fetch(
      `http://127.0.0.1:${server.ready.port}${RESOURCE_PATH}`,
    );
    const body = await response.text();
    const challenge = decodePaymentRequired(response);

    expect(response.status).toBe(402);
    expect(response.headers.get(SETTLEMENT_HEADER)).toBeNull();
    expect(body).not.toMatch(/"paid"\s*:\s*true/);
    expect(challenge.x402Version).toBe(2);
    expect(challenge.resource).toBe(RESOURCE_PATH);
    expect(challenge.accepts).toHaveLength(1);
    expect(challenge.accepts?.[0]).toMatchObject({
      scheme: "exact",
      network: X402_NETWORK,
      payTo: env.X402_HARNESS_PAY_TO,
      asset: MINT,
      maxAmountRequired: "1000",
    });
  });

  it("x402 upto denies unpaid access and advertises an upto challenge", async () => {
    const env = makeX402Env({ X402_HARNESS_AMOUNT: "100000" });
    const server = await startServer(uptoServer, env);
    runningServers.push(server);

    const response = await fetch(
      `http://127.0.0.1:${server.ready.port}${RESOURCE_PATH}`,
    );
    const body = (await response.json()) as { accepts?: unknown[] };
    const challenge = decodePaymentRequired(response);

    expect(response.status).toBe(402);
    expect(response.headers.get(SETTLEMENT_HEADER)).toBeNull();
    expect(body).not.toMatchObject({ paid: true });
    expect(body.accepts).toHaveLength(1);
    expect(challenge.x402Version).toBe(2);
    expect(challenge.resource).toMatchObject({ url: RESOURCE_PATH });
    expect(challenge.accepts).toHaveLength(1);
    expect(challenge.accepts?.[0]).toMatchObject({
      scheme: "upto",
      network: X402_NETWORK,
      amount: "100000",
      asset: MINT,
      payTo: env.X402_HARNESS_PAY_TO,
      extra: {
        assetTransferMethod: "payment-channel",
        facilitatorFee: 0,
      },
    });
  });
});

function makeMppEnv(
  overrides: Record<string, string> = {},
): Record<string, string> {
  const client = Surfnet.newKeypair();
  const feePayer = Surfnet.newKeypair();
  const payTo = Surfnet.newKeypair();

  return {
    MPP_HARNESS_RPC_URL: RPC_URL,
    MPP_HARNESS_NETWORK: MPP_NETWORK,
    MPP_HARNESS_MINT: MINT,
    MPP_HARNESS_AMOUNT: "1000",
    MPP_HARNESS_PRICE: "0.001",
    MPP_HARNESS_RESOURCE_PATH: RESOURCE_PATH,
    MPP_HARNESS_SETTLEMENT_HEADER: SETTLEMENT_HEADER,
    MPP_HARNESS_SECRET_KEY: "mpp-harness-unpaid-smoke-secret-pad",
    MPP_HARNESS_PAY_TO: payTo.publicKey,
    MPP_HARNESS_CLIENT_SECRET_KEY: JSON.stringify(
      Array.from(client.secretKey),
    ),
    MPP_HARNESS_FEE_PAYER_SECRET_KEY: JSON.stringify(
      Array.from(feePayer.secretKey),
    ),
    MPP_HARNESS_SPLITS: "[]",
    ...overrides,
  };
}

function makeX402Env(
  overrides: Record<string, string> = {},
): Record<string, string> {
  const facilitator = Surfnet.newKeypair();
  const payTo = Surfnet.newKeypair();

  return {
    X402_HARNESS_RPC_URL: RPC_URL,
    X402_HARNESS_NETWORK: X402_NETWORK,
    X402_HARNESS_MINT: MINT,
    X402_HARNESS_PAY_TO: payTo.publicKey,
    X402_HARNESS_PRICE: "0.001",
    X402_HARNESS_RESOURCE_PATH: RESOURCE_PATH,
    X402_HARNESS_SETTLEMENT_HEADER: SETTLEMENT_HEADER,
    X402_HARNESS_FACILITATOR_SECRET_KEY: JSON.stringify(
      Array.from(facilitator.secretKey),
    ),
    X402_HARNESS_FACILITATOR_ADDRESS: facilitator.publicKey,
    ...overrides,
  };
}

function requireHeader(response: Response, name: string): string {
  const value = response.headers.get(name);
  expect(value, `${name} header`).toBeTruthy();
  return value ?? "";
}

function decodePaymentRequired(response: Response): {
  x402Version?: number;
  resource?: unknown;
  accepts?: Array<Record<string, unknown>>;
} {
  const value = requireHeader(response, "payment-required");
  return JSON.parse(Buffer.from(value, "base64").toString("utf8")) as {
    x402Version?: number;
    resource?: unknown;
    accepts?: Array<Record<string, unknown>>;
  };
}
