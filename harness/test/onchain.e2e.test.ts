/**
 * On-chain settlement E2E — the regression net the structural harness lacks.
 *
 * Boots a mainnet-forking surfnet (@solana/surfpool 1.4, which executes the
 * deployed payment-channels program) and drives the real pay-kit client/server
 * end-to-end. A success is only returned after settlement CONFIRMS on-chain, so
 * this catches settlement-class regressions the byte-shape harness cannot — e.g.
 * the `TreasuryAccountMismatch` (0x961) that made `upto` silently 402 after
 * payment. (surfpool-sdk 1.2 could not run the program — "unsupported BPF
 * instruction" — which is a chief reason these regressions evaded local CI.)
 *
 * Network-gated: surfpool forks from a mainnet datasource RPC. Set
 * HARNESS_ONCHAIN=1 to run; SURFPOOL_DATASOURCE_RPC_URL sets that datasource
 * (same as the rest of the surfpool CI; defaults to public mainnet).
 */
import { generateKeyPairSigner, type KeyPairSigner } from "@solana/kit";
import { createPayKit, usage, usd } from "@solana/pay-kit";
import { createPayKitClient } from "@solana/pay-kit/client";
import express, { type Request, type Response } from "express";
import type { Server } from "node:http";
import crypto from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { startOnchainSurfnet, PAYMENT_CHANNELS_PROGRAM, type OnchainSurfnet } from "../src/onchain/surfnet.js";

const RUN = process.env.HARNESS_ONCHAIN === "1";
const PRICE_PER_TOKEN = 100n;

let net: OnchainSurfnet;
let operator: KeyPairSigner;
let server: Server;
let baseUrl: string;

async function startServer(): Promise<void> {
  const pay = await createPayKit({
    accept: ["x402", "mpp"],
    mpp: { challengeBindingSecret: crypto.randomBytes(32).toString("hex") },
    network: "localnet",
    operator: { recipient: operator.address, signer: operator },
    pricing: {
      // x402 `upto` — settles by invoking the payment-channels program
      // (settle_and_finalize + distribute). This is the scheme that regressed.
      summarize: usage(usd("0.1"), { description: "Summarize, billed per token" }),
      // Fixed charge baseline (MPP / x402 exact — SPL transfer).
      fortune: { amount: usd("0.01"), description: "A fortune cookie" },
    },
    rpcUrl: net.rpcUrl,
  });

  const app = express();
  app.post(
    "/api/v1/summarize",
    express.text({ type: "*/*" }),
    pay.express("summarize"),
    (req: Request, res: Response) => {
      const body = typeof req.body === "string" ? req.body : "";
      const tokens = BigInt(Math.max(1, Math.floor(body.length / 4)));
      pay.charge(req)?.charge(tokens * PRICE_PER_TOKEN);
      res.json({ billedBaseUnits: (tokens * PRICE_PER_TOKEN).toString(), tokens: tokens.toString() });
    },
  );
  app.get("/api/v1/fortune", pay.express("fortune"), (_req: Request, res: Response) => {
    res.json({ fortune: "You will catch this regression." });
  });

  await new Promise<void>((resolve) => {
    server = app.listen(0, "127.0.0.1", () => resolve());
  });
  const addr = server.address();
  if (!addr || typeof addr === "string") throw new Error("no server port");
  baseUrl = `http://127.0.0.1:${addr.port}`;
}

async function freshFundedClient(): Promise<KeyPairSigner> {
  const signer = await generateKeyPairSigner();
  net.fundUsdc(signer.address, 100_000_000); // 100 USDC
  net.fundSol(signer.address, 2_000_000_000); // 2 SOL
  return signer;
}

/** Pay `path` and assert the server returns 200 — which only happens after
 * settlement confirms on-chain (a settlement failure surfaces as a 402). */
async function payAndAssertSettled(path: string, init: RequestInit, protocol: "x402" | "mpp"): Promise<void> {
  const client = await createPayKitClient({ rpcUrl: net.rpcUrl, signer: await freshFundedClient(), onProgress: () => {} });
  const res = await client.fetch(`${baseUrl}${path}`, init, protocol);
  const text = await res.text().catch(() => "<unreadable>");
  expect(res.status, `settlement did not confirm on-chain: ${res.status} ${text}`).toBe(200);
}

describe.skipIf(!RUN)("on-chain settlement (mainnet fork, real program)", () => {
  beforeAll(async () => {
    net = await startOnchainSurfnet();
    await net.awaitProgram(PAYMENT_CHANNELS_PROGRAM);
    operator = await generateKeyPairSigner();
    net.fundSol(operator.address, 5_000_000_000); // fees + ATA rent
    net.fundUsdc(operator.address, 0); // pre-create payee ATA
    await startServer();
  }, 60_000);

  afterAll(() => {
    server?.close();
    net?.stop();
  });

  // The exact regression that bit us: TreasuryAccountMismatch (0x961) failed the
  // distribute step, silently 402-ing after payment. With the treasury owner
  // aligned to the deployed program, this settles 200.
  it("x402 upto settles on-chain (TreasuryAccountMismatch regression)", async () => {
    await payAndAssertSettled(
      "/api/v1/summarize",
      { method: "POST", body: "The quick brown fox jumps over the lazy dog. ".repeat(20) },
      "x402",
    );
  }, 90_000);

  it("x402 exact charge settles on-chain", async () => {
    await payAndAssertSettled("/api/v1/fortune", { method: "GET" }, "x402");
  }, 60_000);

  it("mpp charge settles on-chain", async () => {
    await payAndAssertSettled("/api/v1/fortune", { method: "GET" }, "mpp");
  }, 60_000);
});

/*
 * MATRIX GAPS (explicit — no client/server today; not yet covered):
 *   - x402 upto:             Go, Python   (no svm payment-channel client)
 *   - x402 batch-settlement: Go, Python   (Rust + TS only)
 *   - mpp subscription:      TS, Go, Python (Rust SDK only; needs plan bootstrap)
 *   - mpp session:           Go, TS, Ruby, Lua servers (Python/Rust only)
 * Per-language on-chain coverage lands by registering process adapters for these
 * schemes against this same forked-surfnet bootstrap.
 */
