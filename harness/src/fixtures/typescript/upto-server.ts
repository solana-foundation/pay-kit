// ts-x402 upto server adapter: a @solana/pay-kit `usage` (x402 `upto`) gate.
//
// Env in (X402_HARNESS_*, same as the Rust upto adapter
// rust/crates/harness-bins/src/bin/x402_harness_upto_server.rs), JSON out:
// prints one `ready` line with the bound port, then serves
//   GET X402_HARNESS_RESOURCE_PATH   authorizes up to X402_HARNESS_PRICE and
//                                    settles X402_HARNESS_ACTUAL_AMOUNT
//   GET /health
// The route is `pay.fetch(gate, handler)` on a `usage` gate: pay-kit issues
// the 402, verifies and broadcasts the client's channel `open` with the
// vendored @x402/svm upto facilitator (its open + settle + distribute
// readiness simulation included), then settles the metered amount with
// settle_and_seal and distribute. The operator (X402_HARNESS_FEE_PAYER_SECRET_KEY)
// is fee payer, rent payer, receiver authorizer and recipient. The handler
// only reports the metered amount through the SDK's `charge` meter; the
// adapter translates node:http to fetch and exposes the settlement signature
// pay-kit recorded on the scenario's settlement header.

import http from "node:http";
import type { AddressInfo } from "node:net";
import { createPayKit, Signer, usage, usd } from "@solana/pay-kit";
import { readX402ServerEnvironment } from "./exact-shared";

function readRequiredEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.trim() === "") throw new Error(`${name} is required`);
  return value;
}

function toRequest(req: http.IncomingMessage, origin: string): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    headers.set(name, Array.isArray(value) ? value.join(", ") : value);
  }
  return new Request(new URL(req.url ?? "/", origin), { headers, method: req.method ?? "GET" });
}

async function writeResponse(
  res: http.ServerResponse,
  response: Response,
  extraHeaders: Record<string, string>,
): Promise<void> {
  const body = await response.text();
  const headers: Record<string, string> = {};
  response.headers.forEach((value, name) => {
    if (name !== "content-length") headers[name] = value;
  });
  res.writeHead(response.status, { ...headers, ...extraHeaders });
  res.end(body);
}

async function main(): Promise<void> {
  const env = readX402ServerEnvironment();
  const operator = await Signer.bytes(
    new Uint8Array(JSON.parse(readRequiredEnv("X402_HARNESS_FEE_PAYER_SECRET_KEY")) as number[]),
  );
  const actualAmount = BigInt(process.env.X402_HARNESS_ACTUAL_AMOUNT ?? "0");
  const pay = await createPayKit({
    accept: ["x402"],
    network: env.network,
    operator: { recipient: env.payTo, signer: operator },
    pricing: { usage: usage(usd(env.price, "USDC")) },
    rpcUrl: env.rpcUrl,
  });

  const route = pay.fetch("usage", (request) => {
    pay.charge(request)?.charge(actualAmount);
    return Response.json({ ok: true, paid: true });
  });

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (url.pathname === "/health") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    if (url.pathname !== env.resourcePath) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }
    const request = toRequest(req, `http://${req.headers.host ?? "127.0.0.1"}`);
    route(request)
      .then((response) => {
        // pay-kit records the settlement transaction on the request's payment.
        const transaction = pay.payment(request)?.transaction;
        return writeResponse(
          res,
          response,
          response.status === 200 && transaction ? { [env.settlementHeader]: transaction } : {},
        );
      })
      .catch((error: unknown) => {
        console.error("ts-x402 upto server error:", error);
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
      });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;

  // Refuse to serve a payment the scenario did not ask for (see exact-server.ts).
  const challenge = await route(new Request(`http://127.0.0.1:${port}${env.resourcePath}`));
  const offered = (await challenge.json()) as { accepts?: { amount?: string; asset?: string }[] };
  const offer = offered.accepts?.[0];
  if (offer?.asset !== env.mint || (env.amount !== undefined && offer.amount !== env.amount)) {
    throw new Error(
      `pay-kit prices ${env.price} USD on ${env.network} as ${offer?.amount} of ${offer?.asset}; ` +
        `the scenario expects ${env.amount ?? "(any)"} of ${env.mint}`,
    );
  }

  console.log(
    JSON.stringify({
      type: "ready",
      implementation: "typescript",
      role: "server",
      port,
      capabilities: ["upto"],
    }),
  );

  const shutdown = () => server.close(() => process.exit(0));
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
