// ts-x402 server adapter: a @solana/pay-kit x402 `exact` gate.
//
// Env in (X402_HARNESS_*, same as the Rust adapter), JSON out: prints one
// `ready` line with the bound port, then serves
//   GET X402_HARNESS_RESOURCE_PATH         priced at X402_HARNESS_PRICE
//   GET MPP_HARNESS_REPLAY_SOURCE_PATH     priced at MPP_HARNESS_REPLAY_SOURCE_PRICE
//                                          (cross-route replay scenarios only)
//   GET /health
// Every paid route is `pay.fetch(gate, handler)`: pay-kit issues the 402,
// verifies the credential with the @x402/svm exact facilitator and settles
// it on X402_HARNESS_RPC_URL with the operator (X402_HARNESS_FACILITATOR_
// SECRET_KEY) as fee payer. The adapter only translates node:http to fetch
// and adds the harness's canonical `code` to a rejection.
//
// pay-kit prices gates in USD settled in a stablecoin and resolves the mint
// itself. The adapter refuses to start when that mint or the base-unit
// amount differs from the scenario's, rather than advertise a different
// payment than the harness funded.

import http from "node:http";
import type { AddressInfo } from "node:net";
import { createPayKit, type PricingDef, Signer, usd } from "@solana/pay-kit";
import { classifyMessageToCanonicalCode } from "../../canonical-codes";
import { readX402ServerEnvironment } from "./exact-shared";

// @x402/svm reason codes whose meaning the shared classifier cannot read
// from the words alone.
const SDK_CODE_TO_CANONICAL: Record<string, string> = {
  duplicate_settlement: "signature_consumed",
};

function canonicalCode(sdkCode: string, detail: string | undefined): string {
  const mapped = SDK_CODE_TO_CANONICAL[sdkCode];
  if (mapped) return mapped;
  // @x402/svm codes are snake_case phrases ("..._amount_mismatch").
  return classifyMessageToCanonicalCode(`${sdkCode} ${detail ?? ""}`.replace(/_/g, " "));
}

function toRequest(req: http.IncomingMessage, origin: string): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    headers.set(name, Array.isArray(value) ? value.join(", ") : value);
  }
  return new Request(new URL(req.url ?? "/", origin), { headers, method: req.method ?? "GET" });
}

async function writeResponse(res: http.ServerResponse, response: Response): Promise<void> {
  let body = await response.text();
  if (response.status === 402) {
    try {
      const parsed = JSON.parse(body) as Record<string, unknown>;
      if (typeof parsed.code === "string") {
        parsed.sdkCode = parsed.code;
        parsed.code = canonicalCode(parsed.code, typeof parsed.detail === "string" ? parsed.detail : undefined);
        body = JSON.stringify(parsed);
      }
    } catch {
      // Not JSON: forward verbatim.
    }
  }
  const headers: Record<string, string> = {};
  response.headers.forEach((value, name) => {
    if (name !== "content-length") headers[name] = value;
  });
  res.writeHead(response.status, headers);
  res.end(body);
}

async function main(): Promise<void> {
  const env = readX402ServerEnvironment();
  const operator = await Signer.bytes(env.facilitatorSecretKey);
  const pricing: PricingDef = {
    protected: { accept: ["x402"], amount: usd(env.price, "USDC") },
    ...(env.replaySource
      ? { replaySource: { accept: ["x402"], amount: usd(env.replaySource.price, "USDC") } }
      : {}),
  };
  const pay = await createPayKit({
    accept: ["x402"],
    network: env.network,
    operator: { recipient: env.payTo, signer: operator },
    pricing,
    rpcUrl: env.rpcUrl,
  });

  const paidHandler = (request: Request, payment: { transaction: string }) =>
    Response.json(
      { ok: true, paid: true, settlement: { success: true, transaction: payment.transaction } },
      { headers: { [env.settlementHeader]: payment.transaction } },
    );
  const routes = new Map<string, (request: Request) => Promise<Response>>([
    [env.resourcePath, pay.fetch("protected", paidHandler)],
  ]);
  if (env.replaySource) {
    routes.set(env.replaySource.resourcePath, pay.fetch("replaySource", paidHandler));
  }

  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    if (url.pathname === "/health") {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }
    const route = routes.get(url.pathname);
    if (!route) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }
    const origin = `http://${req.headers.host ?? "127.0.0.1"}`;
    route(toRequest(req, origin))
      .then((response) => writeResponse(res, response))
      .catch((error: unknown) => {
        console.error("ts-x402 server error:", error);
        res.writeHead(500, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: error instanceof Error ? error.message : String(error) }));
      });
  });

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;

  // Refuse to serve a payment the scenario did not ask for (see header).
  const challenge = await routes.get(env.resourcePath)!(
    new Request(`http://127.0.0.1:${port}${env.resourcePath}`),
  );
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
      capabilities: ["exact"],
    }),
  );

  const shutdown = () => server.close(() => process.exit(0));
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
