// TypeScript x402 `upto` challenge-only fixture.
//
// This fixture is intentionally not registered as an x402-upto settlement
// adapter. It exists for structural unpaid-access smoke coverage: an unpaid
// protected route must deny access and advertise a valid `upto` challenge
// without requiring the payment-channels program or a live RPC.

import http from "node:http";
import {
  PAYMENT_REQUIRED_HEADER,
  X402_VERSION_V2,
  readX402ServerEnvironment,
  toBaseUnits,
} from "./exact-shared";

const TOKEN_DECIMALS = 6;
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const PAYMENT_CHANNEL_PROGRAM =
  process.env.PAYMENT_CHANNELS_PROGRAM_ID ??
  "CHNLxYvVA28MJP9PrFuDXccuoGXAx7jBacfLEkahyGsX";

type UptoRequirement = {
  scheme: "upto";
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra: {
    assetTransferMethod: "payment-channel";
    channelProgram: string;
    facilitatorAddress: string;
    facilitatorFee: number;
    feePayer: string;
    tokenProgram: string;
  };
};

function encodePaymentRequiredHeader(
  requirement: UptoRequirement,
  resourcePath: string,
): string {
  const envelope = {
    x402Version: X402_VERSION_V2,
    resource: {
      url: resourcePath,
    },
    accepts: [requirement],
    error: null,
  };
  return Buffer.from(JSON.stringify(envelope), "utf8").toString("base64");
}

async function main() {
  const env = readX402ServerEnvironment();
  const amount =
    process.env.X402_HARNESS_AMOUNT ?? toBaseUnits(env.price, TOKEN_DECIMALS);
  const facilitatorAddress =
    process.env.X402_HARNESS_FACILITATOR_ADDRESS ?? env.payTo;
  const requirement: UptoRequirement = {
    scheme: "upto",
    network: env.network,
    amount,
    asset: env.mint,
    payTo: env.payTo,
    maxTimeoutSeconds: 300,
    extra: {
      assetTransferMethod: "payment-channel",
      channelProgram: PAYMENT_CHANNEL_PROGRAM,
      facilitatorAddress,
      facilitatorFee: 0,
      feePayer: facilitatorAddress,
      tokenProgram: TOKEN_PROGRAM,
    },
  };
  const paymentRequiredHeader = encodePaymentRequiredHeader(
    requirement,
    env.resourcePath,
  );

  const server = http.createServer((request, response) => {
    const url = new URL(request.url ?? "/", "http://127.0.0.1");

    if (url.pathname === "/health") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true }));
      return;
    }

    if (url.pathname !== env.resourcePath) {
      response.writeHead(404, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: "not_found" }));
      return;
    }

    response.writeHead(402, {
      "content-type": "application/json",
      [PAYMENT_REQUIRED_HEADER]: paymentRequiredHeader,
    });
    response.end(
      JSON.stringify({
        error: "payment_required",
        accepts: [requirement],
      }),
    );
  });

  server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Failed to bind TypeScript x402 upto challenge server");
    }

    console.log(
      JSON.stringify({
        type: "ready",
        implementation: "typescript",
        role: "server",
        port: address.port,
        capabilities: ["upto-challenge"],
      }),
    );
  });

  const shutdown = () => server.close(() => process.exit(0));
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

void main();
