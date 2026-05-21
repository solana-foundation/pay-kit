import http from "node:http";
import { createKeyPairSignerFromBytes } from "@solana/kit";
import { Mppx, solana } from "@solana/mpp/server";
import { readInteropEnvironment } from "./shared";

function toWebRequest(request: http.IncomingMessage, body: string): Request {
  const headers = new Headers();
  for (const [key, value] of Object.entries(request.headers)) {
    if (value) {
      headers.set(key, Array.isArray(value) ? value[0] : value);
    }
  }

  return new Request(`http://127.0.0.1${request.url ?? "/"}`, {
    method: request.method,
    headers,
    body: body || undefined,
  });
}

function decodeReceiptReference(
  receiptHeader: string | null,
): string | undefined {
  if (!receiptHeader) {
    return undefined;
  }

  const padded = receiptHeader.replace(/-/g, "+").replace(/_/g, "/");
  const receipt = JSON.parse(
    Buffer.from(padded, "base64").toString("utf8"),
  ) as {
    reference?: string;
  };
  return receipt.reference;
}

async function main() {
  const environment = readInteropEnvironment();
  const feePayerSigner = await createKeyPairSignerFromBytes(
    environment.feePayerSecretKey,
  );
  const mppx = Mppx.create({
    secretKey: environment.secretKey,
    methods: [
      solana.charge({
        recipient: environment.payTo,
        currency: environment.mint,
        decimals: 6,
        network: environment.network,
        rpcUrl: environment.rpcUrl,
        signer: feePayerSigner,
        splits: environment.splits,
      }),
    ],
  });

  const server = http.createServer(async (request, response) => {
    try {
      const chunks: Buffer[] = [];
      for await (const chunk of request) {
        chunks.push(chunk as Buffer);
      }
      const body = Buffer.concat(chunks).toString();
      const url = new URL(request.url ?? "/", "http://127.0.0.1");

      if (url.pathname === "/health") {
        response.writeHead(200, { "content-type": "application/json" });
        response.end(JSON.stringify({ ok: true }));
        return;
      }

      if (
        request.method !== "GET" ||
        !isProtectedPath(url.pathname, environment)
      ) {
        response.writeHead(404, { "content-type": "application/json" });
        response.end(JSON.stringify({ error: "not_found" }));
        return;
      }

      const result = await mppx.charge({
        amount: amountForPath(url.pathname, environment),
        currency: environment.mint,
        description: "Surfpool-backed protected content",
      })(toWebRequest(request, body));

      if (result.status === 402) {
        const challenge = result.challenge as Response;
        response.writeHead(
          challenge.status,
          Object.fromEntries(challenge.headers),
        );
        response.end(await challenge.text());
        return;
      }

      const paid = result.withReceipt(
        Response.json({
          ok: true,
          paid: true,
        }),
      ) as Response;
      const headers = new Headers(paid.headers);
      const settlement = decodeReceiptReference(headers.get("payment-receipt"));
      if (settlement) {
        headers.set(environment.settlementHeader, settlement);
      }

      response.writeHead(paid.status, Object.fromEntries(headers));
      response.end(await paid.text());
    } catch (error) {
      response.writeHead(500, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          error: error instanceof Error ? error.message : String(error),
        }),
      );
    }
  });

  server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Failed to bind TypeScript interop server");
    }

    console.log(
      JSON.stringify({
        type: "ready",
        implementation: "typescript",
        role: "server",
        port: address.port,
        capabilities: ["charge"],
      }),
    );
  });

  const shutdown = () => {
    server.close(() => process.exit(0));
  };

  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

function isProtectedPath(
  path: string,
  environment: ReturnType<typeof readInteropEnvironment>,
): boolean {
  return (
    path === environment.resourcePath ||
    path === environment.replaySource?.resourcePath
  );
}

function amountForPath(
  path: string,
  environment: ReturnType<typeof readInteropEnvironment>,
): string {
  if (path === environment.replaySource?.resourcePath) {
    return environment.replaySource.amount;
  }
  return environment.amount;
}

void main();
