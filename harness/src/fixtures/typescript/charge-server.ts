import http from "node:http";
import { createKeyPairSignerFromBytes } from "@solana/kit";
import { Mppx, solana } from "@solana/mpp/server";
import { injectCanonicalCode } from "../../canonical-codes";
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
  const isSolNative = environment.assetKind === "sol";
  const currency = isSolNative ? "sol" : environment.mint;
  // G28a. `solana.charge({ splits })` validates split count at
  // construction time and throws on > 8 entries. That one specific
  // construct-time rejection is the correct 402-class outcome and
  // gets surfaced as `challenge_unavailable` on protected requests.
  // Other Mppx.create failures (bad signer, unsupported currency,
  // env regressions) must crash the fixture so the harness sees a
  // real error instead of a misleading 402 (Codex review of this
  // PR). We allowlist by error message text rather than catching all.
  // The exact return type of Mppx.create depends on the inferred
  // methods tuple, which Typescript widens here. `unknown` plus a
  // narrow cast at the call site is sufficient for the fixture.
  let mppx: unknown;
  let constructError: Error | undefined;
  // B34 / push-mode: when the harness drives this server in push mode
  // the route MUST NOT advertise a server-side fee payer. Omitting
  // `signer` removes `feePayer/feePayerKey` from the challenge so the
  // push verifier accepts the client-built, client-broadcast tx.
  const pushMode = environment.paymentMode === "push";
  try {
    mppx = Mppx.create({
      secretKey: environment.secretKey,
      methods: [
        solana.charge({
          recipient: environment.payTo,
          currency,
          decimals: environment.decimals,
          network: environment.network,
          rpcUrl: environment.rpcUrl,
          ...(pushMode ? {} : { signer: feePayerSigner }),
          splits: environment.splits,
        }),
      ],
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (!/splits cannot exceed/i.test(message)) {
      throw error;
    }
    constructError = error instanceof Error ? error : new Error(message);
  }

  // Capture the underlying SDK error message that mppx logs but
  // strips from the wire response. The TS Mppx wraps any non-PaymentError
  // thrown by `verify` into a generic `VerificationFailedError` (see
  // mppx/src/server/Mppx.ts:425) and only emits `console.error('mppx:
  // internal verification error', e)` with the original cause. Without
  // this capture, the fixture cannot distinguish `signature_consumed`
  // from `payment_invalid` on the 402 body the harness asserts on.
  let lastInternalError: string | undefined;
  const originalConsoleError = console.error.bind(console);
  console.error = (...args: unknown[]) => {
    const first = args[0];
    if (typeof first === "string" && first.includes("mppx: internal verification error")) {
      const cause = args[1];
      lastInternalError =
        cause instanceof Error ? cause.message : String(cause ?? "");
    }
    originalConsoleError(...(args as []));
  };

  const server = http.createServer(async (request, response) => {
    lastInternalError = undefined;
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

      if (!mppx || constructError) {
        response.writeHead(402, { "content-type": "application/json" });
        // G39: surface a canonical L6 code on every 402. The harness
        // fault matrix asserts `responseBody.code` so the server fixture
        // must always emit one, even on construct-time rejections.
        response.end(
          injectCanonicalCode(
            JSON.stringify({
              error: "challenge_unavailable",
              message: constructError?.message ?? "mppx not initialized",
            }),
          ),
        );
        return;
      }

      const result = await (
        mppx as {
          charge: (params: {
            amount: string;
            currency: string;
            description: string;
          }) => (request: Request) => Promise<{
            status: number;
            challenge?: Response;
            withReceipt: (response: Response) => Response;
          }>;
        }
      ).charge({
        amount: amountForPath(url.pathname, environment),
        currency,
        description: "Surfpool-backed protected content",
      })(toWebRequest(request, body));

      if (result.status === 402) {
        const challenge = result.challenge as Response;
        response.writeHead(
          challenge.status,
          Object.fromEntries(challenge.headers),
        );
        // G39: surface a canonical L6 code on every 402. The TS SDK
        // emits free-text messages today; the fixture classifies them
        // into canonical codes at the response boundary so the harness
        // fault matrix has something to assert on.
        const challengeBody = await challenge.text();
        // Enrich the 402 body with the captured SDK-internal error
        // message so injectCanonicalCode can classify replay-store hits
        // and HMAC mismatches that mppx otherwise generalizes to
        // "Payment verification failed."
        let enriched = challengeBody;
        if (lastInternalError) {
          try {
            const parsed = JSON.parse(challengeBody) as Record<string, unknown>;
            parsed.message = lastInternalError;
            enriched = JSON.stringify(parsed);
          } catch {
            // leave as-is
          }
        }
        response.end(injectCanonicalCode(enriched));
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
      const message = error instanceof Error ? error.message : String(error);
      // Cross-server portability / idempotent resubmit: the TS SDK
      // surfaces replay-store hits and HMAC mismatches as thrown errors
      // during settlement rather than as a structured 402. The harness
      // expects a canonical 402 for these classes, so we translate any
      // verification-class thrown error into the canonical 402 shape
      // here and let injectCanonicalCode pick the snake_case code.
      if (isVerificationClassError(message)) {
        response.writeHead(402, { "content-type": "application/json" });
        response.end(
          injectCanonicalCode(
            JSON.stringify({
              error: "verification_failed",
              message,
            }),
          ),
        );
        return;
      }
      response.writeHead(500, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: message }));
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

function isVerificationClassError(message: string): boolean {
  return (
    /already consumed/i.test(message) ||
    /signature already consumed/i.test(message) ||
    /already been processed/i.test(message) ||
    /transaction already processed/i.test(message) ||
    /challenge verification failed/i.test(message) ||
    /challenge id mismatch/i.test(message) ||
    /not issued by this server/i.test(message) ||
    /challenge expired/i.test(message) ||
    /amount mismatch/i.test(message) ||
    /currency mismatch/i.test(message) ||
    /recipient mismatch/i.test(message) ||
    /method details mismatch/i.test(message) ||
    /credential method does not match/i.test(message) ||
    /credential intent is not a charge/i.test(message) ||
    /credential realm does not match/i.test(message)
  );
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
