// TypeScript reference x402 `exact` interop server.
//
// Wire-compatible with `rust/crates/x402/src/bin/interop_server.rs`:
// - 402 carries a `PAYMENT-REQUIRED` header whose value is the
//   base64 of the JSON envelope `{x402Version, accepts, resource}`.
// - The credential is delivered in the `PAYMENT-SIGNATURE` header.
// - On successful settlement, the response includes
//   `PAYMENT-RESPONSE` and the fixture settlement header.
//
// This fixture deliberately keeps the SDK surface area minimal so the
// adapter is portable across pay-kit checkouts. The cross-language
// matrix is the load-bearing path; this adapter exists so language
// adapters have a TS counterpart to pair against while the canonical
// SDK lands. End-to-end verification against a live Surfpool RPC is
// driven by the matrix runner.

import http from "node:http";
import {
  PAYMENT_REQUIRED_HEADER,
  PAYMENT_RESPONSE_HEADER,
  PAYMENT_SIGNATURE_HEADER,
  X402_VERSION_V2,
  readX402ServerEnvironment,
} from "./exact-shared";

const TOKEN_DECIMALS = 6;
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

type PaymentRequirement = {
  scheme: "exact";
  network: string;
  resource: string;
  description: string;
  mimeType: string;
  payTo: string;
  asset: string;
  maxAmountRequired: string;
  maxTimeoutSeconds: number;
  extra: {
    decimals: number;
    tokenProgram?: string;
    feePayer?: string;
  };
};

function buildRequirements(
  env: ReturnType<typeof readX402ServerEnvironment>,
): PaymentRequirement[] {
  const primary: PaymentRequirement = {
    scheme: "exact",
    network: env.network,
    resource: env.resourcePath,
    description: "Surfpool-backed protected content",
    mimeType: "application/json",
    payTo: env.payTo,
    asset: env.mint,
    maxAmountRequired: env.price,
    maxTimeoutSeconds: 60,
    extra: {
      decimals: TOKEN_DECIMALS,
      tokenProgram: TOKEN_PROGRAM,
    },
  };

  const extras: PaymentRequirement[] = env.extraOfferedMints.map(mint => ({
    scheme: "exact",
    network: env.network,
    resource: env.resourcePath,
    description: "Surfpool-backed protected content",
    mimeType: "application/json",
    payTo: env.payTo,
    asset: mint,
    maxAmountRequired: env.price,
    maxTimeoutSeconds: 60,
    extra: { decimals: TOKEN_DECIMALS },
  }));

  return [primary, ...extras];
}

function encodePaymentRequiredHeader(accepts: PaymentRequirement[]): string {
  const envelope = {
    x402Version: X402_VERSION_V2,
    accepts,
    resource: accepts[0]?.resource,
    error: null,
  };
  return Buffer.from(JSON.stringify(envelope), "utf8").toString("base64");
}

type DecodedCredential = {
  x402Version?: number;
  accepted?: {
    scheme?: string;
    network?: string;
    asset?: string;
    payTo?: string;
    amount?: string;
  };
  payload?: {
    challengeId?: string;
    resource?: string;
  };
  resource?: string;
};

function decodeCredential(headerValue: string): DecodedCredential | null {
  try {
    const decoded = Buffer.from(headerValue, "base64").toString("utf8");
    return JSON.parse(decoded) as DecodedCredential;
  } catch {
    return null;
  }
}

type RejectReason = {
  code:
    | "payment_invalid"
    | "wrong_network"
    | "charge_request_mismatch"
    | "challenge_verification_failed";
  message: string;
};

function classifyCredential(
  credential: DecodedCredential | null,
  accepts: PaymentRequirement[],
  requestedResource: string,
): { offer: PaymentRequirement; credentialKey: string } | { reject: RejectReason } {
  if (!credential || !credential.accepted || !credential.payload) {
    return {
      reject: {
        code: "payment_invalid",
        message: "credential is missing accepted/payload fields",
      },
    };
  }

  const offer = accepts.find(
    candidate =>
      candidate.asset === credential.accepted?.asset &&
      candidate.network === credential.accepted?.network &&
      candidate.scheme === credential.accepted?.scheme,
  );

  if (!offer) {
    // Could be either network mismatch or no matching offer.
    if (
      credential.accepted.network &&
      !accepts.some(c => c.network === credential.accepted?.network)
    ) {
      return {
        reject: {
          code: "wrong_network",
          message: `credential network ${credential.accepted.network} does not match server`,
        },
      };
    }
    return {
      reject: {
        code: "charge_request_mismatch",
        message: "no offered requirement matches the credential",
      },
    };
  }

  if (offer.payTo !== credential.accepted.payTo) {
    return {
      reject: {
        code: "charge_request_mismatch",
        message: "recipient does not match",
      },
    };
  }

  if (offer.maxAmountRequired !== credential.accepted.amount) {
    return {
      reject: {
        code: "charge_request_mismatch",
        message: "amount does not match",
      },
    };
  }

  const credentialResource = credential.payload.resource ?? credential.resource;
  if (credentialResource && credentialResource !== requestedResource) {
    return {
      reject: {
        code: "charge_request_mismatch",
        message: `credential resource ${credentialResource} does not match requested ${requestedResource}`,
      },
    };
  }

  const challengeId = credential.payload.challengeId;
  if (!challengeId || typeof challengeId !== "string") {
    return {
      reject: {
        code: "challenge_verification_failed",
        message: "credential payload missing challengeId",
      },
    };
  }

  return { offer, credentialKey: challengeId };
}

async function main() {
  const env = readX402ServerEnvironment();
  const accepts = buildRequirements(env);
  const paymentRequiredHeader = encodePaymentRequiredHeader(accepts);

  // Track consumed credentials by challengeId to surface
  // `signature_consumed` on idempotent resubmit.
  const consumed = new Set<string>();
  // Track challenge IDs this server has issued (recognised when a
  // credential's payload.challengeId matches). Cross-server portability:
  // server B sees a credential carrying an id only server A issued, so B
  // rejects with `challenge_verification_failed`. A real x402 facilitator
  // verifies HMAC over the challenge id with its own secret; this fixture
  // simulates that by tracking issuance in-process.
  const issued = new Set<string>();

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

    const paymentHeader = request.headers[PAYMENT_SIGNATURE_HEADER] as
      | string
      | undefined;

    if (!paymentHeader) {
      // Issue a fresh challenge id so the client can echo it back. The
      // fixture's "verification" is presence-in-`issued`; a real
      // facilitator would HMAC the id with its secret.
      const challengeId = `ts-srv-${Date.now().toString(36)}-${Math.random()
        .toString(36)
        .slice(2, 10)}`;
      issued.add(challengeId);
      response.writeHead(402, {
        "content-type": "application/json",
        [PAYMENT_REQUIRED_HEADER]: paymentRequiredHeader,
        "x-challenge-id": challengeId,
      });
      response.end(
        JSON.stringify({ error: "payment_required", challengeId }),
      );
      return;
    }

    const credential = decodeCredential(paymentHeader);
    const classified = classifyCredential(credential, accepts, env.resourcePath);

    if ("reject" in classified) {
      response.writeHead(402, {
        "content-type": "application/json",
        [PAYMENT_REQUIRED_HEADER]: paymentRequiredHeader,
      });
      response.end(
        JSON.stringify({
          error: classified.reject.code,
          code: classified.reject.code,
          message: classified.reject.message,
        }),
      );
      return;
    }

    const { credentialKey } = classified;

    if (consumed.has(credentialKey)) {
      response.writeHead(402, {
        "content-type": "application/json",
        [PAYMENT_REQUIRED_HEADER]: paymentRequiredHeader,
      });
      response.end(
        JSON.stringify({
          error: "signature_consumed",
          code: "signature_consumed",
          message: "signature already consumed",
        }),
      );
      return;
    }

    // Cross-server portability check: when the client supplies a payload
    // challengeId, it must be one this server issued (or this server
    // never required HMAC issuance). The first paid request that didn't
    // come from this server's 402 will be missing from `issued`.
    if (issued.size > 0 && !issued.has(credentialKey)) {
      response.writeHead(402, {
        "content-type": "application/json",
        [PAYMENT_REQUIRED_HEADER]: paymentRequiredHeader,
      });
      response.end(
        JSON.stringify({
          error: "challenge_verification_failed",
          code: "challenge_verification_failed",
          message: "challenge id was not issued by this server",
        }),
      );
      return;
    }

    consumed.add(credentialKey);

    // Settlement: a real facilitator would broadcast a signed Solana
    // transaction here. The fixture returns a deterministic placeholder
    // so the harness can assert presence of the settlement header.
    const settlement = `ts-x402-exact-${credentialKey.slice(0, 16)}`;
    const paymentResponse = JSON.stringify({
      success: true,
      network: accepts[0]?.network,
      transaction: settlement,
    });

    response.writeHead(200, {
      "content-type": "application/json",
      [env.settlementHeader]: settlement,
      [PAYMENT_RESPONSE_HEADER]: paymentResponse,
    });
    response.end(
      JSON.stringify({
        ok: true,
        paid: true,
        settlement: {
          success: true,
          transaction: settlement,
          network: accepts[0]?.network,
        },
      }),
    );
  });

  server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Failed to bind TypeScript x402 interop server");
    }

    console.log(
      JSON.stringify({
        type: "ready",
        implementation: "typescript",
        role: "server",
        port: address.port,
        capabilities: ["exact"],
      }),
    );
  });

  const shutdown = () => server.close(() => process.exit(0));
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

void main();
