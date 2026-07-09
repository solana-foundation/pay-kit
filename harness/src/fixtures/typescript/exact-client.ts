// TypeScript reference x402 `exact` harness client.
//
// Shares the same `X402_HARNESS_*` env-var contract and ready/result
// JSON protocol as the Rust spine (`rust/crates/x402/src/bin/
// harness_client.rs`). Sends an unpaid GET, parses the base64
// `PAYMENT-REQUIRED` envelope, selects an offer (`preferredCurrencies`
// first) and resubmits with `PAYMENT-SIGNATURE`. Prints one result
// JSON line to stdout.
//
// Scope: the fixture carries a stub credential payload (challenge id +
// resource) so the harness wiring, negative-code classification, and
// cross-server portability + idempotent-resubmit flows can run without
// a full Solana signer. Real SVM PaymentProof construction (signed
// VersionedTransaction or settled signature) lives in the Rust spine
// and the TS SDK port; this client only pairs against the TS reference
// server in the default matrix (see `test/x402-exact.e2e.test.ts`).

import {
  PAYMENT_REQUIRED_HEADER,
  PAYMENT_SIGNATURE_HEADER,
  readX402ClientEnvironment,
} from "./exact-shared";

type PaymentRequirement = {
  scheme: string;
  network: string;
  resource?: string;
  payTo: string;
  asset: string;
  maxAmountRequired: string;
  extra?: { decimals?: number; tokenProgram?: string };
};

type PaymentRequiredEnvelope = {
  x402Version: number;
  accepts: PaymentRequirement[];
  resource?: string;
};

const STABLECOIN_MINTS: Record<string, Record<string, string>> = {
  USDC: {
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp":
      "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1":
      "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
  },
  PYUSD: {
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp":
      "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
  },
};

function resolveMint(currency: string, network: string): string {
  const upper = currency.toUpperCase();
  const byNetwork = STABLECOIN_MINTS[upper];
  if (byNetwork && byNetwork[network]) {
    return byNetwork[network];
  }
  return currency;
}

function pickOffer(
  envelope: PaymentRequiredEnvelope,
  preferred: string[],
  network: string,
): PaymentRequirement | undefined {
  const supported = envelope.accepts.filter(
    offer => offer.scheme === "exact" && offer.network === network,
  );
  if (supported.length === 0) {
    return undefined;
  }
  if (preferred.length === 0) {
    return supported[0];
  }
  for (const wanted of preferred) {
    const wantedMint = resolveMint(wanted, network);
    const match = supported.find(offer => offer.asset === wantedMint);
    if (match) return match;
  }
  return supported[0];
}

function decodePaymentRequired(headerValue: string | null): PaymentRequiredEnvelope | null {
  if (!headerValue) return null;
  try {
    const raw = Buffer.from(headerValue, "base64").toString("utf8");
    return JSON.parse(raw) as PaymentRequiredEnvelope;
  } catch {
    return null;
  }
}

async function readResponseBody(response: Response): Promise<unknown> {
  const raw = await response.text();
  try {
    return JSON.parse(raw);
  } catch {
    return raw;
  }
}

async function main() {
  const env = readX402ClientEnvironment();
  const resubmitUrl = process.env.MPP_HARNESS_RESUBMIT_URL;
  if (resubmitUrl) {
    await runResubmitFlow(env.targetUrl, resubmitUrl, env);
    return;
  }

  const paidResponse = process.env.MPP_HARNESS_REPLAY_SOURCE_PATH
    ? await runCrossRouteReplay(env.targetUrl, env)
    : await payTarget(env.targetUrl, env);

  await reportResult(paidResponse, env.settlementHeader);
}

async function buildCredentialHeader(
  targetUrl: string,
  env: ReturnType<typeof readX402ClientEnvironment>,
): Promise<string> {
  const firstResponse = await fetch(targetUrl);
  const envelope = decodePaymentRequired(
    firstResponse.headers.get(PAYMENT_REQUIRED_HEADER),
  );

  if (!envelope) {
    throw new Error(
      `missing or unparseable PAYMENT-REQUIRED header (status ${firstResponse.status}): ` +
        JSON.stringify(await readResponseBody(firstResponse)),
    );
  }

  const offer = pickOffer(envelope, env.preferredCurrencies, env.network);
  if (!offer) {
    throw new Error(`no offer matched network ${env.network}`);
  }

  // Credential payload mirrors the canonical x402 `exact` shape: an
  // adapter-specific id plus the offer the client is committing to.
  // A live SDK would also embed a signed Solana transaction here; the
  // matrix runner uses the rust spine for the actual on-chain
  // settlement assertions. The TS fixture's role is wire-level
  // protocol compliance.
  // Use the server-issued challenge id if present (TS reference server
  // emits one in the `x-challenge-id` header on the 402). This lets the
  // server verify the credential was issued against its own 402 — the
  // cross-server portability scenario relies on this distinction.
  const issuedChallengeId = firstResponse.headers.get("x-challenge-id");
  const credentialId =
    issuedChallengeId ??
    `ts-x402-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  // Mirrors the Rust spine's PaymentPayload wire shape:
  //   { x402Version, accepted: { scheme, network, asset, payTo, amount, extra? },
  //     payload: { ... scheme-specific blob ... }, resource?: string }
  // The `payload` field is required by Rust's parser. For the wire-only
  // TS adapter the payload carries the credential id plus the route the
  // client is committing to; a full SDK fixture would carry a signed
  // Solana transaction here.
  const credential = {
    x402Version: envelope.x402Version,
    accepted: {
      scheme: offer.scheme,
      network: offer.network,
      asset: offer.asset,
      payTo: offer.payTo,
      amount: offer.maxAmountRequired,
      extra: offer.extra ?? null,
    },
    payload: {
      challengeId: credentialId,
      resource: offer.resource ?? envelope.resource,
    },
    resource: offer.resource ?? envelope.resource,
  };
  return Buffer.from(JSON.stringify(credential), "utf8").toString(
    "base64",
  );
}

async function payTarget(
  targetUrl: string,
  env: ReturnType<typeof readX402ClientEnvironment>,
): Promise<Response> {
  const credentialHeader = await buildCredentialHeader(targetUrl, env);
  const paidResponse = await fetch(targetUrl, {
    headers: { [PAYMENT_SIGNATURE_HEADER]: credentialHeader },
  });
  return withSentHeader(paidResponse, credentialHeader);
}

async function runCrossRouteReplay(
  targetUrl: string,
  env: ReturnType<typeof readX402ClientEnvironment>,
): Promise<Response> {
  const replaySourcePath = process.env.MPP_HARNESS_REPLAY_SOURCE_PATH;
  if (!replaySourcePath) {
    throw new Error("MPP_HARNESS_REPLAY_SOURCE_PATH is required");
  }

  const sourceUrl = new URL(replaySourcePath, targetUrl).toString();
  const credentialHeader = await buildCredentialHeader(sourceUrl, env);
  const replayResponse = await fetch(targetUrl, {
    headers: { [PAYMENT_SIGNATURE_HEADER]: credentialHeader },
  });
  return withSentHeader(replayResponse, credentialHeader);
}

async function runResubmitFlow(
  targetUrl: string,
  resubmitUrl: string,
  env: ReturnType<typeof readX402ClientEnvironment>,
): Promise<void> {
  const credentialHeader = await buildCredentialHeader(targetUrl, env);

  const firstResponse = await fetch(targetUrl, {
    headers: { [PAYMENT_SIGNATURE_HEADER]: credentialHeader },
  });
  const firstBody = await readResponseBody(firstResponse);

  const secondResponse = await fetch(resubmitUrl, {
    headers: { [PAYMENT_SIGNATURE_HEADER]: credentialHeader },
  });
  const secondHeaders = Object.fromEntries(secondResponse.headers.entries());
  secondHeaders[`${PAYMENT_SIGNATURE_HEADER}-sent`] = credentialHeader;

  console.log(
    JSON.stringify({
      type: "result",
      implementation: "typescript",
      role: "client",
      ok: secondResponse.ok,
      status: secondResponse.status,
      responseHeaders: secondHeaders,
      responseBody: await readResponseBody(secondResponse),
      settlement: secondResponse.headers.get(env.settlementHeader),
      firstStatus: firstResponse.status,
      firstBody,
    }),
  );
}

function withSentHeader(response: Response, credentialHeader: string): Response {
  const headers = new Headers(response.headers);
  // Echo the credential the client sent so the harness can replay it in
  // cross-server portability + idempotent-resubmit scenarios. The credential
  // is a request header so it is never reflected in the response on its own.
  headers.set(`${PAYMENT_SIGNATURE_HEADER}-sent`, credentialHeader);
  return new Response(response.body, {
    headers,
    status: response.status,
    statusText: response.statusText,
  });
}

async function reportResult(
  response: Response,
  settlementHeader: string,
): Promise<void> {
  console.log(
    JSON.stringify({
      type: "result",
      implementation: "typescript",
      role: "client",
      ok: response.ok,
      status: response.status,
      responseHeaders: Object.fromEntries(response.headers.entries()),
      responseBody: await readResponseBody(response),
      settlement: response.headers.get(settlementHeader),
    }),
  );
}

void main().catch(error => {
  console.log(
    JSON.stringify({
      type: "result",
      implementation: "typescript",
      role: "client",
      ok: false,
      status: 0,
      responseHeaders: {},
      responseBody: null,
      settlement: null,
      error: error instanceof Error ? error.message : String(error),
    }),
  );
});
