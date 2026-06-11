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

  const firstResponse = await fetch(env.targetUrl);
  const envelope = decodePaymentRequired(
    firstResponse.headers.get(PAYMENT_REQUIRED_HEADER),
  );

  if (!envelope) {
    console.log(
      JSON.stringify({
        type: "result",
        implementation: "typescript",
        role: "client",
        ok: false,
        status: firstResponse.status,
        responseHeaders: Object.fromEntries(firstResponse.headers.entries()),
        responseBody: await readResponseBody(firstResponse),
        settlement: null,
        error: "missing or unparseable PAYMENT-REQUIRED header",
      }),
    );
    return;
  }

  const offer = pickOffer(envelope, env.preferredCurrencies, env.network);
  if (!offer) {
    console.log(
      JSON.stringify({
        type: "result",
        implementation: "typescript",
        role: "client",
        ok: false,
        status: firstResponse.status,
        responseHeaders: Object.fromEntries(firstResponse.headers.entries()),
        responseBody: await readResponseBody(firstResponse),
        settlement: null,
        error: `no offer matched network ${env.network}`,
      }),
    );
    return;
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
  const credentialHeader = Buffer.from(JSON.stringify(credential), "utf8").toString(
    "base64",
  );

  const paidResponse = await fetch(env.targetUrl, {
    headers: { [PAYMENT_SIGNATURE_HEADER]: credentialHeader },
  });

  const responseHeaders = Object.fromEntries(paidResponse.headers.entries());
  // Echo the credential the client sent so the harness can replay it in
  // cross-server portability + idempotent-resubmit scenarios. The credential
  // is a request header so it is never reflected in the response on its own.
  responseHeaders[`${PAYMENT_SIGNATURE_HEADER}-sent`] = credentialHeader;

  console.log(
    JSON.stringify({
      type: "result",
      implementation: "typescript",
      role: "client",
      ok: paidResponse.ok,
      status: paidResponse.status,
      responseHeaders,
      responseBody: await readResponseBody(paidResponse),
      settlement: paidResponse.headers.get(env.settlementHeader),
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
