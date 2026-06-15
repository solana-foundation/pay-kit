import { createKeyPairSignerFromBytes } from "@solana/kit";
import {
  buildChargeTransaction,
  Mppx,
  selectSolanaChargeChallengeFromResponse,
  solana,
} from "@solana/mpp/client";
import { Credential } from "mppx";
import { readHarnessEnvironment } from "./shared";

async function main() {
  const targetUrl = process.env.MPP_HARNESS_TARGET_URL;
  if (!targetUrl) {
    throw new Error("MPP_HARNESS_TARGET_URL is required");
  }

  const environment = readHarnessEnvironment();
  const signer = await createKeyPairSignerFromBytes(
    environment.clientSecretKey,
  );
  const resubmitUrl = process.env.MPP_HARNESS_RESUBMIT_URL;
  if (resubmitUrl) {
    await runResubmitFlow(targetUrl, resubmitUrl, environment, signer);
    return;
  }
  let paidResponse: Response;
  try {
    paidResponse = environment.replaySource
      ? await runCrossRouteReplay(targetUrl, environment, signer)
      : await payTarget(targetUrl, environment, signer);
  } catch (error) {
    // G28b. `buildChargeTransaction` refuses to build a credential
    // when `splits` consume the entire amount, raising before any
    // request reaches the server. The harness treats that one
    // specific pre-broadcast rejection as the correct 402-class
    // outcome. Every other thrown error is a real fixture or SDK
    // failure and must surface as a non-zero exit so the harness
    // sees it. We allowlist by error message rather than catching
    // all to avoid masking unrelated regressions (Codex review of
    // this PR).
    if (isClientSideSplitRejection(error)) {
      reportClientSideRejection(error);
      return;
    }
    throw error;
  }

  await reportResult(paidResponse, environment.settlementHeader);
}

function isClientSideSplitRejection(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }
  // G28b: client-side pre-broadcast rejection.
  if (/Splits consume the entire amount/i.test(error.message)) {
    return true;
  }
  // Server-side rejection symptom: the server emits a 402 body with no
  // `WWW-Authenticate` header (mppx's wrapped fetch throws this exact
  // message before exposing the underlying 402 response to the caller).
  // Today this branch covers two distinct cases that both fail at the
  // server's request construction stage:
  //   - G28a splits > 8.
  //   - G14 compute budget over-cap (limit > 200_000 or price > 5_000_000).
  // Both have expectedStatus 402 so the test result is correct. The
  // allowlist stays narrow to this one two-word literal so it does not
  // accidentally absorb unrelated client-side regressions; if mppx ever
  // changes the message both scenarios surface together and the failure
  // is easy to diagnose.
  return /Missing WWW-Authenticate header/i.test(error.message);
}

function reportClientSideRejection(error: unknown): void {
  const message = error instanceof Error ? error.message : String(error);
  console.log(
    JSON.stringify({
      type: "result",
      implementation: "typescript",
      role: "client",
      ok: false,
      status: 402,
      responseHeaders: {},
      responseBody: {
        error: "client_rejected_credential",
        message,
      },
      settlement: null,
    }),
  );
}

async function payTarget(
  targetUrl: string,
  environment: ReturnType<typeof readHarnessEnvironment>,
  signer: Awaited<ReturnType<typeof createKeyPairSignerFromBytes>>,
): Promise<Response> {
  const client = Mppx.create({
    methods: [
      solana.charge({
        // Push-mode (broadcast=true): the SDK signs, broadcasts, and
        // confirms locally, then sends a type=signature credential.
        // Pull-mode (default): the SDK signs and lets the server
        // broadcast a type=transaction credential. The harness drives
        // the choice via MPP_HARNESS_PAYMENT_MODE so a single client
        // adapter covers both wire modes.
        broadcast: environment.paymentMode === "push",
        signer,
        rpcUrl: environment.rpcUrl,
        ...(environment.computeUnitLimit !== undefined
          ? { computeUnitLimit: environment.computeUnitLimit }
          : {}),
        ...(environment.computeUnitPrice !== undefined
          ? { computeUnitPrice: environment.computeUnitPrice }
          : {}),
      }),
    ],
  });

  return await client.fetch(targetUrl);
}

// Cross-server portability + same-server idempotent resubmit. Pays
// `targetUrl` via the manual challenge/credential flow so we can capture
// the Authorization header, then re-sends that same header to
// `resubmitUrl`. The harness asserts on the second (resubmit) response;
// the first must succeed (200) for the scenario to be meaningful, so a
// failed first hop is reported with a synthetic 402 carrying the error
// for diagnostic.
async function runResubmitFlow(
  targetUrl: string,
  resubmitUrl: string,
  environment: ReturnType<typeof readHarnessEnvironment>,
  signer: Awaited<ReturnType<typeof createKeyPairSignerFromBytes>>,
): Promise<void> {
  const challengeResponse = await fetch(targetUrl);
  if (challengeResponse.status !== 402) {
    emitResubmitResult({
      firstStatus: challengeResponse.status,
      firstBody: await safeText(challengeResponse),
      secondStatus: 0,
      secondHeaders: {},
      secondBody: { error: "first_hop_not_402" },
      settlement: null,
      settlementHeader: environment.settlementHeader,
    });
    return;
  }
  const challenge = selectSolanaChargeChallengeFromResponse(challengeResponse, {
    currency: environment.mint,
  });
  if (!challenge) {
    throw new Error("Target did not return a Solana charge challenge");
  }
  const transaction = await buildChargeTransaction({
    request: challenge.request,
    rpcUrl: environment.rpcUrl,
    signer,
  });
  const authorization = Credential.serialize({
    challenge,
    payload: { transaction, type: "transaction" },
  });

  const firstResponse = await fetch(targetUrl, {
    headers: { Authorization: authorization },
  });
  const firstBody = await safeText(firstResponse);

  const secondResponse = await fetch(resubmitUrl, {
    headers: { Authorization: authorization },
  });
  const secondRawBody = await secondResponse.text();
  let secondBody: unknown = secondRawBody;
  try {
    secondBody = JSON.parse(secondRawBody);
  } catch {
    // raw string is fine
  }

  emitResubmitResult({
    firstStatus: firstResponse.status,
    firstBody,
    secondStatus: secondResponse.status,
    secondHeaders: Object.fromEntries(secondResponse.headers.entries()),
    secondBody,
    settlement: secondResponse.headers.get(environment.settlementHeader),
    settlementHeader: environment.settlementHeader,
  });
}

async function safeText(response: Response): Promise<unknown> {
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

function emitResubmitResult(params: {
  firstStatus: number;
  firstBody: unknown;
  secondStatus: number;
  secondHeaders: Record<string, string>;
  secondBody: unknown;
  settlement: string | null;
  settlementHeader: string;
}): void {
  console.log(
    JSON.stringify({
      type: "result",
      implementation: "typescript",
      role: "client",
      ok: params.secondStatus >= 200 && params.secondStatus < 300,
      status: params.secondStatus,
      responseHeaders: params.secondHeaders,
      responseBody: params.secondBody,
      settlement: params.settlement,
      firstStatus: params.firstStatus,
      firstBody: params.firstBody,
    }),
  );
}

async function runCrossRouteReplay(
  targetUrl: string,
  environment: ReturnType<typeof readHarnessEnvironment>,
  signer: Awaited<ReturnType<typeof createKeyPairSignerFromBytes>>,
): Promise<Response> {
  if (!environment.replaySource) {
    throw new Error("MPP_HARNESS_REPLAY_SOURCE_PATH is required");
  }

  const sourceUrl = new URL(environment.replaySource.resourcePath, targetUrl);
  const sourceResponse = await fetch(sourceUrl);
  if (sourceResponse.status !== 402) {
    throw new Error(
      `Expected replay source route to challenge with 402, got ${sourceResponse.status}`,
    );
  }

  const challenge = selectSolanaChargeChallengeFromResponse(sourceResponse, {
    currency: environment.mint,
  });
  if (!challenge) {
    throw new Error("Replay source did not return a Solana charge challenge");
  }

  const transaction = await buildChargeTransaction({
    request: challenge.request,
    rpcUrl: environment.rpcUrl,
    signer,
  });
  const authorization = Credential.serialize({
    challenge,
    payload: {
      transaction,
      type: "transaction",
    },
  });

  return await fetch(targetUrl, {
    headers: {
      Authorization: authorization,
    },
  });
}

async function reportResult(
  response: Response,
  settlementHeader: string,
): Promise<void> {
  const rawBody = await response.text();
  let responseBody: unknown = rawBody;
  try {
    responseBody = JSON.parse(rawBody);
  } catch {
    // Keep raw string when the response body is not JSON.
  }

  console.log(
    JSON.stringify({
      type: "result",
      implementation: "typescript",
      role: "client",
      ok: response.ok,
      status: response.status,
      responseHeaders: Object.fromEntries(response.headers.entries()),
      responseBody,
      settlement: response.headers.get(settlementHeader),
    }),
  );
}

void main();
