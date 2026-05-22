import { createKeyPairSignerFromBytes } from "@solana/kit";
import {
  buildChargeTransaction,
  Mppx,
  selectSolanaChargeChallengeFromResponse,
  solana,
} from "@solana/mpp/client";
import { Credential } from "mppx";
import { readInteropEnvironment } from "./shared";

async function main() {
  const targetUrl = process.env.MPP_INTEROP_TARGET_URL;
  if (!targetUrl) {
    throw new Error("MPP_INTEROP_TARGET_URL is required");
  }

  const environment = readInteropEnvironment();
  const signer = await createKeyPairSignerFromBytes(
    environment.clientSecretKey,
  );
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
  // G28a: when the server refuses to construct (e.g. splits > 8) it
  // serves a 402 body without a `WWW-Authenticate` header. mppx's
  // wrapped fetch then throws this exact message before exposing the
  // 402 response to the caller. The allowlist stays narrow: only
  // this two-word literal symptom of "server emitted a 402 with no
  // Solana challenge" maps to a synthetic 402 here.
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
  environment: ReturnType<typeof readInteropEnvironment>,
  signer: Awaited<ReturnType<typeof createKeyPairSignerFromBytes>>,
): Promise<Response> {
  const client = Mppx.create({
    methods: [
      solana.charge({
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

async function runCrossRouteReplay(
  targetUrl: string,
  environment: ReturnType<typeof readInteropEnvironment>,
  signer: Awaited<ReturnType<typeof createKeyPairSignerFromBytes>>,
): Promise<Response> {
  if (!environment.replaySource) {
    throw new Error("MPP_INTEROP_REPLAY_SOURCE_PATH is required");
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
