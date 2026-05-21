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
  const paidResponse = environment.replaySource
    ? await runCrossRouteReplay(targetUrl, environment, signer)
    : await payTarget(targetUrl, environment, signer);

  await reportResult(paidResponse, environment.settlementHeader);
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
