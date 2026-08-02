// TypeScript MPP `session` harness client.
//
// Mirrors harness/python-session-client/main.py against the wire-only session
// server contract (Python harness SessionServer with accept-all open verify):
//   GET resource → 402 WWW-Authenticate (session challenge)
//   open credential → 200
//   POST /__402/session/deliveries → reserve
//   POST /__402/session/commit → voucher
//   POST /__402/session/close → settlement header / reference
//
// Uses @solana/mpp client helpers only — no protocol reinvention.
// Env: MPP_HARNESS_TARGET_URL (injected by harness), MPP_HARNESS_AMOUNT,
// MPP_HARNESS_DELIVERY_COUNT (default 1; multi-delivery sets 3),
// optional MPP_HARNESS_RPC_URL (unused for challenge-bound open blockhash).

import { generateKeyPairSigner } from "@solana/kit";
import {
  createPaymentChannelSessionOpener,
  selectSolanaSessionChallengeFromResponse,
  serializeSessionCredential,
  type SessionChallenge,
  type SignedVoucher,
} from "@solana/mpp/client";

function baseUrlFromTarget(targetUrl: string): string {
  const u = new URL(targetUrl);
  return `${u.protocol}//${u.host}`;
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return text;
  }
}

function emitResult(parameters: {
  ok: boolean;
  status: number;
  responseHeaders: Record<string, string>;
  responseBody: unknown;
  settlement?: string;
  error?: string;
}): void {
  console.log(
    JSON.stringify({
      type: "result",
      implementation: "typescript",
      role: "client",
      ok: parameters.ok,
      status: parameters.status,
      responseHeaders: parameters.responseHeaders,
      responseBody: parameters.responseBody,
      ...(parameters.settlement ? { settlement: parameters.settlement } : {}),
      ...(parameters.error ? { error: parameters.error } : {}),
    }),
  );
}

function headersRecord(response: Response): Record<string, string> {
  return Object.fromEntries(response.headers.entries());
}

async function main(): Promise<void> {
  const targetUrl = process.env.MPP_HARNESS_TARGET_URL;
  if (!targetUrl) {
    throw new Error("MPP_HARNESS_TARGET_URL is required");
  }
  const amount = process.env.MPP_HARNESS_AMOUNT ?? "700";
  const deliveryCount = Number.parseInt(
    process.env.MPP_HARNESS_DELIVERY_COUNT ?? "1",
    10,
  );
  if (!Number.isFinite(deliveryCount) || deliveryCount < 1) {
    throw new Error("MPP_HARNESS_DELIVERY_COUNT must be an integer >= 1");
  }
  const base = baseUrlFromTarget(targetUrl);
  const reserveUrl = `${base}/__402/session/deliveries`;
  const commitUrl = `${base}/__402/session/commit`;
  const closeUrl = `${base}/__402/session/close`;

  const probe = await fetch(targetUrl);
  if (probe.status !== 402) {
    emitResult({
      ok: false,
      status: probe.status,
      responseHeaders: headersRecord(probe),
      responseBody: await readJson(probe),
      error: "expected 402 session challenge",
    });
    return;
  }

  const challenge = selectSolanaSessionChallengeFromResponse(probe) as SessionChallenge | null;
  if (!challenge) {
    emitResult({
      ok: false,
      status: probe.status,
      responseHeaders: headersRecord(probe),
      responseBody: await readJson(probe),
      error: "no solana session challenge in WWW-Authenticate",
    });
    return;
  }

  // Client builds open against challenged blockhash/slot; harness server
  // verifies wire shape only (Python accept-all) — no on-chain broadcast required.
  const payer = await generateKeyPairSigner();
  const opener = createPaymentChannelSessionOpener({ signer: payer });
  // SessionOpener contract requires the original 402 response + fetch input;
  // the payment-channel opener only consumes `challenge`.
  const opened = await opener({
    challenge,
    input: targetUrl,
    response: probe,
  });
  const openAuth = serializeSessionCredential({
    challenge,
    payload: opened.payload,
  });

  const openedResponse = await fetch(targetUrl, {
    headers: { authorization: openAuth },
  });
  if (!openedResponse.ok) {
    emitResult({
      ok: false,
      status: openedResponse.status,
      responseHeaders: headersRecord(openedResponse),
      responseBody: await readJson(openedResponse),
      error: "session open rejected",
    });
    return;
  }

  const channelId = opened.session.channelId;
  // Cumulative watermark: each reserve/commit advances by `amount`.
  // session-basic leaves DELIVERY_COUNT=1; session-multi-delivery sets 3.
  let voucher: SignedVoucher | undefined;
  for (let i = 0; i < deliveryCount; i++) {
    const reserveResponse = await fetch(reserveUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ sessionId: channelId, amount }),
    });
    const reserveBody = await readJson(reserveResponse);
    if (
      !reserveResponse.ok ||
      typeof reserveBody !== "object" ||
      reserveBody === null ||
      !("deliveryId" in reserveBody)
    ) {
      emitResult({
        ok: false,
        status: reserveResponse.status,
        responseHeaders: headersRecord(reserveResponse),
        responseBody: reserveBody,
        error: "session delivery reserve failed",
      });
      return;
    }

    const deliveryId = String(
      (reserveBody as { deliveryId: unknown }).deliveryId,
    );
    voucher = await opened.session.prepareIncrement(amount);
    const commitResponse = await fetch(commitUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ deliveryId, voucher }),
    });
    const commitBody = await readJson(commitResponse);
    if (!commitResponse.ok) {
      emitResult({
        ok: false,
        status: commitResponse.status,
        responseHeaders: headersRecord(commitResponse),
        responseBody: commitBody,
        error: "session commit failed",
      });
      return;
    }
    opened.session.recordVoucher(voucher);
  }

  if (!voucher) {
    throw new Error("no voucher produced");
  }

  const closeAuth = serializeSessionCredential({
    challenge,
    payload: {
      action: "close",
      channelId,
      voucher,
    },
  });
  const closeResponse = await fetch(closeUrl, {
    method: "POST",
    headers: { authorization: closeAuth },
  });
  const closeBody = await readJson(closeResponse);
  let settlement = "";
  if (typeof closeBody === "object" && closeBody !== null) {
    const record = closeBody as Record<string, unknown>;
    settlement = String(
      record.reference ?? record.settledSignature ?? "",
    );
  }
  const settlementHeader =
    process.env.MPP_HARNESS_SETTLEMENT_HEADER ?? "x-session-settlement-signature";
  if (!settlement) {
    settlement = closeResponse.headers.get(settlementHeader) ?? "";
  }

  emitResult({
    ok: closeResponse.ok,
    status: closeResponse.status,
    responseHeaders: headersRecord(closeResponse),
    responseBody: closeBody,
    settlement: settlement || undefined,
  });
}

void main().catch(error => {
  emitResult({
    ok: false,
    status: 0,
    responseHeaders: {},
    responseBody: null,
    error: error instanceof Error ? error.message : String(error),
  });
});
