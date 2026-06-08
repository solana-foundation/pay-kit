// TypeScript reference protocol runner.
//
// Implements the canonical mpp-tools adapter ABI on top of `mppx` — the
// core protocol package that pay-kit's TypeScript SDK (`@solana/mpp`)
// depends on for its challenge / credential / receipt header codec,
// base64url, and challenge-id HMAC. This runner is the reference the
// per-language runners are validated against, and it is what the harness
// test drives the vendored canonical vectors through.

import { Buffer } from "node:buffer";
import { createHmac } from "node:crypto";
import { Credential, PaymentRequest, Receipt } from "mppx";
// `Challenge` comes from pay-kit's `@solana/mpp` boundary, which wraps mppx's
// challenge codec with the canonical empty-id parse guard. This is the surface
// pay-kit's TypeScript SDK actually exposes, so the conformance run reflects
// pay-kit behaviour, not raw mppx.
import { Challenge } from "@solana/mpp/client";
import type { AdapterRequest, AdapterResponse, ProtocolAdapter } from "../driver";

function ok(result: unknown): AdapterResponse {
  return { success: true, result };
}

function fail(error: string, error_type: string): AdapterResponse {
  return { success: false, error, error_type };
}

function base64UrlEncode(text: string): string {
  return Buffer.from(text, "utf8").toString("base64url");
}

function base64UrlDecode(text: string): string {
  return Buffer.from(text, "base64url").toString("utf8");
}

// Canonical challenge-id derivation. The HMAC input is the pay-kit/mppx
// canonical request encoding (`PaymentRequest.serialize` = base64url of the
// RFC 8785 / JCS canonical JSON) joined into the fixed pipe-slot layout, then
// HMAC-SHA256, then unpadded base64url. mppx's public `Challenge.from({
// secretKey })` takes `opaque` as a structured record and re-serializes it;
// the canonical `challenge.id` ABI instead feeds `opaque` as an
// already-serialized pipe-slot string, which this reproduces exactly. The
// HMAC math (request canonicalization + pipe layout + base64url) is identical
// to mppx's internal `computeId`.
function generateChallengeId(input: {
  secretKey: string;
  realm?: string;
  method?: string;
  intent?: string;
  request?: Record<string, unknown>;
  expires?: string;
  digest?: string;
  opaque?: string;
}): string {
  const payload = [
    input.realm ?? "",
    input.method ?? "",
    input.intent ?? "",
    PaymentRequest.serialize(input.request ?? {}),
    input.expires ?? "",
    input.digest ?? "",
    input.opaque ?? "",
  ].join("|");
  return createHmac("sha256", input.secretKey).update(payload, "utf8").digest("base64url");
}

function asHeader(input: unknown): string {
  return (input as { header: string }).header;
}

function asText(input: unknown): string {
  return (input as { text: string }).text;
}

function dispatch(request: AdapterRequest): AdapterResponse {
  const { op, input } = request;
  try {
    switch (op) {
      case "challenge.parse": {
        const challenge = Challenge.deserialize(asHeader(input));
        return ok(challenge);
      }
      case "challenge.format": {
        const challenge = Challenge.from(input as Parameters<typeof Challenge.from>[0]);
        return ok({ header: Challenge.serialize(challenge) });
      }
      case "credential.parse": {
        const credential = Credential.deserialize(asHeader(input));
        return ok(credential);
      }
      case "credential.format": {
        const credential = Credential.from(input as Parameters<typeof Credential.from>[0]);
        return ok({ header: Credential.serialize(credential) });
      }
      case "receipt.parse": {
        const receipt = Receipt.deserialize(asHeader(input));
        return ok(receipt);
      }
      case "receipt.format": {
        const receipt = Receipt.from(input as Parameters<typeof Receipt.from>[0]);
        return ok({ header: Receipt.serialize(receipt) });
      }
      case "base64url.encode": {
        return ok({ text: base64UrlEncode(asText(input)) });
      }
      case "base64url.decode": {
        // Canonical base64url.decode yields UTF-8 text.
        return ok({ text: base64UrlDecode(asText(input)) });
      }
      case "challenge.id": {
        return ok({ id: generateChallengeId(input as Parameters<typeof generateChallengeId>[0]) });
      }
      default:
        return fail(`Unknown operation: ${op}`, "unsupported_operation");
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (op.endsWith(".parse")) return fail(message, "parse_error");
    if (op.endsWith(".format")) return fail(message, "format_error");
    if (op.startsWith("base64url.")) return fail(message, "encoding_error");
    if (op === "challenge.id") return fail(message, "generation_error");
    return fail(message, "unknown_error");
  }
}

export const typescriptProtocolAdapter: ProtocolAdapter = {
  name: "typescript",
  runProtocolRequest(request: AdapterRequest): AdapterResponse {
    return dispatch(request);
  },
};

// stdin/stdout entrypoint speaking the canonical mpp-tools adapter ABI:
// reads a single `{ "op": ..., "input": ... }` request as JSON on stdin and
// writes a `{ "success": true, "result": ... }` / `{ "success": false,
// "error": ..., "error_type": ... }` response as JSON on stdout. This is the
// exact contract every per-language protocol runner must satisfy, so the
// spawn driver wires them all identically. Run directly:
//   echo '{"op":"base64url.encode","input":{"text":"a"}}' | tsx typescript.ts
async function readStdin(): Promise<string> {
  return await new Promise((resolve) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => (data += chunk));
    process.stdin.on("end", () => resolve(data.trim()));
  });
}

const isMain = (() => {
  try {
    return process.argv[1] !== undefined && import.meta.url === `file://${process.argv[1]}`;
  } catch {
    return false;
  }
})();

if (isMain) {
  readStdin()
    .then((raw) => {
      const request = JSON.parse(raw) as AdapterRequest;
      const response = dispatch(request);
      process.stdout.write(JSON.stringify(response));
    })
    .catch((err) => {
      const message = err instanceof Error ? err.message : String(err);
      process.stdout.write(
        JSON.stringify({ success: false, error: message, error_type: "unknown_error" }),
      );
      process.exitCode = 1;
    });
}
