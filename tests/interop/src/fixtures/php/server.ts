import http from "node:http";
import { spawn } from "node:child_process";
import {
  createKeyPairSignerFromBytes,
  getBase64Codec,
  getCompiledTransactionMessageDecoder,
  getTransactionDecoder,
} from "@solana/kit";
import { coSignBase64Transaction } from "../../../../../typescript/packages/mpp/src/utils/transactions";
import { readInteropEnvironment } from "../typescript/shared";

type PhpChallenge = {
  type: "challenge";
  request: Record<string, unknown>;
  wwwAuthenticate: string;
};

type PhpVerified = {
  type: "verified";
  receipt: string;
  reference: string;
  transaction?: string;
  signature?: string;
};

type PhpBridgeErrorPayload = {
  type: "error";
  code: string;
  error: string;
};

class PhpBridgeError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "PhpBridgeError";
  }
}

async function main() {
  const environment = readInteropEnvironment();
  const feePayerSigner = await createKeyPairSignerFromBytes(
    environment.feePayerSecretKey,
  );

  const server = http.createServer(async (request, response) => {
    try {
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

      const challenge = await buildChallenge(
        environment,
        feePayerSigner.address,
        amountForPath(url.pathname, environment),
      );
      const authorization = headerValue(request.headers.authorization);

      if (!authorization) {
        writePaymentRequired(response, challenge, "Payment is required (PHP interop server).");
        return;
      }

      const verified = await verifyCredential(
        environment,
        feePayerSigner.address,
        authorization,
        challenge.request,
      ).catch((error: unknown) => {
        if (isPaymentRejected(error)) {
          writePaymentRequired(
            response,
            challenge,
            error instanceof Error ? error.message : String(error),
          );
          return undefined;
        }
        throw error;
      });
      if (!verified) {
        return;
      }
      if (!verified.transaction) {
        throw new Error("PHP verifier did not return a transaction payload");
      }
      const blockhash = extractRecentBlockhash(verified.transaction);
      if (isNetworkMismatch(environment.network, blockhash)) {
        writePaymentRequired(
          response,
          challenge,
          `Signed with a Surfpool localnet blockhash but the server expects ${environment.network}.`,
        );
        return;
      }

      const coSigned = await coSignBase64Transaction(
        feePayerSigner,
        verified.transaction,
      );
      const signature = await sendTransaction(environment.rpcUrl, coSigned);
      await waitForSignature(environment.rpcUrl, signature);

      response.writeHead(200, {
        "content-type": "application/json",
        [environment.settlementHeader]: signature,
        "payment-receipt": verified.receipt,
      });
      response.end(JSON.stringify({ ok: true, paid: true }));
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
      throw new Error("Failed to bind PHP interop server");
    }

    console.log(
      JSON.stringify({
        type: "ready",
        implementation: "php",
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

function writePaymentRequired(
  response: http.ServerResponse,
  challenge: PhpChallenge,
  detail: string,
): void {
  const body = JSON.stringify({
    detail,
    status: 402,
    title: "Payment Required",
    type: "https://paymentauth.org/problems/payment-required",
  });

  response.writeHead(402, {
    "cache-control": "no-store",
    "connection": "close",
    "content-length": Buffer.byteLength(body),
    "content-type": "application/problem+json",
    "www-authenticate": challenge.wwwAuthenticate,
  });
  response.end(body);
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

function headerValue(value: string | string[] | undefined): string | undefined {
  if (Array.isArray(value)) {
    return value[0];
  }
  return value;
}

async function buildChallenge(
  environment: ReturnType<typeof readInteropEnvironment>,
  feePayerKey: string,
  amount: string,
): Promise<PhpChallenge> {
  const recentBlockhash = await getLatestBlockhash(environment.rpcUrl);
  return await runPhpBridge<PhpChallenge>({
    amount,
    command: "challenge",
    currency: environment.mint,
    decimals: 6,
    description: "PHP interop protected content",
    feePayer: true,
    feePayerKey,
    network: environment.network,
    recentBlockhash,
    recipient: environment.payTo,
    secretKey: environment.secretKey,
    splits: environment.splits,
  });
}

async function verifyCredential(
  environment: ReturnType<typeof readInteropEnvironment>,
  feePayerKey: string,
  authorization: string,
  expected: Record<string, unknown>,
): Promise<PhpVerified> {
  return await runPhpBridge<PhpVerified>({
    authorization,
    command: "verify",
    currency: environment.mint,
    decimals: 6,
    expected,
    feePayer: true,
    feePayerKey,
    network: environment.network,
    recipient: environment.payTo,
    secretKey: environment.secretKey,
  });
}

async function runPhpBridge<T>(payload: unknown): Promise<T> {
  const child = spawn("php", ["php-server/bridge.php"], {
    cwd: process.cwd(),
    stdio: ["pipe", "pipe", "pipe"],
  });

  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  child.stdin.end(`${JSON.stringify(payload)}\n`);
  const code = await new Promise<number | null>((resolve) =>
    child.once("exit", resolve),
  );

  if (code !== 0) {
    const parsed = parseBridgeError(stdout);
    if (parsed) {
      throw new PhpBridgeError(parsed.code, parsed.error);
    }
    throw new Error(`PHP bridge exited with ${code}: ${stderr}${stdout}`);
  }

  return JSON.parse(stdout) as T;
}

function parseBridgeError(stdout: string): PhpBridgeErrorPayload | undefined {
  try {
    const payload = JSON.parse(stdout) as Partial<PhpBridgeErrorPayload>;
    if (payload.type === "error" && payload.code && payload.error) {
      return payload as PhpBridgeErrorPayload;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

async function rpc<T>(rpcUrl: string, method: string, params: unknown[]): Promise<T> {
  const response = await fetch(rpcUrl, {
    body: JSON.stringify({
      id: 1,
      jsonrpc: "2.0",
      method,
      params,
    }),
    headers: { "content-type": "application/json" },
    method: "POST",
  });
  const payload = await response.json() as { result?: T; error?: { message?: string } };
  if (payload.error) {
    throw new Error(payload.error.message ?? `${method} failed`);
  }
  return payload.result as T;
}

async function getLatestBlockhash(rpcUrl: string): Promise<string> {
  const result = await rpc<{ value: { blockhash: string } }>(
    rpcUrl,
    "getLatestBlockhash",
    [{ commitment: "confirmed" }],
  );
  return result.value.blockhash;
}

async function sendTransaction(
  rpcUrl: string,
  transaction: string,
): Promise<string> {
  return await rpc<string>(rpcUrl, "sendTransaction", [
    transaction,
    { encoding: "base64", skipPreflight: false },
  ]);
}

async function waitForSignature(
  rpcUrl: string,
  signature: string,
): Promise<void> {
  for (let attempt = 0; attempt < 40; attempt += 1) {
    const status = await rpc<{ value: Array<{ confirmationStatus?: string } | null> }>(
      rpcUrl,
      "getSignatureStatuses",
      [[signature]],
    );
    const confirmationStatus = status.value[0]?.confirmationStatus;
    if (confirmationStatus === "confirmed" || confirmationStatus === "finalized") {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Timed out waiting for transaction ${signature}`);
}

function extractRecentBlockhash(transaction: string): string | null {
  try {
    const txBytes = getBase64Codec().encode(transaction);
    const decoded = getTransactionDecoder().decode(txBytes);
    const message = getCompiledTransactionMessageDecoder().decode(decoded.messageBytes);
    return message.lifetimeToken;
  } catch {
    return null;
  }
}

function isNetworkMismatch(network: string, blockhash: string | null): boolean {
  return network !== "localnet" && blockhash?.startsWith("SURFNET") === true;
}

function isPaymentRejected(error: unknown): boolean {
  return (
    error instanceof PhpBridgeError &&
    [
      "charge_request_mismatch",
      "challenge_realm_mismatch",
      "challenge_verification_failed",
      "challenge_expired",
      "challenge_method_or_intent_mismatch",
    ].includes(error.code)
  );
}

void main();
