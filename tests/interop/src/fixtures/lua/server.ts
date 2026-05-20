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
import { resolveLuaBinary } from "./binary";

type LuaChallenge = {
  type: "challenge";
  request: Record<string, unknown>;
  wwwAuthenticate: string;
};

type LuaVerified = {
  type: "verified";
  receipt: string;
  reference: string;
  transaction?: string;
  signature?: string;
};

const luaBin = resolveLuaBinary();

async function main() {
  if (!luaBin) {
    throw new Error(
      "Lua interop server requires a Lua binary. Set MPP_INTEROP_LUA_BIN or install lua in PATH.",
    );
  }

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
        priceForPath(url.pathname, environment),
      );
      const authorization = headerValue(request.headers.authorization);

      if (!authorization) {
        writePaymentRequired(response, challenge, "Payment is required (Lua interop server).");
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
        throw new Error("Lua verifier did not return a transaction payload");
      }
      const blockhash = extractRecentBlockhash(verified.transaction);
      if (isNetworkMismatch(environment.network, blockhash)) {
        writePaymentRequired(
          response,
          challenge,
          `Signed against localnet but the server expects ${environment.network}.`,
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
      throw new Error("Failed to bind Lua interop server");
    }

    console.log(
      JSON.stringify({
        type: "ready",
        implementation: "lua",
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
  challenge: LuaChallenge,
  detail: string,
): void {
  response.writeHead(402, {
    "cache-control": "no-store",
    "content-type": "application/problem+json",
    "www-authenticate": challenge.wwwAuthenticate,
  });
  response.end(
    JSON.stringify({
      detail,
      status: 402,
      title: "Payment Required",
      type: "https://paymentauth.org/problems/payment-required",
    }),
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

function priceForPath(
  path: string,
  environment: ReturnType<typeof readInteropEnvironment>,
): string {
  if (path === environment.replaySource?.resourcePath) {
    return environment.replaySource.price;
  }
  return environment.price;
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
  price: string,
): Promise<LuaChallenge> {
  const recentBlockhash = await getLatestBlockhash(environment.rpcUrl);
  return await runLuaBridge<LuaChallenge>({
    command: "challenge",
    currency: environment.mint,
    decimals: 6,
    description: "Lua interop protected content",
    feePayer: true,
    feePayerKey,
    network: environment.network,
    price,
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
): Promise<LuaVerified> {
  return await runLuaBridge<LuaVerified>({
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

async function runLuaBridge<T>(payload: unknown): Promise<T> {
  const command = luaBin;
  if (!command) {
    throw new Error(
      "Lua interop server requires a Lua binary. Set MPP_INTEROP_LUA_BIN or install lua in PATH.",
    );
  }

  const child = spawn(command, ["lua-server/bridge.lua"], {
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
    throw new Error(`Lua bridge exited with ${code}: ${stderr}${stdout}`);
  }

  return JSON.parse(stdout) as T;
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
  const data = (await response.json()) as {
    error?: { message?: string };
    result?: T;
  };
  if (data.error) {
    throw new Error(`${method}: ${data.error.message ?? "RPC error"}`);
  }
  return data.result as T;
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
  for (let attempt = 0; attempt < 30; attempt += 1) {
    const result = await rpc<{
      value: Array<{ confirmationStatus?: string; err?: unknown } | null>;
    }>(rpcUrl, "getSignatureStatuses", [[signature]]);
    const status = result.value[0];
    if (status?.err) {
      throw new Error(`Transaction failed: ${JSON.stringify(status.err)}`);
    }
    if (status?.confirmationStatus) {
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
    const message = getCompiledTransactionMessageDecoder().decode(
      decoded.messageBytes,
    );
    return message.lifetimeToken;
  } catch {
    return null;
  }
}

function isNetworkMismatch(network: string, blockhash: string | null): boolean {
  return (
    network !== "localnet" &&
    blockhash !== null &&
    blockhash.startsWith("SURFNETxSAFEHASH")
  );
}

function isPaymentRejected(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return (
    message.includes("amount mismatch") ||
    message.includes("charge request mismatch") ||
    message.includes("challenge verification failed") ||
    message.includes("challenge expired") ||
    message.includes("challenge method or intent mismatch")
  );
}

void main();
