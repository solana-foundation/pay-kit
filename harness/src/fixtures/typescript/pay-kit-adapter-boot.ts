import http from "node:http";

import { configure } from "../../../../typescript/packages/pay-kit/src/config.js";
import { Signer } from "../../../../typescript/packages/pay-kit/src/signer.js";

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function networkFromHarness(
  network: string,
): "solana_devnet" | "solana_localnet" | "solana_mainnet" {
  if (network === "devnet") return "solana_devnet";
  if (network === "localnet") return "solana_localnet";
  if (network === "mainnet" || network === "mainnet-beta")
    return "solana_mainnet";
  throw new Error(`Unsupported MPP_HARNESS_NETWORK: ${network}`);
}

async function main(): Promise<void> {
  const signer = await Signer.json(
    requiredEnv("MPP_HARNESS_FEE_PAYER_SECRET_KEY"),
  );
  await configure({
    accept: ["mpp"],
    mpp: { challengeBindingSecret: requiredEnv("MPP_HARNESS_SECRET_KEY") },
    network: networkFromHarness(requiredEnv("MPP_HARNESS_NETWORK")),
    operator: { recipient: requiredEnv("MPP_HARNESS_PAY_TO"), signer },
    preflight: false,
    rpcUrl: requiredEnv("MPP_HARNESS_RPC_URL"),
  });

  const server = http.createServer((_request, response) => {
    response.writeHead(404).end();
  });
  server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    if (!address || typeof address === "string")
      throw new Error("Failed to bind TypeScript boot probe");
    console.log(
      JSON.stringify({
        implementation: "typescript",
        port: address.port,
        role: "server",
        type: "ready",
      }),
    );
  });

  const shutdown = () => server.close(() => process.exit(0));
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

void main();
