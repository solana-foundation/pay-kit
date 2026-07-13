import http from "node:http";
import { createKeyPairSignerFromBytes } from "@solana/kit";
import { createPayKit, type NetworkSlug, usd } from "@solana/pay-kit";
import { readHarnessEnvironment } from "./shared";

function networkSlug(network: string): NetworkSlug {
  switch (network) {
    case "mainnet":
    case "devnet":
    case "localnet":
      return network;
    default:
      throw new Error(`Unsupported MPP_HARNESS_NETWORK: ${network}`);
  }
}

async function main(): Promise<void> {
  const environment = readHarnessEnvironment();
  const signer = await createKeyPairSignerFromBytes(
    environment.feePayerSecretKey,
  );

  // Deliberately omit replayStore. This fixture exercises the real PayKit
  // configuration/adapter boundary: mainnet must reject, while devnet may use
  // process-local state only with PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1.
  const paykit = await createPayKit({
    accept: ["mpp"],
    mpp: { challengeBindingSecret: environment.secretKey },
    network: networkSlug(environment.network),
    operator: { recipient: environment.payTo, signer },
    preflight: false,
    pricing: { boot: usd("0.001") },
  });
  const result = await paykit.requirePayment(
    new Request("http://boot.test/protected"),
    "boot",
  );
  if (!("challenge" in result) || result.status !== 402) {
    throw new Error(
      "TypeScript PayKit boot fixture did not issue an MPP challenge",
    );
  }

  const server = http.createServer((_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(JSON.stringify({ ok: true }));
  });
  server.listen(0, "127.0.0.1", () => {
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Failed to bind TypeScript PayKit boot fixture");
    }
    console.log(
      JSON.stringify({
        type: "ready",
        implementation: "typescript",
        role: "server",
        port: address.port,
        capabilities: ["mpp"],
      }),
    );
  });

  const shutdown = () => server.close(() => process.exit(0));
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

void main().catch((error: unknown) => {
  // Keep the policy signature at the end of stderr so the harness's bounded
  // child-process stderr capture retains it even when the SDK adds a long stack.
  console.error(
    `[paykit-boot] ${error instanceof Error ? error.message : String(error)}`,
  );
  process.exitCode = 1;
});
