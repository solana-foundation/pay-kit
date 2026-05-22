import net from "node:net";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import { createSolanaRpc } from "@solana/kit";
import { Surfnet } from "surfpool-sdk";
import { InteropScenario, selectInteropScenarios } from "../src/contracts";
import {
  clientImplementations,
  serverImplementations,
} from "../src/implementations";
import { runClient, startServer, stopServer } from "../src/process";

type RunningServer = Awaited<ReturnType<typeof startServer>>;

const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const MINT_ACCOUNT_SIZE = 82;

const runningServers: RunningServer[] = [];

let surfnet: Surfnet | undefined;
let interopEnv: Record<string, string> | undefined;
let splitRecipients: Record<string, string> = {};

async function canBindLocalSocket(): Promise<boolean> {
  return await new Promise<boolean>((resolve) => {
    const server = net.createServer();
    server.once("error", () => resolve(false));
    server.listen(0, "127.0.0.1", () => {
      server.close(() => resolve(true));
    });
  });
}

async function getTokenBalance(
  surfnet: Surfnet,
  owner: string,
  mint: string,
  missingAsZero = false,
): Promise<bigint> {
  const rpc = createSolanaRpc(surfnet.rpcUrl);
  const ata = surfnet.getAta(owner, mint);
  try {
    const response = await rpc.getTokenAccountBalance(ata as never).send();
    return BigInt(response.value.amount);
  } catch (error) {
    if (missingAsZero) {
      return 0n;
    }
    throw error;
  }
}

function createSplMintAccountData(decimals: number): Uint8Array {
  const data = new Uint8Array(MINT_ACCOUNT_SIZE);
  const view = new DataView(data.buffer);
  view.setBigUint64(36, 0n, true);
  data[44] = decimals;
  data[45] = 1;
  return data;
}

const socketSupport = await canBindLocalSocket();
const activeScenarios = selectInteropScenarios(
  process.env.MPP_INTEROP_INTENTS,
  process.env.MPP_INTEROP_SCENARIOS,
);
const baseScenario = activeScenarios[0];

if (!baseScenario) {
  throw new Error("No interop scenarios are active");
}

beforeAll(async () => {
  if (!socketSupport) {
    return;
  }

  surfnet = Surfnet.start();

  const client = Surfnet.newKeypair();
  const payTo = Surfnet.newKeypair();
  const platform = Surfnet.newKeypair();

  surfnet.setAccount(
    baseScenario.asset,
    1_461_600,
    createSplMintAccountData(6),
    TOKEN_PROGRAM,
  );
  surfnet.setAccount(
    client.publicKey,
    2_000_000_000,
    new Uint8Array(),
    "11111111111111111111111111111111",
  );
  surfnet.fundToken(client.publicKey, baseScenario.asset, 100_000);
  surfnet.fundToken(payTo.publicKey, baseScenario.asset, 1);

  splitRecipients = {
    platform: platform.publicKey,
  };

  interopEnv = {
    MPP_INTEROP_RPC_URL: surfnet.rpcUrl,
    MPP_INTEROP_NETWORK: baseScenario.network,
    MPP_INTEROP_MINT: baseScenario.asset,
    MPP_INTEROP_PRICE: baseScenario.price,
    MPP_INTEROP_SECRET_KEY: "mpp-interop-secret-key",
    MPP_INTEROP_PAY_TO: payTo.publicKey,
    MPP_INTEROP_CLIENT_SECRET_KEY: JSON.stringify(Array.from(client.secretKey)),
    MPP_INTEROP_FEE_PAYER_SECRET_KEY: JSON.stringify(
      Array.from(surfnet.payerSecretKey),
    ),
  };
});

afterEach(async () => {
  while (runningServers.length > 0) {
    const server = runningServers.pop();
    if (server) {
      await stopServer(server);
    }
  }
});

describe("mpp interop", () => {
  const activeServers = serverImplementations.filter(
    (implementation) => implementation.enabled,
  );
  const activeClients = clientImplementations.filter(
    (implementation) => implementation.enabled,
  );
  const socketAwareIt = socketSupport ? it : it.skip;

  for (const scenario of activeScenarios) {
    const scenarioServers = activeServers.filter(
      (implementation) =>
        !scenario.serverIds || scenario.serverIds.includes(implementation.id),
    );
    const scenarioClients = activeClients.filter(
      (implementation) =>
        !scenario.clientIds || scenario.clientIds.includes(implementation.id),
    );

    for (const serverImplementation of scenarioServers) {
      for (const clientImplementation of scenarioClients) {
        socketAwareIt(
          `${scenario.id}: ${clientImplementation.id} client pays ${serverImplementation.id} server`,
          async () => {
            if (!surfnet || !interopEnv) {
              throw new Error(
                "Surfpool interop environment was not initialized",
              );
            }

            const scenarioEnv = environmentForScenario(interopEnv, scenario);
            const initialBalance = await getTokenBalance(
              surfnet,
              scenarioEnv.MPP_INTEROP_PAY_TO,
              scenarioEnv.MPP_INTEROP_MINT,
            );
            const initialSplitBalances = await splitBalances(
              surfnet,
              scenario,
              scenarioEnv.MPP_INTEROP_MINT,
              true,
            );

            const server = await startServer(serverImplementation, scenarioEnv);
            runningServers.push(server);

            const targetUrl = `http://127.0.0.1:${server.ready.port}${scenario.resourcePath}`;
            const result = await runClient(
              clientImplementation,
              targetUrl,
              scenarioEnv,
            );

            const finalBalance = await getTokenBalance(
              surfnet,
              scenarioEnv.MPP_INTEROP_PAY_TO,
              scenarioEnv.MPP_INTEROP_MINT,
            );
            const finalSplitBalances = await splitBalances(
              surfnet,
              scenario,
              scenarioEnv.MPP_INTEROP_MINT,
              false,
            );

            expect(result.status, JSON.stringify(result, null, 2)).toBe(
              scenario.expectedStatus,
            );

            if (scenario.expectedStatus === 200) {
              expect(result.ok, JSON.stringify(result, null, 2)).toBe(true);
              expect(result.responseBody).toMatchObject({
                ok: true,
                paid: true,
              });
              expect(typeof result.settlement).toBe("string");
              expect(result.settlement).not.toHaveLength(0);
              expect(finalBalance - initialBalance).toBe(
                primaryDelta(scenario),
              );
              expect(
                splitDeltas(initialSplitBalances, finalSplitBalances),
              ).toEqual(expectedSplitDeltas(scenario));
            } else {
              expect(result.ok, JSON.stringify(result, null, 2)).toBe(false);
              expect(finalBalance - initialBalance).toBe(0n);
              expect(
                splitDeltas(initialSplitBalances, finalSplitBalances),
              ).toEqual(expectedZeroSplitDeltas(scenario));
            }
          },
        );
      }
    }
  }
});

function environmentForScenario(
  baseEnv: Record<string, string>,
  scenario: InteropScenario,
): Record<string, string> {
  return {
    ...baseEnv,
    MPP_INTEROP_AMOUNT: scenario.amount,
    MPP_INTEROP_NETWORK: scenario.network,
    MPP_INTEROP_PAYMENT_MODE: scenario.paymentMode ?? "pull",
    MPP_INTEROP_PRICE: scenario.price,
    MPP_INTEROP_RESOURCE_PATH: scenario.resourcePath,
    ...(scenario.replaySource
      ? {
          MPP_INTEROP_REPLAY_SOURCE_AMOUNT: scenario.replaySource.amount,
          MPP_INTEROP_REPLAY_SOURCE_PATH: scenario.replaySource.resourcePath,
          MPP_INTEROP_REPLAY_SOURCE_PRICE: scenario.replaySource.price,
        }
      : {}),
    MPP_INTEROP_SETTLEMENT_HEADER: scenario.settlementHeader,
    MPP_INTEROP_SPLITS: JSON.stringify(
      (scenario.splits ?? []).map((split) => ({
        recipient: splitRecipients[split.recipientKey],
        amount: split.amount,
        ...(split.ataCreationRequired === undefined
          ? {}
          : { ataCreationRequired: split.ataCreationRequired }),
        ...(split.memo === undefined ? {} : { memo: split.memo }),
      })),
    ),
  };
}

async function splitBalances(
  surfnet: Surfnet,
  scenario: InteropScenario,
  mint: string,
  missingAsZero: boolean,
): Promise<Record<string, bigint>> {
  const balances: Record<string, bigint> = {};
  for (const split of scenario.splits ?? []) {
    const recipient = splitRecipients[split.recipientKey];
    balances[split.recipientKey] = await getTokenBalance(
      surfnet,
      recipient,
      mint,
      missingAsZero,
    );
  }
  return balances;
}

function primaryDelta(scenario: InteropScenario): bigint {
  return (
    BigInt(scenario.amount) -
    (scenario.splits ?? []).reduce(
      (sum, split) => sum + BigInt(split.amount),
      0n,
    )
  );
}

function expectedSplitDeltas(
  scenario: InteropScenario,
): Record<string, bigint> {
  const deltas: Record<string, bigint> = {};
  for (const split of scenario.splits ?? []) {
    deltas[split.recipientKey] = BigInt(split.amount);
  }
  return deltas;
}

function expectedZeroSplitDeltas(
  scenario: InteropScenario,
): Record<string, bigint> {
  const deltas: Record<string, bigint> = {};
  for (const split of scenario.splits ?? []) {
    deltas[split.recipientKey] = 0n;
  }
  return deltas;
}

function splitDeltas(
  before: Record<string, bigint>,
  after: Record<string, bigint>,
): Record<string, bigint> {
  const deltas: Record<string, bigint> = {};
  for (const key of Object.keys(before)) {
    deltas[key] = after[key] - before[key];
  }
  return deltas;
}
