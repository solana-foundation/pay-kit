import net from "node:net";
import { afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  createSolanaRpc,
  getBase64Codec,
  getCompiledTransactionMessageDecoder,
  getTransactionDecoder,
} from "@solana/kit";
import { Surfnet } from "surfpool-sdk";
import { InteropScenario, selectInteropScenarios } from "../src/contracts";
import {
  clientImplementations,
  serverImplementations,
} from "../src/implementations";
import { runClient, startServer, stopServer } from "../src/process";

type RunningServer = Awaited<ReturnType<typeof startServer>>;

const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const MINT_ACCOUNT_SIZE = 82;

const runningServers: RunningServer[] = [];

let surfnet: Surfnet | undefined;
let interopEnv: Record<string, string> | undefined;
let splitRecipients: Record<string, string> = {};

type CompiledInstruction = {
  accountIndices: readonly number[];
  data: Uint8Array;
  programAddressIndex: number;
};

type CompiledMessage = {
  addressTableLookups?: readonly unknown[];
  instructions: readonly CompiledInstruction[];
  staticAccounts: readonly unknown[];
};

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
              await expectSettledTransactionShape(
                surfnet,
                scenario,
                scenarioEnv,
                result.settlement,
              );
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

async function expectSettledTransactionShape(
  surfnet: Surfnet,
  scenario: InteropScenario,
  scenarioEnv: Record<string, string>,
  settlement: unknown,
): Promise<void> {
  if (typeof settlement !== "string" || settlement.length === 0) {
    throw new Error(`Scenario ${scenario.id} did not return a settlement signature`);
  }

  const transaction = await fetchTransactionBase64(
    scenarioEnv.MPP_INTEROP_RPC_URL,
    settlement,
  );
  const message = decodeTransactionMessage(transaction);
  expect(message.addressTableLookups ?? []).toHaveLength(0);

  const matchedInstructions = new Set<number>();
  const expectedTransferCount = 1 + (scenario.splits?.length ?? 0);
  const primaryAmount = primaryDelta(scenario);
  expectSplTransferChecked(
    message,
    {
      destination: surfnet.getAta(
        scenarioEnv.MPP_INTEROP_PAY_TO,
        scenarioEnv.MPP_INTEROP_MINT,
      ),
      mint: scenarioEnv.MPP_INTEROP_MINT,
      amount: primaryAmount,
      decimals: 6,
    },
    matchedInstructions,
  );

  for (const split of scenario.splits ?? []) {
    const recipient = splitRecipients[split.recipientKey];
    const destination = surfnet.getAta(recipient, scenarioEnv.MPP_INTEROP_MINT);
    expectSplTransferChecked(
      message,
      {
        destination,
        mint: scenarioEnv.MPP_INTEROP_MINT,
        amount: BigInt(split.amount),
        decimals: 6,
      },
      matchedInstructions,
    );

    if (split.ataCreationRequired === true) {
      expectIdempotentAtaCreation(message, {
        ata: destination,
        owner: recipient,
        mint: scenarioEnv.MPP_INTEROP_MINT,
      });
    }

    if (split.memo) {
      expectMemo(message, split.memo);
    }
  }

  expectTransferCheckedCount(message, scenarioEnv.MPP_INTEROP_MINT, expectedTransferCount);
}

async function fetchTransactionBase64(
  rpcUrl: string,
  signature: string,
): Promise<string> {
  const response = await fetch(rpcUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "getTransaction",
      params: [
        signature,
        {
          commitment: "confirmed",
          encoding: "base64",
          maxSupportedTransactionVersion: 0,
        },
      ],
    }),
  });
  const payload = (await response.json()) as {
    error?: { message?: string };
    result?: {
      meta?: { err?: unknown };
      transaction?: [string, string];
    } | null;
  };
  if (payload.error) {
    throw new Error(payload.error.message ?? "getTransaction failed");
  }
  if (!payload.result) {
    throw new Error(`getTransaction returned no result for ${signature}`);
  }
  expect(payload.result.meta?.err ?? null).toBeNull();
  const transaction = payload.result.transaction?.[0];
  if (!transaction) {
    throw new Error(`getTransaction returned no base64 transaction for ${signature}`);
  }
  return transaction;
}

function decodeTransactionMessage(transactionBase64: string): CompiledMessage {
  const txBytes = getBase64Codec().encode(transactionBase64);
  const decoded = getTransactionDecoder().decode(txBytes);
  return getCompiledTransactionMessageDecoder().decode(
    decoded.messageBytes,
  ) as unknown as CompiledMessage;
}

function expectSplTransferChecked(
  message: CompiledMessage,
  expected: {
    destination: string;
    mint: string;
    amount: bigint;
    decimals: number;
  },
  matchedInstructions: Set<number>,
): void {
  const match = message.instructions.findIndex((instruction, index) => {
    if (matchedInstructions.has(index)) {
      return false;
    }
    if (accountAt(message, instruction.programAddressIndex) !== TOKEN_PROGRAM) {
      return false;
    }
    if (instruction.data[0] !== 12) {
      return false;
    }
    if (instruction.accountIndices.length < 4) {
      return false;
    }

    const amount = readU64Le(instruction.data, 1);
    const decimals = instruction.data[9];
    return (
      accountAt(message, instruction.accountIndices[1]) === expected.mint &&
      accountAt(message, instruction.accountIndices[2]) === expected.destination &&
      amount === expected.amount &&
      decimals === expected.decimals
    );
  });

  expect(
    match,
    `missing transferChecked mint=${expected.mint} destination=${expected.destination} amount=${expected.amount}`,
  ).not.toBe(-1);
  matchedInstructions.add(match);
}

function expectIdempotentAtaCreation(
  message: CompiledMessage,
  expected: {
    ata: string;
    owner: string;
    mint: string;
  },
): void {
  const match = message.instructions.find((instruction) => {
    if (accountAt(message, instruction.programAddressIndex) !== ASSOCIATED_TOKEN_PROGRAM) {
      return false;
    }
    if (instruction.data[0] !== 1) {
      return false;
    }
    return (
      accountAt(message, instruction.accountIndices[1]) === expected.ata &&
      accountAt(message, instruction.accountIndices[2]) === expected.owner &&
      accountAt(message, instruction.accountIndices[3]) === expected.mint &&
      accountAt(message, instruction.accountIndices[4]) === SYSTEM_PROGRAM &&
      accountAt(message, instruction.accountIndices[5]) === TOKEN_PROGRAM
    );
  });

  expect(
    match,
    `missing idempotent ATA creation ata=${expected.ata} owner=${expected.owner} mint=${expected.mint}`,
  ).toBeDefined();
}

function expectTransferCheckedCount(
  message: CompiledMessage,
  mint: string,
  expectedCount: number,
): void {
  const transfers = message.instructions.filter((instruction) => {
    if (accountAt(message, instruction.programAddressIndex) !== TOKEN_PROGRAM) {
      return false;
    }
    if (instruction.data[0] !== 12 || instruction.accountIndices.length < 4) {
      return false;
    }
    return accountAt(message, instruction.accountIndices[1]) === mint;
  });

  expect(
    transfers,
    `unexpected transferChecked instruction count for mint=${mint}`,
  ).toHaveLength(expectedCount);
}

function expectMemo(message: CompiledMessage, memo: string): void {
  const encoder = new TextEncoder();
  const expected = encoder.encode(memo);
  const match = message.instructions.find((instruction) => {
    if (accountAt(message, instruction.programAddressIndex) !== "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr") {
      return false;
    }
    return bytesEqual(instruction.data, expected);
  });

  expect(match, `missing memo instruction ${memo}`).toBeDefined();
}

function accountAt(message: CompiledMessage, index: number): string {
  return String(message.staticAccounts[index]);
}

function readU64Le(bytes: Uint8Array, offset: number): bigint {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return view.getBigUint64(offset, true);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false;
  }
  return left.every((value, index) => value === right[index]);
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
