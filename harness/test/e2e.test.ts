import net from "node:net";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  createSolanaRpc,
  getBase64Codec,
  getCompiledTransactionMessageDecoder,
  getTransactionDecoder,
} from "@solana/kit";
import { Surfnet } from "surfpool-sdk";
import { HarnessScenario, selectHarnessScenarios } from "../src/contracts";
import {
  clientImplementations,
  serverImplementations,
} from "../src/implementations";
import { runClient, startServer, stopServer } from "../src/process";
import {
  evaluateShardEligibility,
  SOCKET_UNAVAILABLE_CI_MESSAGE,
  socketGateMode,
} from "../src/guards";

type RunningServer = Awaited<ReturnType<typeof startServer>>;

const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const ASSOCIATED_TOKEN_PROGRAM = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";
const SYSTEM_PROGRAM = "11111111111111111111111111111111";
const MINT_ACCOUNT_SIZE = 82;
const SOL_NATIVE_DECIMALS = 9;
const DEFAULT_SPL_DECIMALS = 6;
const CLIENT_SOL_FUND_LAMPORTS = 5_000_000_000;

function tokenProgramAddress(
  variant: "TOKEN_PROGRAM" | "TOKEN_2022_PROGRAM" | undefined,
): string {
  return variant === "TOKEN_2022_PROGRAM" ? TOKEN_2022_PROGRAM : TOKEN_PROGRAM;
}

// The on-chain mint pubkey for a scenario. In pubkey mode this is just
// `scenario.asset`. In symbol mode the harness sends a stablecoin symbol
// to adapters and the on-chain mint is `scenario.expectedMint` (the
// pubkey each SDK's resolver is expected to return). For SOL-native
// scenarios there is no mint at all.
function onChainMintFor(scenario: HarnessScenario): string | null {
  if (isSolNative(scenario)) {
    return null;
  }
  if (scenario.currencyMode === "symbol") {
    if (!scenario.expectedMint) {
      throw new Error(
        `Scenario ${scenario.id} uses symbol mode but does not set expectedMint`,
      );
    }
    return scenario.expectedMint;
  }
  return scenario.asset;
}

function isSolNative(scenario: HarnessScenario): boolean {
  return scenario.assetKind === "sol";
}

function scenarioDecimals(scenario: HarnessScenario): number {
  if (typeof scenario.decimals === "number") {
    return scenario.decimals;
  }
  return isSolNative(scenario) ? SOL_NATIVE_DECIMALS : DEFAULT_SPL_DECIMALS;
}

const runningServers: RunningServer[] = [];

let surfnet: Surfnet | undefined;
let surfnetDrainTimer: NodeJS.Timeout | undefined;
let harnessEnv: Record<string, string> | undefined;
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
  tokenProgram: string,
  missingAsZero = false,
): Promise<bigint> {
  const rpc = createSolanaRpc(surfnet.rpcUrl);
  const ata = surfnet.getAta(owner, mint, tokenProgram);
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

async function getLamportBalance(
  surfnet: Surfnet,
  owner: string,
): Promise<bigint> {
  const rpc = createSolanaRpc(surfnet.rpcUrl);
  const response = await rpc.getBalance(owner as never).send();
  return BigInt(response.value);
}

// Balance helper that dispatches on scenario asset kind. For SPL
// scenarios it reads the recipient ATA token balance; for SOL-native
// scenarios it reads recipient lamports.
async function getPrimaryRecipientBalance(
  surfnet: Surfnet,
  scenario: HarnessScenario,
  owner: string,
  mint: string | null,
  tokenProgram: string,
): Promise<bigint> {
  if (isSolNative(scenario)) {
    return await getLamportBalance(surfnet, owner);
  }
  if (!mint) {
    throw new Error(
      `Scenario ${scenario.id} has no on-chain mint but is not SOL-native`,
    );
  }
  return await getTokenBalance(surfnet, owner, mint, tokenProgram);
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
const activeScenarios = selectHarnessScenarios(
  process.env.MPP_HARNESS_INTENTS,
  process.env.MPP_HARNESS_SCENARIOS,
);
const baseScenario = activeScenarios[0];

if (!baseScenario) {
  throw new Error("No harness scenarios are active");
}

beforeAll(async () => {
  if (!socketSupport) {
    return;
  }

  surfnet = Surfnet.start();
  // Periodically drain the JS-side surfpool event queue. The Rust
  // server fixture broadcasts via this in-process surfpool RPC, and
  // each broadcast enqueues commit/log events on the JS side. Without
  // a periodic drain, the queue backs up over a full matrix run and
  // surfpool's RPC stops responding to subsequent simulate/broadcast
  // calls, which surfaces as a 120s adapter-output timeout on
  // charge-idempotent-resubmit (the matrix's tail scenario). The
  // 1s cadence matches harness/start-surfnet-proxy.mjs, which
  // already does this for the proxy-mode launcher. See Ludo-7 / PR #102.
  surfnetDrainTimer = setInterval(() => {
    surfnet?.drainEvents();
  }, 1_000);

  const client = Surfnet.newKeypair();
  const payTo = Surfnet.newKeypair();
  const platform = Surfnet.newKeypair();

  // Deploy every mint referenced by an active SPL scenario under the
  // right token program with the right decimals byte. SOL-native
  // scenarios contribute lamport funding instead. Symbol-mode
  // scenarios deploy at `expectedMint`, not at the literal asset
  // string. Conflicting tokenProgram or decimals for the same mint
  // pubkey across scenarios is an authoring bug.
  type MintConfig = {
    variant: "TOKEN_PROGRAM" | "TOKEN_2022_PROGRAM";
    decimals: number;
  };
  const uniqueMints = new Map<string, MintConfig>();
  let needsSolFunding = false;
  for (const scenario of activeScenarios) {
    // Push-mode scenarios make the client pay its own fee on-chain, so
    // the client wallet must be pre-funded with lamports even for SPL
    // payments. SOL-native scenarios already trigger funding below.
    if (scenario.paymentMode === "push") {
      needsSolFunding = true;
    }
    if (isSolNative(scenario)) {
      needsSolFunding = true;
      continue;
    }
    const variant = scenario.tokenProgram ?? "TOKEN_PROGRAM";
    const decimals = scenarioDecimals(scenario);
    const mintPubkey = onChainMintFor(scenario);
    if (!mintPubkey) {
      continue;
    }
    const existing = uniqueMints.get(mintPubkey);
    if (existing && existing.variant !== variant) {
      throw new Error(
        `Conflicting tokenProgram for mint ${mintPubkey}: ${existing.variant} vs ${variant} (scenario ${scenario.id})`,
      );
    }
    if (existing && existing.decimals !== decimals) {
      throw new Error(
        `Conflicting decimals for mint ${mintPubkey}: ${existing.decimals} vs ${decimals} (scenario ${scenario.id})`,
      );
    }
    uniqueMints.set(mintPubkey, { variant, decimals });
  }
  for (const [mintPubkey, config] of uniqueMints) {
    const programAddress = tokenProgramAddress(config.variant);
    surfnet.setAccount(
      mintPubkey,
      1_461_600,
      createSplMintAccountData(config.decimals),
      programAddress,
    );
    surfnet.fundToken(client.publicKey, mintPubkey, 100_000, programAddress);
    surfnet.fundToken(payTo.publicKey, mintPubkey, 1, programAddress);
  }

  splitRecipients = {
    platform: platform.publicKey,
  };

  // G13. Pre-create the platform recipient's ATA for any scenario that
  // requests it. `fundToken` with zero amount is the lowest-friction
  // way to call the underlying surfnet cheatcode without changing the
  // settled token balance the test asserts against.
  for (const scenario of activeScenarios) {
    if (!scenario.preCreatePlatformAta) {
      continue;
    }
    const mintPubkey = onChainMintFor(scenario);
    if (!mintPubkey) {
      throw new Error(
        `Scenario ${scenario.id} requested preCreatePlatformAta but has no on-chain mint`,
      );
    }
    const variant = scenario.tokenProgram ?? "TOKEN_PROGRAM";
    surfnet.fundToken(
      platform.publicKey,
      mintPubkey,
      0,
      tokenProgramAddress(variant),
    );
  }

  // G27. SOL-native scenarios need the client wallet pre-funded with
  // lamports so the system transfer can succeed.
  if (needsSolFunding) {
    surfnet.fundSol(client.publicKey, CLIENT_SOL_FUND_LAMPORTS);
  }

  harnessEnv = {
    MPP_HARNESS_RPC_URL: surfnet.rpcUrl,
    MPP_HARNESS_NETWORK: baseScenario.network,
    MPP_HARNESS_MINT: baseScenario.asset,
    MPP_HARNESS_PRICE: baseScenario.price,
    MPP_HARNESS_SECRET_KEY: "mpp-harness-secret-key",
    MPP_HARNESS_PAY_TO: payTo.publicKey,
    MPP_HARNESS_CLIENT_SECRET_KEY: JSON.stringify(Array.from(client.secretKey)),
    MPP_HARNESS_FEE_PAYER_SECRET_KEY: JSON.stringify(
      Array.from(surfnet.payerSecretKey),
    ),
    // x402-shaped twins of the same surfpool fixtures so x402 scenarios
    // can reuse the matrix's funded keypairs.
    X402_HARNESS_RPC_URL: surfnet.rpcUrl,
    X402_HARNESS_PAY_TO: payTo.publicKey,
    X402_HARNESS_CLIENT_SECRET_KEY: JSON.stringify(Array.from(client.secretKey)),
    X402_HARNESS_FACILITATOR_SECRET_KEY: JSON.stringify(
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

afterAll(() => {
  if (surfnetDrainTimer) {
    clearInterval(surfnetDrainTimer);
    surfnetDrainTimer = undefined;
  }
});

describe("mpp harness", () => {
  const activeServers = serverImplementations.filter(
    (implementation) => implementation.enabled,
  );
  const activeClients = clientImplementations.filter(
    (implementation) => implementation.enabled,
  );
  // P0: a sandbox that cannot bind a loopback socket must NOT green-skip
  // the whole matrix under CI. Outside CI we still skip so a restricted
  // local box does not go red. `socketAwareIt` registers a real test, a
  // skip, or a hard-failing test depending on the gate mode.
  const gateMode = socketGateMode(socketSupport);
  const socketAwareIt = (
    name: string,
    body: () => void | Promise<void>,
  ): void => {
    if (gateMode === "run") {
      it(name, body);
      return;
    }
    if (gateMode === "fail") {
      it(name, () => {
        throw new Error(SOCKET_UNAVAILABLE_CI_MESSAGE);
      });
      return;
    }
    it.skip(name, body);
  };

  for (const scenario of activeScenarios) {
    // Cross-server portability and idempotent-resubmit scenarios
    // run in a dedicated block below; skip them here so the standard
    // pair-iteration does not try to drive them with the wrong runner.
    if (
      scenario.kind === "cross-server-portability" ||
      scenario.kind === "idempotent-resubmit"
    ) {
      continue;
    }
    // The x402-exact intent reuses this matrix's surfpool + funded
    // keypairs. `environmentForScenario` emits X402_HARNESS_* shadows
    // alongside MPP_HARNESS_* (same fixtures), and the pair filter
    // below gates on `impl.intents.includes(scenario.intent)` so
    // charge-only adapters skip x402 scenarios automatically.
    const intentServerFilter = (implementation: {
      id: string;
      intents?: string[];
    }) =>
      (implementation.intents ?? ["charge"]).includes(scenario.intent) &&
      (!scenario.serverIds || scenario.serverIds.includes(implementation.id));
    const intentClientFilter = (implementation: {
      id: string;
      intents?: string[];
    }) =>
      (implementation.intents ?? ["charge"]).includes(scenario.intent) &&
      (!scenario.clientIds || scenario.clientIds.includes(implementation.id));

    const scenarioServers = activeServers.filter(intentServerFilter);
    const scenarioClients = activeClients.filter(intentClientFilter);
    // Full-registry eligibility (ignores the `enabled` shard flag) so the
    // guard can tell a legitimate shard exclusion from a genuine false green.
    const fullServers = serverImplementations.filter(intentServerFilter);
    const fullClients = clientImplementations.filter(intentClientFilter);

    // P0 zero-eligible guard, shard-aware: a scenario that has no eligible
    // client/server/pair across the FULL adapter registry is a false green
    // and hard-fails. A scenario that is eligible in the full registry but
    // excluded by THIS shard's enabled-adapter subset is a legitimate
    // shard skip, not a false green.
    const eligibility = evaluateShardEligibility({
      scenarioId: scenario.id,
      shard: {
        clientCount: scenarioClients.length,
        serverCount: scenarioServers.length,
        pairCount: scenarioServers.length * scenarioClients.length,
      },
      full: {
        clientCount: fullClients.length,
        serverCount: fullServers.length,
        pairCount: fullServers.length * fullClients.length,
      },
    });
    it(`${scenario.id}: has at least one eligible client/server pair`, () => {
      // evaluateShardEligibility already threw above if globally empty; this
      // test exists to keep the guard visible per-scenario in the report.
      if (eligibility.verdict === "skip") {
        console.log(`[harness] ${eligibility.reason}`);
      }
    });
    if (eligibility.verdict === "skip") {
      continue;
    }

    for (const serverImplementation of scenarioServers) {
      for (const clientImplementation of scenarioClients) {
        socketAwareIt(
          `${scenario.id}: ${clientImplementation.id} client pays ${serverImplementation.id} server`,
          async () => {
            if (!surfnet || !harnessEnv) {
              throw new Error(
                "Surfpool harness environment was not initialized",
              );
            }

            const scenarioEnv = environmentForScenario(harnessEnv, scenario);
            const scenarioTokenProgram = tokenProgramAddress(scenario.tokenProgram);
            // On-chain mint pubkey (resolved expectedMint in symbol mode,
            // literal asset in pubkey mode, or null for SOL-native). The
            // literal in scenarioEnv goes to the adapter so the SDK's
            // resolver is exercised end-to-end.
            const onChainMint = onChainMintFor(scenario);
            const initialBalance = await getPrimaryRecipientBalance(
              surfnet,
              scenario,
              scenarioEnv.MPP_HARNESS_PAY_TO,
              onChainMint,
              scenarioTokenProgram,
            );
            const initialSplitBalances = await splitBalances(
              surfnet,
              scenario,
              onChainMint,
              scenarioTokenProgram,
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

            const finalBalance = await getPrimaryRecipientBalance(
              surfnet,
              scenario,
              scenarioEnv.MPP_HARNESS_PAY_TO,
              onChainMint,
              scenarioTokenProgram,
            );
            const finalSplitBalances = await splitBalances(
              surfnet,
              scenario,
              onChainMint,
              scenarioTokenProgram,
              // For 402 scenarios the recipient ATA may never have
              // been created on-chain; treat missing as zero so the
              // delta assertion below still holds.
              scenario.expectedStatus === 402,
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
              // Lamport balances are always accessible (unlike SPL token
              // accounts, which can be missing when a 402 fires before
              // any ATA creation), so assert zero delta for SOL-native
              // 402s too. Catches a future SOL-native scenario that
              // accidentally triggers a transfer despite returning 402.
              expect(finalBalance - initialBalance).toBe(0n);
              expect(
                splitDeltas(initialSplitBalances, finalSplitBalances),
              ).toEqual(expectedZeroSplitDeltas(scenario));
              // G39 fault matrix: every server SDK must emit the same
              // canonical L6 structured code for the same failure class.
              // Only asserted when the scenario declares an expectedCode
              // so adapters that have not yet shipped L6 emission do not
              // trip the matrix. Once an adapter ships L6 emission, its
              // server id is added to the scenario's serverIds list and
              // the matrix locks in the cross-SDK agreement.
              if (scenario.expectedCode) {
                const body = result.responseBody as
                  | { code?: string }
                  | undefined;
                expect(
                  body?.code,
                  `G39: server ${serverImplementation.id} did not emit canonical code on 402 for scenario ${scenario.id}. Got body: ${JSON.stringify(result.responseBody)}`,
                ).toBe(scenario.expectedCode);
              }
            }
          },
        );
      }
    }
  }

  // Cross-server credential portability + same-server idempotent
  // resubmit. These run outside the per-pair matrix because they
  // either need two distinct servers (portability) or assert a 402
  // canonical reject on a credential that was already settled
  // (idempotent). Only the TypeScript client adapter implements the
  // raw capture/re-submit flow today, so other clients are gated out.
  const crossServerScenarios = activeScenarios.filter(
    (scenario) => scenario.kind === "cross-server-portability",
  );
  const idempotentScenarios = activeScenarios.filter(
    (scenario) => scenario.kind === "idempotent-resubmit",
  );

  for (const scenario of crossServerScenarios) {
    const pairs = scenario.crossServerPairs ?? [];
    const clientFilter = (implementation: { id: string }) =>
      !scenario.clientIds || scenario.clientIds.includes(implementation.id);
    const eligibleClients = activeClients.filter(clientFilter);
    const resolvablePairs = pairs.filter(
      ([aId, bId]) =>
        activeServers.some((impl) => impl.id === aId) &&
        activeServers.some((impl) => impl.id === bId),
    );
    // Full-registry view (ignores the shard `enabled` flag).
    const fullEligibleClients = clientImplementations.filter(clientFilter);
    const fullResolvablePairs = pairs.filter(
      ([aId, bId]) =>
        serverImplementations.some((impl) => impl.id === aId) &&
        serverImplementations.some((impl) => impl.id === bId),
    );
    const eligibility = evaluateShardEligibility({
      scenarioId: scenario.id,
      shard: {
        clientCount: eligibleClients.length,
        serverCount: resolvablePairs.length,
        pairCount: resolvablePairs.length * eligibleClients.length,
      },
      full: {
        clientCount: fullEligibleClients.length,
        serverCount: fullResolvablePairs.length,
        pairCount: fullResolvablePairs.length * fullEligibleClients.length,
      },
    });
    it(`${scenario.id}: has at least one eligible cross-server pair`, () => {
      if (eligibility.verdict === "skip") {
        console.log(`[harness] ${eligibility.reason}`);
      }
    });
    if (eligibility.verdict === "skip") {
      continue;
    }
    for (const [aId, bId] of pairs) {
      const serverA = activeServers.find((impl) => impl.id === aId);
      const serverB = activeServers.find((impl) => impl.id === bId);
      if (!serverA || !serverB) {
        continue;
      }
      for (const clientImplementation of eligibleClients) {
        socketAwareIt(
          `${scenario.id}: ${clientImplementation.id} client, A=${aId} B=${bId}`,
          async () => {
            if (!surfnet || !harnessEnv) {
              throw new Error("Surfpool harness environment was not initialized");
            }
            const envA = environmentForScenario(harnessEnv, scenario);
            const envB = {
              ...environmentForScenario(harnessEnv, scenario),
              MPP_HARNESS_SECRET_KEY: "mpp-harness-secret-key-server-b",
            };
            const a = await startServer(serverA, envA);
            runningServers.push(a);
            const b = await startServer(serverB, envB);
            runningServers.push(b);
            const aUrl = `http://127.0.0.1:${a.ready.port}${scenario.resourcePath}`;
            const bUrl = `http://127.0.0.1:${b.ready.port}${scenario.resourcePath}`;
            const result = await runClient(clientImplementation, aUrl, {
              ...envA,
              MPP_HARNESS_RESUBMIT_URL: bUrl,
            });
            const resultPayload = JSON.stringify(result, null, 2);
            const firstStatus = (result as unknown as { firstStatus?: number })
              .firstStatus;
            expect(firstStatus, `first hop must succeed: ${resultPayload}`).toBe(
              200,
            );
            expect(result.status, resultPayload).toBe(scenario.expectedStatus);
            if (scenario.expectedCode) {
              const body = result.responseBody as { code?: string } | undefined;
              expect(
                body?.code,
                `server B=${bId} did not emit canonical code; body: ${JSON.stringify(result.responseBody)}`,
              ).toBe(scenario.expectedCode);
            }
          },
        );
      }
    }
  }

  for (const scenario of idempotentScenarios) {
    const serverFilter = (impl: { id: string }) =>
      !scenario.serverIds || scenario.serverIds.includes(impl.id);
    const clientFilter = (impl: { id: string }) =>
      !scenario.clientIds || scenario.clientIds.includes(impl.id);
    const eligibleServers = activeServers.filter(serverFilter);
    const eligibleClients = activeClients.filter(clientFilter);
    const fullEligibleServers = serverImplementations.filter(serverFilter);
    const fullEligibleClients = clientImplementations.filter(clientFilter);
    const eligibility = evaluateShardEligibility({
      scenarioId: scenario.id,
      shard: {
        clientCount: eligibleClients.length,
        serverCount: eligibleServers.length,
        pairCount: eligibleServers.length * eligibleClients.length,
      },
      full: {
        clientCount: fullEligibleClients.length,
        serverCount: fullEligibleServers.length,
        pairCount: fullEligibleServers.length * fullEligibleClients.length,
      },
    });
    it(`${scenario.id}: has at least one eligible idempotent pair`, () => {
      if (eligibility.verdict === "skip") {
        console.log(`[harness] ${eligibility.reason}`);
      }
    });
    if (eligibility.verdict === "skip") {
      continue;
    }
    for (const serverImplementation of eligibleServers) {
      for (const clientImplementation of eligibleClients) {
        socketAwareIt(
          `${scenario.id}: ${clientImplementation.id} client pays ${serverImplementation.id} server twice`,
          async () => {
            if (!surfnet || !harnessEnv) {
              throw new Error("Surfpool harness environment was not initialized");
            }
            const env = environmentForScenario(harnessEnv, scenario);
            const server = await startServer(serverImplementation, env);
            runningServers.push(server);
            const url = `http://127.0.0.1:${server.ready.port}${scenario.resourcePath}`;
            const result = await runClient(clientImplementation, url, {
              ...env,
              MPP_HARNESS_RESUBMIT_URL: url,
            });
            const resultPayload = JSON.stringify(result, null, 2);
            const firstStatus = (result as unknown as { firstStatus?: number })
              .firstStatus;
            expect(firstStatus, `first pay must succeed: ${resultPayload}`).toBe(
              200,
            );
            expect(result.status, resultPayload).toBe(scenario.expectedStatus);
            if (scenario.expectedCode) {
              const body = result.responseBody as { code?: string } | undefined;
              expect(
                body?.code,
                `server ${serverImplementation.id} did not emit canonical code on resubmit; body: ${JSON.stringify(result.responseBody)}`,
              ).toBe(scenario.expectedCode);
            }
          },
        );
      }
    }
  }
});

function environmentForScenario(
  baseEnv: Record<string, string>,
  scenario: HarnessScenario,
): Record<string, string> {
  const env: Record<string, string> = {
    ...baseEnv,
    MPP_HARNESS_AMOUNT: scenario.amount,
    MPP_HARNESS_MINT: scenario.asset,
    MPP_HARNESS_NETWORK: scenario.network,
    MPP_HARNESS_PAYMENT_MODE: scenario.paymentMode ?? "pull",
    MPP_HARNESS_PRICE: scenario.price,
    MPP_HARNESS_RESOURCE_PATH: scenario.resourcePath,
    MPP_HARNESS_DECIMALS: String(scenarioDecimals(scenario)),
    MPP_HARNESS_ASSET_KIND: isSolNative(scenario) ? "sol" : "spl",
    ...(scenario.replaySource
      ? {
          MPP_HARNESS_REPLAY_SOURCE_AMOUNT: scenario.replaySource.amount,
          MPP_HARNESS_REPLAY_SOURCE_PATH: scenario.replaySource.resourcePath,
          MPP_HARNESS_REPLAY_SOURCE_PRICE: scenario.replaySource.price,
        }
      : {}),
    MPP_HARNESS_SETTLEMENT_HEADER: scenario.settlementHeader,
    MPP_HARNESS_SPLITS: JSON.stringify(
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
  if (typeof scenario.clientComputeUnitLimit === "number") {
    env.MPP_HARNESS_COMPUTE_UNIT_LIMIT = String(scenario.clientComputeUnitLimit);
  }
  if (typeof scenario.clientComputeUnitPrice === "string") {
    env.MPP_HARNESS_COMPUTE_UNIT_PRICE = scenario.clientComputeUnitPrice;
  }
  if (scenario.intent === "x402-exact") {
    // Adapters that auto-detect protocol by env namespace
    // (e.g. the Ruby adapter) prefer this explicit hint - the
    // matrix populates both MPP_HARNESS_* and X402_HARNESS_* shadows
    // from the same surfpool fixtures, so namespace probing alone
    // is ambiguous.
    env.PAY_KIT_HARNESS_PROTOCOL = "x402";
    env.X402_HARNESS_AMOUNT = scenario.amount;
    env.X402_HARNESS_MINT = scenario.asset;
    env.X402_HARNESS_NETWORK = scenario.network;
    env.X402_HARNESS_PRICE = scenario.price;
    env.X402_HARNESS_RESOURCE_PATH = scenario.resourcePath;
    env.X402_HARNESS_SETTLEMENT_HEADER = scenario.settlementHeader;
  } else {
    env.PAY_KIT_HARNESS_PROTOCOL = "mpp";
  }
  return env;
}

async function expectSettledTransactionShape(
  surfnet: Surfnet,
  scenario: HarnessScenario,
  scenarioEnv: Record<string, string>,
  settlement: unknown,
): Promise<void> {
  if (typeof settlement !== "string" || settlement.length === 0) {
    throw new Error(`Scenario ${scenario.id} did not return a settlement signature`);
  }

  const transaction = await fetchTransactionBase64(
    scenarioEnv.MPP_HARNESS_RPC_URL,
    settlement,
  );
  const message = decodeTransactionMessage(transaction);
  expect(message.addressTableLookups ?? []).toHaveLength(0);

  // G27. SOL-native scenarios expect a System Program transfer, not
  // SPL transferChecked. The system transfer discriminator is u32 LE
  // = 2 in the first 4 bytes of the instruction data, followed by a
  // u64 LE lamports amount.
  if (isSolNative(scenario)) {
    expectSystemProgramTransfer(message, {
      destination: scenarioEnv.MPP_HARNESS_PAY_TO,
      amount: primaryDelta(scenario),
    });
    return;
  }

  const matchedInstructions = new Set<number>();
  const expectedTransferCount = 1 + (scenario.splits?.length ?? 0);
  const primaryAmount = primaryDelta(scenario);
  const tokenProgram = tokenProgramAddress(scenario.tokenProgram);
  const onChainMint = onChainMintFor(scenario);
  if (!onChainMint) {
    throw new Error(
      `Scenario ${scenario.id} is not SOL-native but resolves to no on-chain mint`,
    );
  }
  const decimals = scenarioDecimals(scenario);
  expectSplTransferChecked(
    message,
    {
      destination: surfnet.getAta(
        scenarioEnv.MPP_HARNESS_PAY_TO,
        onChainMint,
        tokenProgram,
      ),
      mint: onChainMint,
      amount: primaryAmount,
      decimals,
      tokenProgram,
    },
    matchedInstructions,
  );

  for (const split of scenario.splits ?? []) {
    const recipient = splitRecipients[split.recipientKey];
    const destination = surfnet.getAta(
      recipient,
      onChainMint,
      tokenProgram,
    );
    expectSplTransferChecked(
      message,
      {
        destination,
        mint: onChainMint,
        amount: BigInt(split.amount),
        decimals,
        tokenProgram,
      },
      matchedInstructions,
    );

    if (split.ataCreationRequired === true) {
      expectIdempotentAtaCreation(message, {
        ata: destination,
        owner: recipient,
        mint: onChainMint,
        tokenProgram,
      });
    }

    if (split.memo) {
      expectMemo(message, split.memo);
    }
  }

  expectTransferCheckedCount(
    message,
    onChainMint,
    expectedTransferCount,
    tokenProgram,
  );
}

function expectSystemProgramTransfer(
  message: CompiledMessage,
  expected: { destination: string; amount: bigint },
): void {
  const match = message.instructions.find((instruction) => {
    if (
      accountAt(message, instruction.programAddressIndex) !== SYSTEM_PROGRAM
    ) {
      return false;
    }
    // System Program transfer discriminator (4-byte u32 LE = 2),
    // followed by a u64 LE lamports value (8 bytes). Total 12 bytes.
    if (instruction.data.length < 12) {
      return false;
    }
    const view = new DataView(
      instruction.data.buffer,
      instruction.data.byteOffset,
      instruction.data.byteLength,
    );
    if (view.getUint32(0, true) !== 2) {
      return false;
    }
    if (instruction.accountIndices.length < 2) {
      return false;
    }
    const destination = accountAt(message, instruction.accountIndices[1]);
    const amount = view.getBigUint64(4, true);
    return destination === expected.destination && amount === expected.amount;
  });
  expect(
    match,
    `missing system transfer destination=${expected.destination} amount=${expected.amount}`,
  ).toBeDefined();
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
    tokenProgram: string;
  },
  matchedInstructions: Set<number>,
): void {
  const match = message.instructions.findIndex((instruction, index) => {
    if (matchedInstructions.has(index)) {
      return false;
    }
    if (
      accountAt(message, instruction.programAddressIndex) !== expected.tokenProgram
    ) {
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
    tokenProgram: string;
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
      accountAt(message, instruction.accountIndices[5]) === expected.tokenProgram
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
  tokenProgram: string,
): void {
  const transfers = message.instructions.filter((instruction) => {
    if (accountAt(message, instruction.programAddressIndex) !== tokenProgram) {
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
  scenario: HarnessScenario,
  mint: string | null,
  tokenProgram: string,
  missingAsZero: boolean,
): Promise<Record<string, bigint>> {
  const balances: Record<string, bigint> = {};
  for (const split of scenario.splits ?? []) {
    const recipient = splitRecipients[split.recipientKey];
    if (isSolNative(scenario)) {
      balances[split.recipientKey] = await getLamportBalance(surfnet, recipient);
      continue;
    }
    if (!mint) {
      throw new Error(
        `Scenario ${scenario.id} has splits but no on-chain mint`,
      );
    }
    balances[split.recipientKey] = await getTokenBalance(
      surfnet,
      recipient,
      mint,
      tokenProgram,
      missingAsZero,
    );
  }
  return balances;
}

function primaryDelta(scenario: HarnessScenario): bigint {
  return (
    BigInt(scenario.amount) -
    (scenario.splits ?? []).reduce(
      (sum, split) => sum + BigInt(split.amount),
      0n,
    )
  );
}

function expectedSplitDeltas(
  scenario: HarnessScenario,
): Record<string, bigint> {
  const deltas: Record<string, bigint> = {};
  for (const split of scenario.splits ?? []) {
    deltas[split.recipientKey] = BigInt(split.amount);
  }
  return deltas;
}

function expectedZeroSplitDeltas(
  scenario: HarnessScenario,
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
