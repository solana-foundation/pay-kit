import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  assertExpectedChargeCases,
  chargeCaseKey,
  chargeToolchains,
  enumerateChargeCases,
  planChargeBuilds,
  planChargeMatrix,
  type ChargeCase,
} from "../src/ci-matrix";
import { getNativeTarget } from "../src/artifacts";
import { clientImplementations, serverImplementations } from "../src/implementations";
import { chargeScenarios } from "../src/intents/charge";
import type { HarnessScenario } from "../src/contracts";

const clients = clientImplementations.filter((entry) => (entry.intents ?? ["charge"]).includes("charge"));
const servers = serverImplementations.filter((entry) => (entry.intents ?? ["charge"]).includes("charge"));
const basic = chargeScenarios.find((scenario) => scenario.id === "charge-basic")!;
const replay = chargeScenarios.find((scenario) => scenario.kind === "idempotent-resubmit")!;

function plannedKeys(scenarios: readonly HarnessScenario[] = chargeScenarios): string[] {
  return planChargeMatrix(clientImplementations, serverImplementations, scenarios)
    .flatMap((shard) => JSON.parse(shard.env.MPP_HARNESS_EXPECTED_CASES) as string[])
    .sort();
}

describe("authoritative MPP charge CI plan", () => {
  it("builds once upstream and keeps compiler calls out of charge matrix legs", () => {
    const workflow = readFileSync(
      new URL("../../.github/workflows/mpp-matrix.yml", import.meta.url), "utf8",
    );
    const consumer = readFileSync(
      new URL("../../.github/actions/setup-harness-leg/action.yml", import.meta.url), "utf8",
    );
    const charge = workflow.split("\n  charge:\n")[1]?.split("\n  complete:\n")[0];
    expect(charge).toBeDefined();
    for (const text of [charge!, consumer]) {
      expect(text).not.toMatch(/cargo (?:run|build)|go (?:run|build)|swift (?:run|build)|gradle|rust-toolchain|setup-go|build-adapters\.ts|--filter @solana\/mpp build/);
      expect(text).not.toContain("uses: ./.github/actions/setup-harness\n");
    }
    expect(charge).toContain("uses: ./.github/actions/setup-harness-leg");
    expect(charge).toContain("native-artifact: ${{ matrix.nativeArtifact }}");
    expect(charge).toContain("needs: [plan, build-node, build-native]");
    expect(charge).toContain("java-package: jre");
    expect(consumer).toContain("HARNESS_PREBUILT_DIR");
    expect(consumer).toContain("name: mpp-dist");
    expect(workflow.match(/pnpm --filter @solana\/mpp build/g)).toHaveLength(1);
    expect(workflow.match(/node --import tsx build-adapters\.ts/g)).toHaveLength(1);
    expect(workflow).toContain('tar -czf "$RUNNER_TEMP/adapters.tar.gz"');
    expect(workflow).toContain("matrix: ${{ fromJSON(needs.plan.outputs.build_matrix) }}");
    expect(workflow).toContain("test/charge-client-gc.test.ts");
    expect(workflow).toContain("test/canonical-codes.test.ts");
    expect(workflow).toContain("fail-fast: false");
    expect(workflow).toContain("matrix: ${{ fromJSON(needs.plan.outputs.matrix) }}");
    expect(workflow).toContain("env: ${{ matrix.env }}");
    expect(workflow).toContain("needs: [plan, build-node, build-native, charge]");
    for (const result of ["PLAN", "NODE", "NATIVE", "CHARGE"]) {
      expect(workflow).toContain(`test "$${result}_RESULT" = success`);
    }
    expect(workflow).not.toContain("--testNamePattern");
  });

  it("builds every compiled role exactly once per required platform", () => {
    const builds = planChargeBuilds();
    expect(builds).toHaveLength(2);
    const produced = builds.flatMap((build) => [
      ...build.clients.split(",").filter(Boolean).map((id) => `${build.platform}:client:${id}`),
      ...build.servers.split(",").filter(Boolean).map((id) => `${build.platform}:server:${id}`),
    ]);
    // Independent oracle: macOS server artifacts are required by Swift clients.
    expect(produced.sort()).toEqual([
      "linux-x64:client:rust", "linux-x64:client:go", "linux-x64:client:kotlin",
      "linux-x64:server:rust", "linux-x64:server:go",
      "darwin-arm64:client:swift", "darwin-arm64:server:rust", "darwin-arm64:server:go",
    ].sort());
    expect(new Set(produced).size).toBe(produced.length);
    expect(new Set(builds.map((build) => build.nativeArtifact)).size).toBe(builds.length);
    expect(builds.map((build) => build.toolchains)).toEqual([
      ["go", "kotlin", "rust"], ["go", "rust", "swift"],
    ]);
  });

  it("gives every native consumer exactly one matching platform producer", () => {
    const shards = planChargeMatrix();
    const builds = planChargeBuilds(shards);
    for (const shard of shards) {
      let nativeCount = 0;
      for (const [role, selector] of [
        ["client", "MPP_HARNESS_CLIENTS"], ["server", "MPP_HARNESS_SERVERS"],
      ] as const) {
        for (const id of shard.env[selector].split(",")) {
          if (!getNativeTarget(role, id)) continue;
          nativeCount++;
          const producers = builds.filter((build) =>
            build.nativeArtifact === shard.nativeArtifact &&
            build.platform === shard.platform && build.runner === shard.runner &&
            (role === "client" ? build.clients : build.servers).split(",").includes(id),
          );
          expect(producers, `${shard.id}: ${role} ${id}`).toHaveLength(1);
        }
      }
      expect(Boolean(shard.nativeArtifact)).toBe(nativeCount > 0);
    }
  });

  it("unions native consumers without rebuilding shared targets or interpreted SDKs", () => {
    const shards = planChargeMatrix();
    expect(planChargeBuilds([...shards, ...shards])).toEqual(planChargeBuilds(shards));
    expect(planChargeBuilds(shards.filter((shard) => !shard.nativeArtifact))).toEqual([]);
    expect(planChargeBuilds(shards.filter((shard) => shard.id === "swift-to-rust")))
      .toEqual([{
        platform: "darwin-arm64", runner: "macos-latest",
        nativeArtifact: "mpp-adapters-darwin-arm64",
        clients: "swift", servers: "rust", toolchains: ["rust", "swift"],
      }]);
  });

  it("covers every eligible registry pair exactly once, including TS -> TS", () => {
    // Independent oracle: do not call the planner's enumerator here.
    const expected: string[] = [];
    for (const scenario of chargeScenarios) {
      for (const client of clients) {
        if (scenario.clientIds && !scenario.clientIds.includes(client.id)) continue;
        if (scenario.kind === "cross-server-portability") {
          for (const [source, target] of scenario.crossServerPairs ?? []) {
            expected.push(chargeCaseKey({
              scenarioId: scenario.id, clientId: client.id,
              serverId: source, targetServerId: target,
            }));
          }
        } else {
          for (const server of servers) {
            if (scenario.serverIds && !scenario.serverIds.includes(server.id)) continue;
            expected.push(chargeCaseKey({
              scenarioId: scenario.id, clientId: client.id, serverId: server.id,
            }));
          }
        }
      }
    }
    expect(plannedKeys()).toEqual(expected.sort());
    expect(new Set(expected).size).toBe(expected.length);
    expect(planChargeMatrix().some((shard) => shard.id === "typescript-to-typescript")).toBe(true);
  });

  it("requires the real replay scenario for every charge client and server", () => {
    expect(replay.clientIds).toBeUndefined();
    expect(replay.serverIds).toBeUndefined();
    const expected = clients.flatMap((client) =>
      servers.map((server) => chargeCaseKey({
        scenarioId: replay.id,
        clientId: client.id,
        serverId: server.id,
      })),
    );
    expect(plannedKeys([replay])).toEqual(expected.sort());
  });

  it("selects exactly its declared cases, with only necessary toolchains", () => {
    const allCases = enumerateChargeCases(clientImplementations, serverImplementations, chargeScenarios);
    for (const shard of planChargeMatrix()) {
      const selectedClients = shard.env.MPP_HARNESS_CLIENTS.split(",");
      const selectedServers = shard.env.MPP_HARNESS_SERVERS.split(",");
      const selectedScenarios = shard.env.MPP_HARNESS_SCENARIOS.split(",");
      const selected = allCases.filter((test) =>
        selectedClients.includes(test.clientId) &&
        selectedServers.includes(test.serverId) &&
        (!test.targetServerId || selectedServers.includes(test.targetServerId)) &&
        selectedScenarios.includes(test.scenarioId),
      );
      expect(selected.length).toBeGreaterThan(0);
      expect(selected.length).toBe(shard.caseCount);
      expect(selectedScenarios).toEqual(shard.scenarioIds);
      expect(shard.env.MPP_HARNESS_INTENTS).toBe("charge");
      expect(shard.env.HARNESS_STRICT_SHARD).toBe("1");
      expect(() => assertExpectedChargeCases(selected, shard.env.MPP_HARNESS_EXPECTED_CASES)).not.toThrow();
      expect(new Set(shard.toolchains)).toEqual(new Set(
        [...selectedClients, ...selectedServers].map((id) => chargeToolchains[id]),
      ));
      expect(shard.runner).toBe(shard.toolchains.includes("swift") ? "macos-latest" : "ubuntu-latest");
    }
  });

  it("automatically includes newly eligible replay clients and servers", () => {
    const narrow = { ...replay, clientIds: ["typescript"], serverIds: ["typescript"] };
    const expanded = { ...replay, clientIds: undefined, serverIds: undefined };
    expect(plannedKeys([narrow])).toHaveLength(1);
    expect(plannedKeys([expanded])).toHaveLength(clients.length * servers.length);
    for (const client of clients) {
      for (const server of servers) {
        expect(plannedKeys([expanded])).toContain(chargeCaseKey({
          scenarioId: replay.id, clientId: client.id, serverId: server.id,
        }));
      }
    }
  });

  it("automatically includes new scenarios and declared portability pairs", () => {
    const added = { ...basic, id: "future-charge-scenario" };
    expect(plannedKeys([...chargeScenarios, added]).length - plannedKeys().length)
      .toBe(clients.length * servers.length);
    const portability = chargeScenarios.find((scenario) => scenario.kind === "cross-server-portability")!;
    const expanded = {
      ...portability,
      serverIds: undefined,
      crossServerPairs: [["python", "php"], ["php", "python"]] as Array<[string, string]>,
    };
    const shards = planChargeMatrix(clientImplementations, serverImplementations, [expanded]);
    expect(shards).toHaveLength(1);
    expect(shards[0].caseCount).toBe(2);
    expect(shards[0].toolchains.sort()).toEqual(["php", "python", "typescript"]);
  });

  it("requires toolchain configuration for new SDKs, and rejects stale/unknown configuration", () => {
    const newClients = [...clientImplementations, { ...clients[0], id: "new-sdk" }];
    expect(() => planChargeMatrix(newClients)).toThrow("Missing toolchain for new-sdk");
    expect(() => planChargeMatrix(undefined, undefined, undefined, {
      ...chargeToolchains, retired: "rust",
    })).toThrow("Stale toolchain adapter");
    expect(() => planChargeMatrix(undefined, undefined, undefined, {
      ...chargeToolchains, rust: "unconfigured",
    })).toThrow("Unknown toolchain");
    expect(() => planChargeMatrix(undefined, undefined, undefined, {
      ...chargeToolchains, rust: "go",
    })).toThrow("Native toolchain mismatch");
    expect(() => planChargeMatrix(newClients, serverImplementations, [basic], {
      ...chargeToolchains, "new-sdk": "rust",
    })).toThrow("Missing native target");
    const configured = planChargeMatrix(newClients, serverImplementations, [basic], {
      ...chargeToolchains, "new-sdk": "typescript",
    });
    expect(configured.filter((shard) => shard.env.MPP_HARNESS_CLIENTS === "new-sdk"))
      .toHaveLength(servers.length);
  });

  it.each([
    { ...basic, clientIds: ["typo"] },
    { ...basic, serverIds: ["removed"] },
    { ...basic, clientIds: [] },
    { ...basic, serverIds: [] },
    { ...basic, kind: "cross-server-portability" as const, clientIds: ["typescript"], crossServerPairs: [["typescript", "missing"]] as Array<[string, string]> },
  ])("rejects unknown selectors and zero-case scenarios: %j", (scenario) => {
    expect(() => planChargeMatrix(undefined, undefined, [scenario])).toThrow();
  });

  it("rejects empty plans and duplicate IDs/pairs", () => {
    expect(() => planChargeMatrix(undefined, undefined, [])).toThrow("Empty charge matrix");
    expect(() => planChargeMatrix(undefined, undefined, [basic, basic])).toThrow("Duplicate");
    expect(() => planChargeMatrix([...clientImplementations, clients[0]])).toThrow("Duplicate");
    const portability = chargeScenarios.find((scenario) => scenario.kind === "cross-server-portability")!;
    expect(() => planChargeMatrix(undefined, undefined, [{
      ...portability, crossServerPairs: [portability.crossServerPairs![0], portability.crossServerPairs![0]],
    }])).toThrow("Duplicate charge cases");
  });

  it("runtime guard rejects zero, missing, extra, duplicate and malformed expectations", () => {
    const test: ChargeCase = { scenarioId: basic.id, clientId: "typescript", serverId: "typescript" };
    const expected = JSON.stringify([chargeCaseKey(test)]);
    expect(() => assertExpectedChargeCases([test], expected)).not.toThrow();
    expect(() => assertExpectedChargeCases([], expected)).toThrow("coverage mismatch");
    expect(() => assertExpectedChargeCases([test, { ...test, clientId: "rust" }], expected)).toThrow("coverage mismatch");
    expect(() => assertExpectedChargeCases([test, test], expected)).toThrow("Duplicate");
    for (const invalid of ["[]", "{}", "[1]", "invalid"]) {
      expect(() => assertExpectedChargeCases([], invalid)).toThrow();
    }
  });
});
