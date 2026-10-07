import type { HarnessScenario } from "./contracts";
import {
  clientImplementations,
  serverImplementations,
  type ImplementationDefinition,
} from "./implementations";
import { chargeScenarios } from "./intents/charge";

/** A concrete charge test, independent of its human-readable Vitest name. */
export type ChargeCase = {
  scenarioId: string;
  clientId: string;
  serverId: string;
  targetServerId?: string;
};

/** Toolchain names implemented by .github/workflows/mpp-matrix.yml. */
export const supportedToolchains = [
  "typescript", "rust", "go", "swift", "kotlin", "python", "ruby", "lua", "php",
] as const;

/** Explicit adapter-to-toolchain mapping: new adapters must opt in here. */
export const chargeToolchains: Readonly<Record<string, string>> = {
  typescript: "typescript",
  rust: "rust",
  go: "go",
  swift: "swift",
  kotlin: "kotlin",
  python: "python",
  ruby: "ruby",
  lua: "lua",
  php: "php",
};

function supportsCharge(implementation: ImplementationDefinition): boolean {
  return (implementation.intents ?? ["charge"]).includes("charge");
}

function unique(values: readonly string[], description: string): void {
  if (new Set(values).size !== values.length) {
    throw new Error(`Duplicate ${description}`);
  }
}

/** Stable machine-readable identity, not a test-name regular expression. */
export function chargeCaseKey(test: ChargeCase): string {
  return JSON.stringify([
    test.scenarioId, test.clientId, test.serverId, test.targetServerId ?? null,
  ]);
}

/**
 * Enumerate eligible charge cases, ignoring local enabled defaults.
 * Cross-server scenarios deliberately use their declared driver allowlist.
 */
export function enumerateChargeCases(
  clients: readonly ImplementationDefinition[],
  servers: readonly ImplementationDefinition[],
  scenarios: readonly HarnessScenario[],
): ChargeCase[] {
  const chargeClients = clients.filter(supportsCharge);
  const chargeServers = servers.filter(supportsCharge);
  unique(chargeClients.map(({ id }) => id), "charge client IDs");
  unique(chargeServers.map(({ id }) => id), "charge server IDs");
  unique(scenarios.map(({ id }) => id), "scenario IDs");
  const cases: ChargeCase[] = [];
  for (const scenario of scenarios) {
    if (scenario.intent !== "charge") {
      throw new Error(`Non-charge scenario in charge plan: ${scenario.id}`);
    }
    for (const [ids, registry, role] of [
      [scenario.clientIds, chargeClients, "client"],
      [scenario.serverIds, chargeServers, "server"],
    ] as const) {
      if (ids) {
        unique(ids, `${scenario.id} ${role} allowlist`);
        for (const id of ids) {
          if (!registry.some((entry) => entry.id === id)) {
            throw new Error(`Unknown charge ${role} ${id} in ${scenario.id}`);
          }
        }
      }
    }
    const eligibleClients = chargeClients.filter(
      ({ id }) => !scenario.clientIds || scenario.clientIds.includes(id),
    );
    const eligibleServers = chargeServers.filter(
      ({ id }) => !scenario.serverIds || scenario.serverIds.includes(id),
    );
    const before = cases.length;
    if (scenario.kind === "cross-server-portability") {
      if (!scenario.clientIds?.length || !scenario.crossServerPairs?.length) {
        throw new Error(`Portability scenario needs explicit drivers and pairs: ${scenario.id}`);
      }
      for (const [source, target] of scenario.crossServerPairs) {
        if (source === target || ![source, target].every(
          (id) => eligibleServers.some((server) => server.id === id),
        )) {
          throw new Error(`Invalid portability pair ${source}->${target} in ${scenario.id}`);
        }
        for (const client of eligibleClients) {
          cases.push({
            scenarioId: scenario.id, clientId: client.id,
            serverId: source, targetServerId: target,
          });
        }
      }
    } else {
      if (scenario.kind && scenario.kind !== "standard" && scenario.kind !== "idempotent-resubmit") {
        throw new Error(`Unsupported charge scenario kind: ${scenario.kind}`);
      }
      for (const client of eligibleClients) {
        for (const server of eligibleServers) {
          cases.push({ scenarioId: scenario.id, clientId: client.id, serverId: server.id });
        }
      }
    }
    if (cases.length === before) {
      throw new Error(`Zero eligible cases for ${scenario.id}`);
    }
  }
  if (!cases.length) throw new Error("Empty charge matrix");
  unique(cases.map(chargeCaseKey), "charge cases");
  return cases;
}

/** One CI leg; selectors and the exact expected test set travel together. */
export type ChargeShard = {
  id: string;
  runner: "ubuntu-latest" | "macos-latest";
  toolchains: string[];
  cargoBins: string;
  scenarioIds: string[];
  caseCount: number;
  env: Record<string, string>;
};

/** Build every client/server pair plus explicit portability driver legs. */
export function planChargeMatrix(
  clients = clientImplementations,
  servers = serverImplementations,
  scenarios: readonly HarnessScenario[] = chargeScenarios,
  toolchains: Readonly<Record<string, string>> = chargeToolchains,
): ChargeShard[] {
  const implementations = [...clients, ...servers].filter(supportsCharge);
  const implementationIds = new Set(implementations.map(({ id }) => id));
  for (const [id, toolchain] of Object.entries(toolchains)) {
    if (!implementationIds.has(id)) throw new Error(`Stale toolchain adapter: ${id}`);
    if (!(supportedToolchains as readonly string[]).includes(toolchain)) {
      throw new Error(`Unknown toolchain ${toolchain} for ${id}`);
    }
  }
  for (const { id } of implementations) {
    if (!Object.hasOwn(toolchains, id)) throw new Error(`Missing toolchain for ${id}`);
  }
  const cases = enumerateChargeCases(clients, servers, scenarios);
  const groups = new Map<string, ChargeCase[]>();
  for (const test of cases) {
    // Keep all directed pairs together; splitting overlapping server selectors
    // could accidentally register reverse pairs in more than one shard.
    const id = test.targetServerId
      ? `portability-${test.scenarioId}-${test.clientId}`
      : `${test.clientId}-to-${test.serverId}`;
    const group = groups.get(id) ?? [];
    group.push(test);
    groups.set(id, group);
  }
  return [...groups].map(([id, tests]) => {
    const clientIds = [...new Set(tests.map((test) => test.clientId))];
    const serverIds = [...new Set(tests.flatMap(
      (test) => [test.serverId, ...(test.targetServerId ? [test.targetServerId] : [])],
    ))];
    const scenarioIds = [...new Set(tests.map((test) => test.scenarioId))];
    const required = [...new Set([...clientIds, ...serverIds].map((adapter) => toolchains[adapter]))];
    const bins = [
      ...(clientIds.includes("rust") ? ["mpp_harness_client"] : []),
      ...(serverIds.includes("rust") ? ["mpp_harness_server"] : []),
    ];
    return {
      id,
      runner: required.includes("swift") ? "macos-latest" : "ubuntu-latest",
      toolchains: required,
      cargoBins: bins.length ? `paykit-harness-bins:${bins.join(",")}` : "",
      scenarioIds,
      caseCount: tests.length,
      env: {
        // Dependencies were installed above; prevent pnpm 11 from injecting
        // install banners into the adapters' line-delimited JSON stdout.
        pnpm_config_verify_deps_before_run: "false",
        HARNESS_STRICT_SHARD: "1",
        MPP_HARNESS_INTENTS: "charge",
        MPP_HARNESS_CLIENTS: clientIds.join(","),
        MPP_HARNESS_SERVERS: serverIds.join(","),
        MPP_HARNESS_SCENARIOS: scenarioIds.join(","),
        MPP_HARNESS_EXPECTED_CASES: JSON.stringify(tests.map(chargeCaseKey).sort()),
      },
    };
  });
}

/** Fail closed when a CI leg registers fewer, extra, duplicate, or zero cases. */
export function assertExpectedChargeCases(
  actual: readonly ChargeCase[],
  expectedJson = process.env.MPP_HARNESS_EXPECTED_CASES,
): void {
  if (expectedJson === undefined) return;
  const expected: unknown = JSON.parse(expectedJson);
  if (!Array.isArray(expected) || !expected.length || !expected.every(
    (key): key is string => typeof key === "string",
  )) {
    throw new Error("MPP_HARNESS_EXPECTED_CASES must be a nonempty array of case keys");
  }
  unique(expected, "expected charge cases");
  const actualKeys = actual.map(chargeCaseKey).sort();
  unique(actualKeys, "registered charge cases");
  if (JSON.stringify(actualKeys) !== JSON.stringify([...expected].sort())) {
    throw new Error(`Charge CI coverage mismatch: expected ${JSON.stringify(expected)}, registered ${JSON.stringify(actualKeys)}`);
  }
}
