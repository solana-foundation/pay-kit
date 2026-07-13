import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  harnessCapabilityProtocols,
  harnessCapabilityRegistry,
  isHarnessCapabilityProtocol,
  protocolsForImplementation,
  type HarnessCapabilityProtocol,
  type HarnessCapabilityRole,
  type HarnessRoleCapability,
} from "../src/capabilities";
import {
  harnessScenarios,
  selectHarnessScenarios,
  supportedHarnessIntents,
  type HarnessScenario,
} from "../src/contracts";
import { discoverRunners } from "../src/conformance/runners";
import type { VectorMode } from "../src/conformance/schema";
import {
  clientImplementations,
  serverImplementations,
  type ImplementationDefinition,
} from "../src/implementations";

type VectorSummary = {
  id: string;
  intent: string;
  mode: VectorMode;
};

type RoleDeclaration = {
  language: string;
  protocol: HarnessCapabilityProtocol;
  role: HarnessCapabilityRole;
  details: HarnessRoleCapability;
};

const here = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(here, "..", "vectors");
const vectorModes = new Set<VectorMode>([
  "build-transaction",
  "verify-transaction",
  "canonical-bytes",
  "verify-x402-transaction",
]);

function isVectorMode(value: string): value is VectorMode {
  return vectorModes.has(value as VectorMode);
}

function loadVectorSummaries(): VectorSummary[] {
  return readdirSync(vectorsDir)
    .filter((name) => name.endsWith(".json"))
    .flatMap((name) => {
      const parsed = JSON.parse(readFileSync(join(vectorsDir, name), "utf8"));
      if (!Array.isArray(parsed)) {
        throw new Error(`vector file ${name} must contain an array`);
      }
      return parsed.map((vector) => {
        const record = vector as Partial<VectorSummary>;
        if (typeof record.id !== "string" || typeof record.intent !== "string") {
          throw new Error(`vector file ${name} contains a malformed vector`);
        }
        if (typeof record.mode !== "string" || !isVectorMode(record.mode)) {
          throw new Error(`vector ${record.id} in ${name} has unknown mode`);
        }
        return {
          id: record.id,
          intent: record.intent,
          mode: record.mode,
        } satisfies VectorSummary;
      });
    });
}

function roleDeclarations(role?: HarnessCapabilityRole): RoleDeclaration[] {
  return harnessCapabilityRegistry.flatMap((capability) =>
    Object.entries(capability.roles).flatMap(([rawRole, details]) => {
      const declaredRole = rawRole as HarnessCapabilityRole;
      if (!details || (role && declaredRole !== role)) return [];
      return [
        {
          language: capability.language,
          protocol: capability.protocol,
          role: declaredRole,
          details,
        },
      ];
    }),
  );
}

function implementationSupportsProtocol(
  implementation: ImplementationDefinition,
  protocol: HarnessCapabilityProtocol,
): boolean {
  return protocolsForImplementation(implementation).includes(protocol);
}

function scenarioAllowsImplementation(
  scenario: HarnessScenario,
  role: "client" | "server",
  implementationId: string,
): boolean {
  const ids = role === "client" ? scenario.clientIds : scenario.serverIds;
  return ids === undefined || ids.includes(implementationId);
}

function hasScenarioCoverage(
  scenarios: readonly HarnessScenario[],
  protocol: HarnessCapabilityProtocol,
  role: "client" | "server",
  implementationId: string,
  settlementOnly = false,
): boolean {
  return scenarios.some((scenario) => {
    if (scenario.intent !== protocol) return false;
    if (settlementOnly && scenario.expectedStatus !== 200) return false;
    return scenarioAllowsImplementation(scenario, role, implementationId);
  });
}

function hasRegistryImplementation(
  role: "client" | "server" | "settlement",
  protocol: HarnessCapabilityProtocol,
  implementationId: string,
): boolean {
  return roleDeclarations(role).some(
    (declaration) =>
      declaration.protocol === protocol &&
      (declaration.details.implementationIds ?? []).includes(implementationId),
  );
}

function implementationRoleMatrix(
  implementations: readonly ImplementationDefinition[],
  role: "client" | "server",
): Array<{
  implementation: ImplementationDefinition;
  protocol: HarnessCapabilityProtocol;
}> {
  return implementations.flatMap((implementation) =>
    protocolsForImplementation(implementation).map((protocol) => ({
      implementation,
      protocol,
    })),
  );
}

describe("harness capability registry", () => {
  const clientById = new Map(clientImplementations.map((impl) => [impl.id, impl]));
  const serverById = new Map(serverImplementations.map((impl) => [impl.id, impl]));
  const defaultScenarios = selectHarnessScenarios(undefined, undefined);
  const runnersByLanguage = new Map(
    discoverRunners().map((runner) => [runner.language, runner]),
  );
  const vectors = loadVectorSummaries();

  it("lists the same protocol set that harnessScenarios exposes", () => {
    expect([...supportedHarnessIntents].sort()).toEqual(
      [...harnessCapabilityProtocols].sort(),
    );
  });

  it("has one language/protocol entry per registry row", () => {
    const keys = harnessCapabilityRegistry.map(
      (capability) => `${capability.language}:${capability.protocol}`,
    );
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("records every declared client and server implementation intent", () => {
    for (const { implementation, protocol } of implementationRoleMatrix(
      clientImplementations,
      "client",
    )) {
      expect(
        hasRegistryImplementation("client", protocol, implementation.id),
        `missing client capability for ${implementation.id}/${protocol}`,
      ).toBe(true);
    }

    for (const { implementation, protocol } of implementationRoleMatrix(
      serverImplementations,
      "server",
    )) {
      expect(
        hasRegistryImplementation("server", protocol, implementation.id),
        `missing server capability for ${implementation.id}/${protocol}`,
      ).toBe(true);
    }
  });

  it("backs process-adapter roles with implementations and scenarios", () => {
    for (const declaration of roleDeclarations()) {
      if (declaration.role === "verifier") continue;

      const ids = declaration.details.implementationIds ?? [];
      expect(
        ids.length,
        `${declaration.language}/${declaration.protocol}/${declaration.role} has no implementationIds`,
      ).toBeGreaterThan(0);

      const role =
        declaration.role === "client" ? "client" : "server";
      const implementations = role === "client" ? clientById : serverById;
      const settlementOnly = declaration.role === "settlement";

      for (const id of ids) {
        const implementation = implementations.get(id);
        expect(
          implementation,
          `${declaration.language}/${declaration.protocol}/${declaration.role} references unknown implementation ${id}`,
        ).toBeDefined();
        if (!implementation) continue;

        expect(
          implementationSupportsProtocol(implementation, declaration.protocol),
          `${id} does not declare intent ${declaration.protocol}`,
        ).toBe(true);

        if (settlementOnly) {
          expect(
            hasRegistryImplementation("server", declaration.protocol, id),
            `${id}/${declaration.protocol} declares settlement without server support`,
          ).toBe(true);
        }

        expect(
          hasScenarioCoverage(
            harnessScenarios,
            declaration.protocol,
            role,
            id,
            settlementOnly,
          ),
          `${id}/${declaration.protocol}/${declaration.role} has no matching harnessScenarios coverage`,
        ).toBe(true);

        if (declaration.details.requiredByDefault) {
          expect(
            hasScenarioCoverage(
              defaultScenarios,
              declaration.protocol,
              role,
              id,
              settlementOnly,
            ),
            `${id}/${declaration.protocol}/${declaration.role} is required by the default intent set but is not represented by DEFAULT_INTENTS scenarios`,
          ).toBe(true);
        }
      }
    }
  });

  it("backs verifier roles with runner manifests and vector modes", () => {
    for (const declaration of roleDeclarations("verifier")) {
      const runnerLanguages = declaration.details.runnerLanguages ?? [];
      const vectorModes = declaration.details.vectorModes ?? [];
      expect(
        runnerLanguages.length,
        `${declaration.language}/${declaration.protocol}/verifier has no runnerLanguages`,
      ).toBeGreaterThan(0);
      expect(
        vectorModes.length,
        `${declaration.language}/${declaration.protocol}/verifier has no vectorModes`,
      ).toBeGreaterThan(0);

      for (const language of runnerLanguages) {
        const runner = runnersByLanguage.get(language);
        expect(
          runner,
          `${declaration.language}/${declaration.protocol}/verifier references unknown runner ${language}`,
        ).toBeDefined();
        if (!runner) continue;
        expect(
          protocolsForImplementation(runner).includes(declaration.protocol),
          `${language} runner does not declare intent ${declaration.protocol}`,
        ).toBe(true);
      }

      for (const mode of vectorModes) {
        expect(
          vectors.some(
            (vector) =>
              vector.intent === declaration.protocol && vector.mode === mode,
          ),
          `${declaration.protocol}/verifier declares ${mode} but no vector uses it`,
        ).toBe(true);
      }
    }
  });

  it("does not declare unknown protocols in scenarios or vectors", () => {
    for (const scenario of harnessScenarios) {
      expect(isHarnessCapabilityProtocol(scenario.intent)).toBe(true);
    }

    for (const vector of vectors) {
      expect(
        isHarnessCapabilityProtocol(vector.intent),
        `${vector.id} uses unknown intent ${vector.intent}`,
      ).toBe(true);
    }
  });
});
