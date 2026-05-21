import { chargeScenarios } from "./intents/charge";

export type AdapterKind = "client" | "server";

export type InteropIntent = "charge";

export type InteropScenarioSplit = {
  recipientKey: string;
  amount: string;
  ataCreationRequired?: boolean;
  memo?: string;
};

export type InteropScenario = {
  id: string;
  intent: InteropIntent;
  network: string;
  price: string;
  amount: string;
  asset: string;
  resourcePath: string;
  settlementHeader: string;
  splits?: InteropScenarioSplit[];
  replaySource?: {
    resourcePath: string;
    price: string;
    amount: string;
  };
  expectedStatus: 200 | 402;
  clientIds?: string[];
  serverIds?: string[];
};

export type ReadyMessage = {
  type: "ready";
  implementation: string;
  role: AdapterKind;
  port?: number;
  capabilities?: string[];
};

export type ClientRunResult = {
  type: "result";
  implementation: string;
  role: "client";
  ok: boolean;
  status: number;
  responseHeaders: Record<string, string>;
  responseBody: unknown;
  settlement?: unknown;
};

export type AdapterMessage = ReadyMessage | ClientRunResult;

export { chargeCanonicalJsonVectors } from "./intents/charge";

export const interopScenarios: readonly InteropScenario[] =
  chargeScenarios;

export const interopScenario: InteropScenario = {
  ...(interopScenarios[0] as InteropScenario),
};

export const supportedInteropIntents: readonly InteropIntent[] = Array.from(
  new Set(interopScenarios.map((scenario) => scenario.intent)),
);

export function selectInteropScenarios(
  rawIntentSelection: string | undefined,
  rawScenarioSelection: string | undefined,
): InteropScenario[] {
  const selectedIntents = selectInteropIntents(rawIntentSelection);
  const selectedScenarioIds = selectScenarioIds(rawScenarioSelection);
  const selectedScenarios = interopScenarios.filter(
    (scenario) =>
      selectedIntents.includes(scenario.intent) &&
      selectedScenarioIds.includes(scenario.id),
  );

  if (selectedScenarios.length === 0) {
    throw new Error(
      `No interop scenarios matched MPP_INTEROP_INTENTS=${rawIntentSelection ?? "<default>"} ` +
        `and MPP_INTEROP_SCENARIOS=${rawScenarioSelection ?? "<default>"}.`,
    );
  }

  return [...selectedScenarios];
}

function selectScenarioIds(rawSelection: string | undefined): string[] {
  const supported = interopScenarios.map((scenario) => scenario.id);
  if (!rawSelection || rawSelection.trim() === "") {
    return supported;
  }

  const selected = rawSelection
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const unsupported = selected.filter((value) => !supported.includes(value));

  if (unsupported.length > 0) {
    throw new Error(
      `Unsupported MPP_INTEROP_SCENARIOS value(s): ${unsupported.join(", ")}. ` +
        `Supported scenarios: ${supported.join(", ")}.`,
    );
  }

  return selected;
}

export function selectInteropIntents(
  rawSelection: string | undefined,
): InteropIntent[] {
  if (!rawSelection || rawSelection.trim() === "") {
    return [...supportedInteropIntents];
  }

  const selected = rawSelection
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const unsupported = selected.filter(
    (value) => !supportedInteropIntents.includes(value as never),
  );

  if (unsupported.length > 0) {
    throw new Error(
      `Unsupported MPP_INTEROP_INTENTS value(s): ${unsupported.join(", ")}. ` +
        `Supported intents: ${supportedInteropIntents.join(", ")}. ` +
        "Session and subscription scenarios are not implemented in this harness yet.",
    );
  }

  return selected as InteropIntent[];
}
