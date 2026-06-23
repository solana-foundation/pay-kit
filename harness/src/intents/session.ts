import type { HarnessScenario } from "../contracts";

export const sessionScenarios: readonly HarnessScenario[] = [
  {
    id: "session-basic",
    intent: "session",
    network: "localnet",
    price: "0.0007",
    amount: "700",
    asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    resourcePath: "/session",
    settlementHeader: "x-session-settlement-signature",
    expectedStatus: 200,
    clientIds: ["python-session"],
    serverIds: ["python"],
  },
] as const;
