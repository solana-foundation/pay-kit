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
  // MPP session multi-delivery (cumulative watermark): N reserve/commit
  // increments then a single close. Clients read MPP_HARNESS_DELIVERY_COUNT
  // (default 1) and MPP_HARNESS_AMOUNT per increment. e2e sets count=3 for
  // this scenario (3 × 700 = 2100 cumulative).
  //
  // PR-1 ships python-session only (the sole session harness client today).
  // Expand clientIds to typescript-session / rust-session when those
  // adapters land and implement the same DELIVERY_COUNT loop.
  {
    id: "session-multi-delivery",
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
