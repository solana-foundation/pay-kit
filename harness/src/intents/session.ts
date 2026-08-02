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
    // Phase 1a: multi-client against the wire-only Python session server.
    // TS/Rust high-level session() servers always submit open on-chain, so
    // they stay deferred until a Surfpool/program job (Phase 1a-server).
    clientIds: ["python-session", "typescript-session"],
    serverIds: ["python"],
  },
] as const;
