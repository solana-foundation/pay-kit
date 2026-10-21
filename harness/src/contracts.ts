// The process adapter contract (README "Process adapter contract") as seen
// by the TypeScript adapters in src/fixtures/typescript. The scenarios that
// drive every adapter, and the driver itself, live in Rust:
// rust/crates/conformance/src/interop/ (`pkc run --tier interop`), which
// sets every MPP_HARNESS_* / X402_HARNESS_* variable per case.

export type AdapterKind = "client" | "server";

/** `ready` (server) message on stdout. */
export type ReadyMessage = {
  type: "ready";
  implementation: string;
  role: AdapterKind;
  port?: number;
  capabilities?: string[];
};

/** `result` (client) message on stdout. */
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

/**
 * Fallbacks for an adapter started by hand without the harness environment:
 * the `charge-basic` scenario's values. `pkc` always sets the variables.
 */
export const harnessScenario = {
  network: "localnet",
  asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
  amount: "1000",
  price: "0.001",
  resourcePath: "/protected",
  settlementHeader: "x-fixture-settlement",
} as const;
