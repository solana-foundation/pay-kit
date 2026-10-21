// `x402-upto` vectors for the TypeScript testee. The testee passes the
// vector's input to the SDK unchanged (harness/AGENTS.md).
import type { ConformanceVector, RunnerResult } from "../schema";

export async function run(vector: ConformanceVector): Promise<RunnerResult> {
  return {
    error: `unsupported-mode: no TypeScript path for x402-upto ${vector.mode}`,
    id: vector.id,
    outcome: "unsupported-mode",
  };
}
