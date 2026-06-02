// P0 false-green killers shared by the interop e2e suites.
//
// A green test run must mean the matrix actually asserted something. Two
// failure modes silently subvert that:
//
//   1. A sandbox that cannot bind a loopback socket turns every matrix
//      test into `it.skip`, so the whole suite reports green with zero
//      assertions executed.
//   2. Scenario / adapter filters can intersect to zero eligible clients,
//      servers, or client/server pairs, leaving a scenario in the active
//      set that drives no test at all.
//
// These guards convert both into loud failures. The socket guard only
// hard-fails under CI (`process.env.CI`) so a developer on a restricted
// local box still gets a skip rather than a red bar.

export function isCi(): boolean {
  const value = process.env.CI;
  return typeof value === "string" && value.trim() !== "" && value !== "0" && value !== "false";
}

// Decide how a socket-dependent test should be registered. Returns
// `"run"` when loopback bind works, `"skip"` when it does not and we are
// not in CI, and `"fail"` when it does not and we ARE in CI (a sandbox
// that cannot bind loopback must not green-skip the entire matrix).
export type SocketGateMode = "run" | "skip" | "fail";

export function socketGateMode(socketSupport: boolean): SocketGateMode {
  if (socketSupport) {
    return "run";
  }
  return isCi() ? "fail" : "skip";
}

export const SOCKET_UNAVAILABLE_CI_MESSAGE =
  "Loopback socket bind failed under CI. The interop matrix cannot run, so " +
  "this is a hard failure (not a skip): a sandbox that cannot bind loopback " +
  "must not let the whole matrix report green with zero assertions. Set CI=0 " +
  "to opt into the local skip behaviour.";

// Throw if a scenario selection produced no eligible clients, servers, or
// client/server pairs. `pairCount` is optional for runners (e.g. the
// idempotent / cross-server blocks) that compute pairs differently.
export function assertNonEmptyEligibility(params: {
  scenarioId: string;
  clientCount: number;
  serverCount: number;
  pairCount?: number;
}): void {
  const { scenarioId, clientCount, serverCount, pairCount } = params;
  if (clientCount === 0) {
    throw new Error(
      `Scenario ${scenarioId} selected zero eligible clients. ` +
        `A selected scenario with no client to drive it is a false green: fix the ` +
        `scenario clientIds / enabled adapters or remove the scenario.`,
    );
  }
  if (serverCount === 0) {
    throw new Error(
      `Scenario ${scenarioId} selected zero eligible servers. ` +
        `A selected scenario with no server to pay is a false green: fix the ` +
        `scenario serverIds / enabled adapters or remove the scenario.`,
    );
  }
  if (pairCount !== undefined && pairCount === 0) {
    throw new Error(
      `Scenario ${scenarioId} produced zero client/server pairs. ` +
        `A selected scenario that runs no pair asserts nothing: fix the ` +
        `scenario pairing or remove the scenario.`,
    );
  }
}
