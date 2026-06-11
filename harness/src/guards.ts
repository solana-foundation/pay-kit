// P0 false-green killers shared by the harness e2e suites.
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
  "Loopback socket bind failed under CI. The harness matrix cannot run, so " +
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

// The verdict for a scenario's eligibility once the shard (currently-enabled
// adapter subset) is taken into account.
//
//   - "run"  : the scenario has eligible clients/servers/pairs in this shard.
//   - "skip" : the scenario is eligible against the FULL adapter registry but
//              this shard's enabled subset excludes its adapters. That is a
//              legitimate shard skip, not a false green.
//
// A scenario that resolves to zero eligibility against the FULL registry is a
// genuine misconfiguration (false green) and still throws.
export type EligibilityVerdict =
  | { verdict: "run" }
  | { verdict: "skip"; reason: string };

// Decide whether a scenario should run, be skipped (shard exclusion), or hard
// fail (globally empty) in a sharded harness matrix.
//
// `shard` holds the counts computed against the currently-enabled adapter
// subset; `full` holds the same counts computed against the entire adapter
// registry (ignoring the `enabled` flag). The full counts are what decides
// between a legitimate shard skip and a false green:
//
//   - full set empty on any dimension  -> throw (genuine misconfiguration).
//   - full set non-empty but shard set empty on any dimension -> skip.
//   - both non-empty -> run.
export function evaluateShardEligibility(params: {
  scenarioId: string;
  shard: { clientCount: number; serverCount: number; pairCount?: number };
  full: { clientCount: number; serverCount: number; pairCount?: number };
}): EligibilityVerdict {
  const { scenarioId, shard, full } = params;

  // First: a scenario that is empty across the FULL adapter registry is a
  // real false green regardless of the shard. Surface it loudly.
  assertNonEmptyEligibility({
    scenarioId,
    clientCount: full.clientCount,
    serverCount: full.serverCount,
    pairCount: full.pairCount,
  });

  // The full set covers this scenario, so any shard emptiness is purely a
  // consequence of the enabled-adapter subset: a legitimate shard skip.
  if (shard.clientCount === 0) {
    return {
      verdict: "skip",
      reason:
        `Scenario ${scenarioId} has no eligible client in the enabled adapter ` +
        `subset (shard), but the full adapter registry does. Skipping in this shard.`,
    };
  }
  if (shard.serverCount === 0) {
    return {
      verdict: "skip",
      reason:
        `Scenario ${scenarioId} has no eligible server in the enabled adapter ` +
        `subset (shard), but the full adapter registry does. Skipping in this shard.`,
    };
  }
  if (shard.pairCount !== undefined && shard.pairCount === 0) {
    return {
      verdict: "skip",
      reason:
        `Scenario ${scenarioId} has no client/server pair in the enabled adapter ` +
        `subset (shard), but the full adapter registry does. Skipping in this shard.`,
    };
  }

  return { verdict: "run" };
}
