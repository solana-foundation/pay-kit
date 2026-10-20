// Drives the vendored canonical mpp-tools FLOW suite (HTTP 402 end-to-end:
// challenge -> credential -> retry -> receipt, all flow cases use the
// "tempo" method) through pay-kit's TypeScript protocol layer.
//
// The vendored compliance server (harness/vectors/mpp-protocol-flows/
// compliance-server.ts) is spawned as a child process; the orchestration in
// src/protocol/flow-driver.ts — a port of the normative mpp-tools
// flow_runner.py — performs every HTTP exchange itself and routes only the
// protocol ops (challenge.parse / credential.format / receipt.parse)
// through the adapter. Each recorded result must deep-equal the canonical
// golden entry after the canonical normalization.
//
// Scope: the in-process TS reference adapter only, for now. The spawned
// per-language runners already implement the 9 vector ops the flows need,
// so they can join by claiming `flow` in their expectations file once a
// spawned flow adapter is wired here. Per-case expectations live in
// harness/expectations/typescript.toml.

import { spawn, type ChildProcess } from "node:child_process";
import { createServer } from "node:net";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  COMPLIANCE_SERVER_PATH,
  FLOW_CASES_PATH,
  flowDeepEqual,
  isUnsupportedFlow,
  loadGoldenFlowResults,
  normalizeFlowResult,
  runAllFlowCases,
  runnableFlowCases,
  type FlowResult,
} from "../src/protocol/flow-driver";
import { type CaseRef, danglingEntries, decide, loadAllExpectations } from "../src/expectations";
import { assertSuiteComplete, CaseRecorder, discoveryMode, observe } from "../src/expectations-run";
import { typescriptProtocolAdapter } from "../src/protocol/runners/typescript";

const here = dirname(fileURLToPath(import.meta.url));
const harnessRoot = join(here, "..");
const tsxBin = join(harnessRoot, "node_modules", ".bin", "tsx");

const flowCases = runnableFlowCases();
const golden = loadGoldenFlowResults();
const goldenByName = new Map(golden.map((entry) => [entry.name, entry]));
const EXPECTATIONS = loadAllExpectations();
const flowRefs: CaseRef[] = flowCases.map((c) => ({ suite: "flow", id: c.name, capability: "flow" }));

// Only the in-process TypeScript adapter can drive flows today. A language
// that claims `flow` without an adapter here is a configuration error.
const FLOW_ADAPTERS = { typescript: typescriptProtocolAdapter } as const;

async function getFreePort(): Promise<number> {
  return await new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const address = probe.address();
      if (address === null || typeof address === "string") {
        probe.close(() => reject(new Error("could not determine a free port")));
        return;
      }
      const { port } = address;
      probe.close(() => resolve(port));
    });
  });
}

// Mirrors flow_runner.py's wait_for_server: poll GET /free until it answers
// 200 or the deadline passes.
async function waitForServer(baseUrl: string, timeoutMs = 15_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/free`, { signal: AbortSignal.timeout(2000) });
      if (response.status === 200) return;
    } catch {
      // not up yet
    }
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  throw new Error("compliance server did not start");
}

// File-level, so a test-name filter cannot skip the completeness check.
afterAll(() => assertSuiteComplete("flow"));

describe("flow suite expectations", () => {
  it("only languages with a flow adapter claim flow", () => {
    const claiming = [...EXPECTATIONS.values()]
      .filter((e) => e.capabilities.flow.size > 0)
      .map((e) => e.language);
    expect(claiming.filter((l) => !(l in FLOW_ADAPTERS))).toEqual([]);
  });
});

describe("mpp-protocol flow conformance (canonical flows / TypeScript runner)", () => {
  const exp = EXPECTATIONS.get("typescript");
  if (!exp) throw new Error("no harness/expectations/typescript.toml");
  const recorder = new CaseRecorder("flow", "typescript").expect(flowRefs, exp);
  let server: ChildProcess | undefined;
  let serverStderr = "";
  const resultsByName = new Map<string, FlowResult>();

  const stopServer = () => {
    if (server && server.exitCode === null && !server.killed) {
      server.kill("SIGTERM");
    }
    server = undefined;
  };

  beforeAll(async () => {
    const port = await getFreePort();
    const baseUrl = `http://127.0.0.1:${port}`;
    server = spawn(tsxBin, [COMPLIANCE_SERVER_PATH], {
      cwd: harnessRoot,
      env: {
        ...process.env,
        MPP_FLOW_PORT: String(port),
        MPP_FLOW_CASES: FLOW_CASES_PATH,
      },
      stdio: ["ignore", "ignore", "pipe"],
    });
    server.stderr?.on("data", (chunk: Buffer) => (serverStderr += chunk.toString()));

    // try/finally semantics: if startup or the run itself fails, the server
    // must not outlive the suite (afterAll also fires, as a backstop).
    try {
      await waitForServer(baseUrl);
      // Run every flow case in declaration order against the stateful
      // server, exactly like the canonical runner does per adapter.
      for (const result of await runAllFlowCases(FLOW_ADAPTERS.typescript, baseUrl)) {
        resultsByName.set(result.name, result);
      }
    } catch (err) {
      stopServer();
      const stderrTail = serverStderr.slice(-1024);
      throw new Error(
        `flow run failed: ${err instanceof Error ? err.message : String(err)}` +
          (stderrTail ? `\ncompliance-server stderr tail:\n${stderrTail}` : ""),
      );
    }
  });

  afterAll(() => {
    stopServer();
    recorder.flush();
  });

  it("covers every canonical flow case exactly once", () => {
    const caseNames = flowCases.map((flowCase) => flowCase.name).sort();
    expect(caseNames).toEqual([...goldenByName.keys()].sort());
    expect([...resultsByName.keys()].sort()).toEqual([...goldenByName.keys()].sort());
  });

  it("expectations have no dangling entries", () => {
    expect(danglingEntries(exp, "flow", flowRefs)).toEqual([]);
  });

  for (const [index, flowCase] of flowCases.entries()) {
    const name = flowCase.name;
    const ref = flowRefs[index];
    const decision = discoveryMode() ? { kind: "pass" as const } : decide(exp, ref);
    if (decision.kind === "unclaimed") {
      recorder.record(ref, decision, undefined);
      continue;
    }
    it(`${name} [${decision.kind}]`, async () => {
      const observed = await observe(async () => {
        const expected = goldenByName.get(name);
        const actual = resultsByName.get(name);
        expect(expected, `no golden entry for ${name}`).toBeDefined();
        expect(actual, `no recorded result for ${name}`).toBeDefined();
        if (isUnsupportedFlow(actual!)) {
          return { unsupported: `requires ${String(actual!.unsupported_capability)}` };
        }
        const normalizedExpected = normalizeFlowResult(expected!);
        const normalizedActual = normalizeFlowResult(actual!);
        expect(
          flowDeepEqual(normalizedExpected, normalizedActual),
          `flow result mismatch for ${name}\n` +
            `golden: ${JSON.stringify(normalizedExpected, null, 2)}\n` +
            `actual: ${JSON.stringify(normalizedActual, null, 2)}`,
        ).toBe(true);
        return "pass";
      });
      recorder.verdict(exp, ref, decision, observed);
    });
  }
});
