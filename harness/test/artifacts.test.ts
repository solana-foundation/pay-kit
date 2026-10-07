import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getNativeTarget, nativeTargets, resolveAdapterCommand } from "../src/artifacts.js";
import { clientImplementations, serverImplementations } from "../src/implementations.js";
import { parseBuildArguments, planAdapterBuilds } from "../build-adapters.js";

const directories: string[] = [];
afterEach(() => {
  vi.unstubAllEnvs();
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});
function temporaryDirectory() {
  const directory = mkdtempSync(join(tmpdir(), "harness-artifacts-"));
  directories.push(directory);
  return directory;
}

describe("adapter build selection", () => {
  it("parses separate roles, trims and deduplicates selectors", () => {
    expect(parseBuildArguments(["--clients", " rust,go,rust, ", "--servers", "rust", "--out", "build dir"])).toEqual({
      clients: ["rust", "go"], servers: ["rust"], conformance: [], out: "build dir",
    });
    expect(() => parseBuildArguments([])).toThrow("--out");
    expect(() => parseBuildArguments(["--out", "build", "--wat"])).toThrow();
  });
  it("deduplicates Go aliases and ignores interpreted adapters", () => {
    const plan = planAdapterBuilds({
      clients: ["go", "go-x402", "go-x402-upto", "rust", "rust", "typescript"],
      servers: ["go", "go-x402-upto", "rust", "php"],
    });
    expect(plan.map(({ key }) => key)).toEqual(["go-client-go", "go-server-go", "rust-client-rust", "rust-server-rust"]);
    expect(planAdapterBuilds({ clients: [], servers: [] })).toEqual([]);
  });
  it("rejects unknown and wrong-role adapters", () => {
    expect(() => planAdapterBuilds({ clients: ["bad"], servers: [] })).toThrow('Unknown client adapter "bad"');
    expect(() => planAdapterBuilds({ clients: [], servers: ["swift"] })).toThrow('Unknown server adapter "swift"');
  });
  it("validates and deduplicates declared conformance runners", () => {
    const selection = parseBuildArguments(["--conformance", " swift,kotlin,swift,go,typescript ", "--out", "out"]);
    expect(selection.conformance).toEqual(["swift", "kotlin", "go", "typescript"]);
    expect(planAdapterBuilds(selection).map(({ key }) => key)).toEqual([
      "go-conformance-go", "kotlin-conformance-kotlin", "swift-conformance-swift",
    ]);
    expect(() => planAdapterBuilds({ clients: [], servers: [], conformance: ["rust"] }))
      .toThrow('Unknown conformance adapter "rust"');
  });
  it("covers every compiled implementation without importing SDKs", () => {
    for (const implementation of [...clientImplementations, ...serverImplementations]) {
      const compiled = /^(rust|go|swift|kotlin)(-|$)/.test(implementation.id);
      expect(Boolean(getNativeTarget(implementation.role, implementation.id))).toBe(compiled);
    }
    expect(new Set(nativeTargets.map(({ key }) => key)).size).toBe(nativeTargets.length);
  });
});

describe("prebuilt runtime", () => {
  it("keeps local and interpreted commands unchanged", () => {
    const command = ["go", "run", "."];
    expect(resolveAdapterCommand("client", "go", command, "")).toBe(command);
    expect(resolveAdapterCommand("server", "php", ["php", "server.php"], "/missing")).toEqual(["php", "server.php"]);
  });
  it("uses direct absolute artifact commands for every native target", () => {
    const root = temporaryDirectory();
    for (const target of nativeTargets) {
      const executable = resolve(root, target.executable);
      mkdirSync(dirname(executable), { recursive: true });
      writeFileSync(executable, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
      for (const id of target.ids) {
        expect(resolveAdapterCommand(target.role, id, ["compiler"], root)).toEqual([executable]);
      }
    }
  });
  it("fails closed for missing and non-executable artifacts", () => {
    const root = temporaryDirectory();
    expect(() => resolveAdapterCommand("client", "rust", ["cargo", "run"], root)).toThrow("forbids compiler fallback");
    const target = getNativeTarget("client", "go")!;
    const executable = resolve(root, target.executable);
    mkdirSync(dirname(executable), { recursive: true });
    writeFileSync(executable, "");
    chmodSync(executable, 0o644);
    expect(() => resolveAdapterCommand("client", "go", ["go", "run", "."], root)).toThrow("non-executable");
  });
  it("never treats missing native metadata as an interpreted target", () => {
    for (const role of ["client", "server", "conformance"] as const) {
      expect(() => resolveAdapterCommand(role, "new-compiled-sdk", ["compiler", "run"], "/missing"))
        .toThrow("Unclassified");
    }
  });
  it("resolves registry commands lazily so unused targets can be absent", () => {
    vi.stubEnv("HARNESS_PREBUILT_DIR", temporaryDirectory());
    expect(clientImplementations.map(({ id }) => id)).toContain("rust");
    expect(() => clientImplementations.find(({ id }) => id === "rust")!.command).toThrow("prebuilt client");
    expect(serverImplementations.find(({ id }) => id === "php")!.command[0]).toBe("php");
  });
});
