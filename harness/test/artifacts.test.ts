import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getNativeTarget, nativeTargets, resolveAdapterCommand } from "../src/artifacts.js";
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

describe("conformance runner build selection", () => {
  it("parses, trims and deduplicates selectors", () => {
    expect(parseBuildArguments(["--conformance", " swift,go,swift, ", "--out", "build dir"])).toEqual({
      conformance: ["swift", "go"], out: "build dir",
    });
    expect(() => parseBuildArguments([])).toThrow("--out");
    expect(() => parseBuildArguments(["--out", "build", "--wat"])).toThrow();
  });
  it("leaves payment adapters to pkc", () => {
    expect(() => parseBuildArguments(["--clients", "rust", "--out", "x"])).toThrow("pkc adapters build");
    expect(() => parseBuildArguments(["--servers", "go", "--out", "x"])).toThrow("pkc adapters build");
  });
  it("validates and deduplicates declared conformance runners", () => {
    const selection = parseBuildArguments(["--conformance", " swift,kotlin,swift,go,typescript ", "--out", "out"]);
    expect(selection.conformance).toEqual(["swift", "kotlin", "go", "typescript"]);
    expect(planAdapterBuilds(selection).map(({ key }) => key)).toEqual([
      "go-conformance-go", "kotlin-conformance-kotlin", "swift-conformance-swift",
    ]);
    expect(() => planAdapterBuilds({ conformance: ["cobol"] })).toThrow('Unknown conformance adapter "cobol"');
    expect(new Set(nativeTargets.map(({ key }) => key)).size).toBe(nativeTargets.length);
  });
});

describe("prebuilt runtime", () => {
  it("keeps local and interpreted commands unchanged", () => {
    const command = ["go", "run", "."];
    expect(resolveAdapterCommand("conformance", "go", command, "")).toBe(command);
    expect(resolveAdapterCommand("conformance", "php", ["php", "runner.php"], "/missing")).toEqual(["php", "runner.php"]);
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
    expect(() => resolveAdapterCommand("conformance", "swift", ["swift", "run"], root)).toThrow("forbids compiler fallback");
    const target = getNativeTarget("conformance", "go")!;
    const executable = resolve(root, target.executable);
    mkdirSync(dirname(executable), { recursive: true });
    writeFileSync(executable, "");
    chmodSync(executable, 0o644);
    expect(() => resolveAdapterCommand("conformance", "go", ["go", "run", "."], root)).toThrow("non-executable");
  });
  it("never treats missing native metadata as an interpreted target", () => {
    expect(() => resolveAdapterCommand("conformance", "new-compiled-sdk", ["compiler", "run"], "/missing"))
      .toThrow("Unclassified");
  });
});
