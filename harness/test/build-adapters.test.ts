import { afterEach, describe, expect, it, vi } from "vitest";
import { resolve } from "node:path";
import { buildAdapters, planAdapterBuilds } from "../build-adapters.js";
import { spawnSync } from "node:child_process";
import { cpSync } from "node:fs";

vi.mock("node:child_process", () => ({ spawnSync: vi.fn() }));
vi.mock("node:fs", async (importOriginal) => {
  const original = await importOriginal<typeof import("node:fs")>();
  return {
    ...original,
    mkdirSync: vi.fn(),
    cpSync: vi.fn(),
    readdirSync: vi.fn((path) => String(path) === "/swift/bin"
      ? ["fixture.bundle", "fixture.resources", "libfixture.dylib", "ignored.o"]
      : original.readdirSync(path)),
  };
});
afterEach(() => vi.resetAllMocks());

function successfulBuild() {
  vi.mocked(spawnSync).mockReturnValue({
    pid: 1, output: [], stdout: "/swift/bin\n", stderr: "", status: 0, signal: null,
  });
}

describe("adapter packaging", () => {
  it("groups all Rust bins in one cargo build and builds Go aliases once", () => {
    successfulBuild();
    buildAdapters(planAdapterBuilds({
      clients: ["rust", "rust-x402", "go", "go-x402"],
      servers: ["rust", "rust-x402", "go", "go-x402-upto"],
    }), "test-output");
    const calls = vi.mocked(spawnSync).mock.calls;
    expect(calls.map(([command]) => command)).toEqual(["cargo", "go", "go"]);
    expect(calls[0][1]).toEqual(expect.arrayContaining([
      "--bin", "mpp_harness_client", "x402_harness_client", "mpp_harness_server", "x402_harness_server",
    ]));
    expect(calls[0][1]).not.toContain("run");
    // The library workspace does not check in Cargo.lock.
    expect(calls[0][1]).not.toContain("--locked");
    expect(vi.mocked(cpSync)).toHaveBeenCalledTimes(4);
  });
  it("copies the complete Kotlin installed distribution", () => {
    successfulBuild();
    buildAdapters(planAdapterBuilds({ clients: ["kotlin"], servers: [] }), "test-output");
    expect(vi.mocked(spawnSync).mock.calls[0].slice(0, 2)).toEqual(["gradle", ["--no-daemon", "installDist"]]);
    expect(cpSync).toHaveBeenCalledWith(
      expect.stringContaining("kotlin-client/build/install/mpp-kotlin-harness-client"),
      resolve("test-output/kotlin-client-kotlin"), { recursive: true },
    );
  });
  it("packages adjacent Swift resources and shared libraries", () => {
    successfulBuild();
    buildAdapters(planAdapterBuilds({ clients: ["swift"], servers: [] }), "test-output");
    const calls = vi.mocked(spawnSync).mock.calls;
    expect(calls.map(([, args]) => args)).toEqual([
      ["build", "--configuration", "debug", "--product", "SwiftHarnessClient"],
      ["build", "--configuration", "debug", "--show-bin-path"],
    ]);
    expect(vi.mocked(cpSync).mock.calls.map(([source]) => source)).toEqual([
      "/swift/bin/SwiftHarnessClient",
      "/swift/bin/fixture.bundle",
      "/swift/bin/fixture.resources",
      "/swift/bin/libfixture.dylib",
    ]);
  });
  it("stops immediately on compiler failure without packaging stale output", () => {
    successfulBuild();
    vi.mocked(spawnSync).mockReturnValueOnce({
      pid: 1, output: [], stdout: "", stderr: "", status: 1, signal: null,
    });
    expect(() => buildAdapters(planAdapterBuilds({
      clients: ["rust", "go"], servers: [],
    }), "test-output")).toThrow("failed (1)");
    expect(spawnSync).toHaveBeenCalledTimes(1);
    expect(cpSync).not.toHaveBeenCalled();
  });
  it("packages conformance products once with their runtime resources", () => {
    successfulBuild();
    buildAdapters(planAdapterBuilds({
      clients: [], servers: [], conformance: ["swift", "kotlin", "go", "swift"],
    }), "test-output");
    const calls = vi.mocked(spawnSync).mock.calls;
    expect(calls.map(([command]) => command)).toEqual(["go", "gradle", "swift", "swift"]);
    expect(calls[0][2]?.cwd).toEqual(expect.stringContaining("/go/cmd/conformance"));
    expect(calls[1][2]?.cwd).toEqual(expect.stringContaining("/harness/kotlin-conformance"));
    expect(calls[2][1]).toEqual(["build", "--configuration", "release", "--product", "mpp-conformance"]);
    expect(calls[2][2]?.cwd).toMatch(/\/swift$/);
    expect(cpSync).toHaveBeenCalledWith(
      expect.stringContaining("kotlin-conformance/build/install/mpp-kotlin-conformance"),
      resolve("test-output/kotlin-conformance-kotlin"), { recursive: true },
    );
    expect(cpSync).toHaveBeenCalledWith("/swift/bin/mpp-conformance", resolve("test-output/swift-conformance-swift/mpp-conformance"));
    expect(cpSync).toHaveBeenCalledWith(
      "/swift/bin/fixture.bundle", resolve("test-output/swift-conformance-swift/fixture.bundle"),
      { recursive: true, dereference: true },
    );
  });
});
