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

describe("conformance runner packaging", () => {
  it("stops immediately on compiler failure without packaging stale output", () => {
    successfulBuild();
    vi.mocked(spawnSync).mockReturnValueOnce({
      pid: 1, output: [], stdout: "", stderr: "", status: 1, signal: null,
    });
    expect(() => buildAdapters(planAdapterBuilds({ conformance: ["go", "kotlin"] }), "test-output"))
      .toThrow("failed (1)");
    expect(spawnSync).toHaveBeenCalledTimes(1);
    expect(cpSync).not.toHaveBeenCalled();
  });
  it("packages conformance products once with their runtime resources", () => {
    successfulBuild();
    buildAdapters(planAdapterBuilds({ conformance: ["swift", "kotlin", "go", "swift"] }), "test-output");
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
