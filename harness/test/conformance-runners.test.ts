import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { getNativeTarget } from "../src/artifacts.js";
import { discoverRunners } from "../src/conformance/runners.js";

const directories: string[] = [];
afterEach(() => {
  vi.unstubAllEnvs();
  for (const directory of directories.splice(0)) rmSync(directory, { recursive: true, force: true });
});

function artifactDirectory() {
  const directory = mkdtempSync(join(tmpdir(), "conformance-artifacts-"));
  directories.push(directory);
  vi.stubEnv("HARNESS_PREBUILT_DIR", directory);
  return directory;
}

describe("conformance runner commands", () => {
  it("preserves manifest developer commands without prebuilt mode", () => {
    vi.stubEnv("HARNESS_PREBUILT_DIR", "");
    const runners = discoverRunners();
    expect(runners.find(({ language }) => language === "swift")?.command)
      .toEqual(["swift", "run", "-c", "release", "mpp-conformance"]);
    expect(runners.find(({ language }) => language === "kotlin")?.command)
      .toEqual(["sh", "-c", "exec build/install/mpp-kotlin-conformance/bin/mpp-kotlin-conformance"]);
  });

  it.each(["swift", "kotlin", "go"])("resolves only selected %s artifacts and keeps capabilities", (language) => {
    const root = artifactDirectory();
    const target = getNativeTarget("conformance", language)!;
    const executable = join(root, target.executable);
    mkdirSync(dirname(executable), { recursive: true });
    writeFileSync(executable, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    const runner = discoverRunners().find((runner) => runner.language === language)!;
    expect(runner.command).toEqual([executable]);
    expect(runner.intents).toContain("session");
    expect(runner.cwd).toMatch(language === "kotlin" ? /\/harness\/kotlin-conformance$/ : new RegExp(`/${language}$`));
    chmodSync(executable, 0o644);
    expect(() => runner.command).toThrow("non-executable");
  });

  it("fails closed on selected missing binaries without requiring excluded platforms", () => {
    artifactDirectory();
    const runners = discoverRunners();
    expect(runners.find(({ language }) => language === "typescript")?.command[0]).toBe("pnpm");
    for (const language of ["swift", "kotlin", "go"]) {
      expect(() => runners.find((runner) => runner.language === language)!.command)
        .toThrow("forbids compiler fallback");
    }
  });
});
