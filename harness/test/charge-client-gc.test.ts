import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { expect, it } from "vitest";

const execFileAsync = promisify(execFile);

it("keeps MPP challenge responses usable across garbage collection", async () => {
  // A subprocess enables GC without changing Vitest's workers or global fetch.
  // This fails deterministically on the old CI runtime (Node 22.13.0).
  const result = await execFileAsync(
    process.execPath,
    [
      "--expose-gc",
      "--import",
      "tsx",
      fileURLToPath(new URL("./fixtures/charge-client-gc.ts", import.meta.url)),
    ],
    { timeout: 15_000 },
  );
  expect(result.stderr).toBe("");
}, 20_000);
