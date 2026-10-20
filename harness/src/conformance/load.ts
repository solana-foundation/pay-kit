// Load and validate every conformance vector under harness/vectors/*.json.
// Shared by the vector driver and the coverage-table generator.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { assertConformanceVector } from "./contract-schema";
import type { ConformanceVector } from "./schema";

const here = dirname(fileURLToPath(import.meta.url));
const vectorsDir = join(here, "..", "..", "vectors");

export function loadVectors(): ConformanceVector[] {
  const files = readdirSync(vectorsDir)
    .filter((name) => name.endsWith(".json"))
    .sort();
  const vectors: ConformanceVector[] = [];
  for (const file of files) {
    const parsed = JSON.parse(
      readFileSync(join(vectorsDir, file), "utf8"),
    ) as ConformanceVector[];
    for (const vector of parsed) {
      // Validate the vector against the ABI at load so an authoring mistake
      // (wrong mode, missing expect.outcome, stray envelope key) fails here
      // with a clear message instead of deep inside a runner.
      assertConformanceVector(vector, `${file}:${vector?.id ?? "(no id)"}`);
      vectors.push(vector);
    }
  }
  return vectors;
}
