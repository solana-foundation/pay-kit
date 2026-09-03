// Generator: cyberphone/json-canonicalization testdata → ConformanceVector[].
//
// Reads the vendored pairs under `harness/vectors/rfc8785/{input,output}/`
// and emits a single ConformanceVector[] file at
// `harness/vectors/rfc8785-vectors.json`. The vectors land in the
// `canonical-bytes` mode the driver already supports, so the
// `harness/test/conformance.test.ts` matrix runs every SDK's runner
// against them with no vector changes.
//
// Run with `pnpm run jcs:generate-vectors` from the harness directory, or
// `just jcs-generate-vectors` from the repo root. The generated file is
// checked in so a clean checkout has the corpus without rerunning this.
//
// Correctness invariants:
//
// 1. The output file's bytes ARE the canonical form. We MUST NOT parse
//    and re-stringify the output — re-serialization will pick a different
//    escape policy (literal UTF-8 vs `\uXXXX`) and the runner's
//    cross-SDK byte agreement is broken the moment we touch the bytes.
//    Read the file as utf-8 text and embed it verbatim as
//    `expect.exactBytes.canonicalJson`.
//
// 2. The base64url is `base64url(utf8(canonicalJson))`, not
//    `base64url(canonicalJson)`. UTF-8 first; the canonical form may
//    contain literal non-ASCII bytes (e.g. `€` in `values.json`).
//
// 3. The input is a JSON value. We parse the input file (it is JSON) and
//    re-stringify it for embedding into the vector; the runner's JSON
//    parser re-parses on receipt, and the JCS encoder canonicalizes the
//    resulting value. Round-trip equivalence holds for our cases.
//
// 4. arrays.json is a JSON array of multiple cases; the other files are
//    single values. We expand arrays into one vector per element with a
//    `-N` suffix so failures are attributable to a specific case.

import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const harnessRoot = resolve(here, "..", "..");
const corpusDir = join(harnessRoot, "vectors", "rfc8785");
const outFile = join(harnessRoot, "vectors", "rfc8785-vectors.json");

// The 6 input/output pairs from cyberphone/json-canonicalization
// testdata/. Pinned to the same set the Justfile's `jcs-pull-corpus`
// recipe fetches. Order is preserved in the generated file for stable
// diffs across regenerations.
const FILES = [
  "arrays",
  "french",
  "structures",
  "unicode",
  "values",
  "weird",
] as const;

type ConformanceVector = {
  id: string;
  intent: "charge";
  mode: "canonical-bytes";
  description: string;
  input: { value: unknown };
  expect: {
    outcome: "accept";
    exactBytes: { canonicalJson: string; base64Url: string };
  };
};

function readUtf8(path: string): string {
  return readFileSync(path, "utf8");
}

function base64UrlFromUtf8(s: string): string {
  return Buffer.from(s, "utf8").toString("base64url");
}

// Each cyberphone input file is a single case — the file as a whole is
// the input to JCS, the output file as a whole is the expected canonical
// form. The top-level JSON shape of the input varies (object, array, or
// even a bare number/string) but it is always ONE case per file. The
// reference implementations in cyberphone call `Transform(bytes)` once
// per file, never per element. We must mirror that: one vector per file.
function buildVectors(): ConformanceVector[] {
  const vectors: ConformanceVector[] = [];
  for (const name of FILES) {
    const inputPath = join(corpusDir, "input", `${name}.json`);
    const outputPath = join(corpusDir, "output", `${name}.json`);

    // (1) Read the output file's bytes verbatim — see invariant 1.
    const canonicalJson = readUtf8(outputPath).trimEnd();

    // (2) Compute base64url of the utf-8 bytes.
    const base64Url = base64UrlFromUtf8(canonicalJson);

    // (3) Parse the input. `JSON.parse` is the right call here: the
    // runner re-parses the embedded value on receipt, and JCS operates
    // on the resulting structure, not on the source string.
    const inputRaw = readUtf8(inputPath);
    const value = JSON.parse(inputRaw) as unknown;

    vectors.push({
      id: `rfc8785-${name}`,
      intent: "charge",
      mode: "canonical-bytes",
      description: `cyberphone/json-canonicalization testdata/${name}`,
      input: { value },
      expect: {
        outcome: "accept",
        exactBytes: { canonicalJson, base64Url },
      },
    });
  }
  return vectors;
}

function main(): void {
  const vectors = buildVectors();
  mkdirSync(dirname(outFile), { recursive: true });
  writeFileSync(outFile, JSON.stringify(vectors, null, 2) + "\n", "utf8");
  // eslint-disable-next-line no-console
  console.log(
    `Wrote ${vectors.length} vector(s) to ${outFile} ` +
      `(from ${FILES.length} cyberphone testdata file(s))`,
  );
}

main();
