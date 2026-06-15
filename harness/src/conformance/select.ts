// Path-based conformance-runner selection for CI.
//
// On a PR that touches only one SDK, exercising every language runner is
// wasted CI time: a Go-only change cannot affect the Python runner's
// agreement with the vectors. This selects which language runners to run
// from the set of changed paths, and falls back to the FULL set whenever a
// shared file changes (the vectors, the driver, a runner manifest, or the
// harness conformance source), because a shared change can shift the
// cross-SDK contract for every language at once.
//
// Mirrors mpp-tools select_ci_adapters.py: per-language path prefixes, with
// a shared-path tripwire that forces the full matrix. The selection is
// advisory — the driver itself still discovers every runner; CI narrows the
// set by passing MPP_CONFORMANCE_LANGUAGES (see filterRunnersByEnv).

// Per-language path prefixes. A changed path under one of these prefixes
// selects that language's runner.
const LANGUAGE_PREFIXES: Record<string, string[]> = {
  typescript: ["typescript/"],
  go: ["go/"],
  python: ["python/"],
  ruby: ["ruby/"],
  php: ["php/"],
  lua: ["lua/"],
};

// Shared paths whose change can shift the cross-SDK contract for every
// language, so any touch here forces the full matrix. The conformance
// driver, the contract schema, the shared JCS/decode/reject/x402 reference,
// the vectors, and the runner manifests are all shared.
const SHARED_PREFIXES: string[] = [
  "harness/vectors/",
  "harness/runners/",
  "harness/src/conformance/",
  "harness/test/conformance.test.ts",
];

export const ALL_LANGUAGES: string[] = Object.keys(LANGUAGE_PREFIXES).sort();

// Decide which language runners to exercise for a set of changed paths.
// Returns the full language set when a shared file changed or when the
// change set is empty (be conservative: run everything). Otherwise returns
// exactly the languages whose own trees changed, sorted and de-duplicated.
export function selectConformanceLanguages(changedPaths: string[]): string[] {
  if (changedPaths.length === 0) return [...ALL_LANGUAGES];

  const normalized = changedPaths.map((p) => p.replace(/^\.\//, ""));

  const sharedTouched = normalized.some((path) =>
    SHARED_PREFIXES.some((prefix) =>
      prefix.endsWith("/") ? path.startsWith(prefix) : path === prefix,
    ),
  );
  if (sharedTouched) return [...ALL_LANGUAGES];

  const selected = new Set<string>();
  for (const path of normalized) {
    for (const [language, prefixes] of Object.entries(LANGUAGE_PREFIXES)) {
      if (prefixes.some((prefix) => path.startsWith(prefix))) {
        selected.add(language);
      }
    }
  }
  return [...selected].sort();
}

// Parse the comma-separated MPP_CONFORMANCE_LANGUAGES env var into a
// language allowlist. Returns undefined (no filtering: run all discovered
// runners) when the var is unset or empty.
export function parseLanguageAllowlist(
  raw: string | undefined,
): Set<string> | undefined {
  if (!raw) return undefined;
  const langs = raw
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);
  return langs.length > 0 ? new Set(langs) : undefined;
}
