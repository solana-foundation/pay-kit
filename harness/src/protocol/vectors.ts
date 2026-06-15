// Loader and types for the canonical mpp-protocol conformance vectors
// vendored under `harness/vectors/mpp-protocol/`.
//
// These vectors come from tempoxyz/mpp-tools (MIT) and are the protocol
// oracle for pay-kit's per-SDK protocol layer (challenge / credential /
// receipt header codec, base64url, and the challenge-id HMAC). See
// `harness/vectors/mpp-protocol/README.md` for provenance.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
export const VECTORS_DIR = join(here, "..", "..", "vectors", "mpp-protocol");

// Canonical adapter-ABI operation identifiers. These match
// `conformance/operations.json` in mpp-tools verbatim.
export type ProtocolOperation =
  | "challenge.parse"
  | "challenge.format"
  | "credential.parse"
  | "credential.format"
  | "receipt.parse"
  | "receipt.format"
  | "base64url.encode"
  | "base64url.decode"
  | "challenge.id";

// Comparison discipline per operation, taken from operations.json:
//   exact    -> result string/object must equal the golden byte-for-byte
//   semantic -> parsed object must be deep-equal to the golden object
//               (header whitespace / param order is not significant)
export type ComparisonMode = "exact" | "semantic";

export const OPERATION_COMPARISON: Record<ProtocolOperation, ComparisonMode> = {
  "challenge.parse": "semantic",
  "challenge.format": "semantic",
  "credential.parse": "semantic",
  "credential.format": "semantic",
  "receipt.parse": "semantic",
  "receipt.format": "semantic",
  "base64url.encode": "exact",
  "base64url.decode": "exact",
  "challenge.id": "exact",
};

// ── Raw vector file shapes ──

// A per-direction test flag is either `true` (happy-path: run the op and
// compare to the golden object/wire) or an object declaring an expected
// failure, e.g. `{ "success": false, "error_type": "parse_error" }`.
type TestExpectation = boolean | { success: false; error_type: string };

type TestFlags = {
  parse?: TestExpectation;
  format?: TestExpectation;
  roundtrip?: TestExpectation;
};

function expectsError(flag: TestExpectation | undefined): string | null {
  if (flag && typeof flag === "object" && flag.success === false) {
    return flag.error_type;
  }
  return null;
}

function expectsSuccess(flag: TestExpectation | undefined): boolean {
  return flag === true;
}

// A scenario `wire` is either a literal header string or a constructed
// shorthand for inputs too large to vendor literally: the materialized
// wire is `prefix + repeat.repeat(count) + suffix`. Mirrors the canonical
// runner's `scenario_wire`.
export type ConstructedWire = {
  prefix?: string;
  repeat?: string;
  count?: number;
  suffix?: string;
};

export function materializeWire(wire: string | ConstructedWire): string {
  if (typeof wire === "string") return wire;
  const prefix = wire.prefix ?? "";
  const repeat = wire.repeat ?? "";
  const count = wire.count ?? 0;
  const suffix = wire.suffix ?? "";
  return `${prefix}${repeat.repeat(count)}${suffix}`;
}

export type HeaderScenario = {
  name: string;
  description?: string;
  tags?: string[];
  object?: Record<string, unknown>;
  wire: string | ConstructedWire;
  tests: TestFlags;
  // Adapter allow-list: when present, the scenario only runs against
  // runners whose language name is listed (canonical runner skips it for
  // every other adapter).
  adapters?: string[];
  // Wall-clock budgets (ms) for the operation; the per-adapter map wins
  // over the scalar. Mirrors the canonical runner's `duration_limit_ms`.
  maxDurationMs?: number;
  maxDurationMsByAdapter?: Record<string, number>;
};

export type Base64Scenario = {
  name: string;
  description?: string;
  tags?: string[];
  decoded: string;
  encoded: string;
  tests: TestFlags;
};

export type ChallengeIdScenario = {
  name: string;
  description?: string;
  tags?: string[];
  input: {
    secretKey: string;
    realm?: string;
    method?: string;
    intent?: string;
    request?: Record<string, unknown>;
    expires?: string;
    digest?: string;
    description?: string;
    opaque?: string;
  };
  expected: string;
};

type VectorFile<S> = {
  version: string;
  spec_ref: string;
  description: string;
  commands: Record<string, string>;
  scenarios: S[];
};

function load<S>(file: string): VectorFile<S> {
  return JSON.parse(readFileSync(join(VECTORS_DIR, file), "utf8")) as VectorFile<S>;
}

export function loadWwwAuthenticate(): VectorFile<HeaderScenario> {
  return load<HeaderScenario>("www-authenticate.json");
}

export function loadAuthorization(): VectorFile<HeaderScenario> {
  return load<HeaderScenario>("authorization.json");
}

export function loadReceipt(): VectorFile<HeaderScenario> {
  return load<HeaderScenario>("receipt.json");
}

export function loadBase64Url(): VectorFile<Base64Scenario> {
  return load<Base64Scenario>("base64url.json");
}

export function loadChallengeId(): VectorFile<ChallengeIdScenario> {
  return load<ChallengeIdScenario>("challenge-id.json");
}

// A single dispatchable unit of work derived from a vector scenario: the
// op to run, the adapter input envelope, and either the golden success
// output (for a happy-path) or the expected error_type.
//
// `reparseWith` mirrors the canonical runner's `semantic` discipline for
// `*.format` operations: rather than comparing wire bytes (which differ
// across SDKs by JCS key order, header param order, or request encoding),
// the driver feeds BOTH the golden wire and the adapter's produced wire
// back through `reparseWith` and compares the parsed objects. base64url
// and challenge.id are `exact` and never set `reparseWith`.
type ProtocolCaseBase = {
  op: ProtocolOperation;
  scenario: string;
  input: unknown;
  // Carried over from the scenario: adapter allow-list and wall-clock
  // budgets (see HeaderScenario). Both are enforced by the driver/test via
  // `caseRunsOnAdapter` and `durationLimitMs`.
  adapters?: string[];
  maxDurationMs?: number;
  maxDurationMsByAdapter?: Record<string, number>;
};

export type ProtocolCase = ProtocolCaseBase & ({
  expectSuccess: true;
  golden: unknown;
  reparseWith?: ProtocolOperation;
} | {
  expectSuccess: false;
  errorType: string;
});

// Canonical adapter filter: a case with an `adapters` allow-list only runs
// against adapters whose name is listed; everything else runs everywhere.
// Mirrors the canonical runner's scenario_adapters skip.
export function caseRunsOnAdapter(testCase: ProtocolCase, adapterName: string): boolean {
  if (!testCase.adapters || testCase.adapters.length === 0) return true;
  return testCase.adapters.includes(adapterName);
}

// Canonical duration budget resolution: the per-adapter entry wins over the
// scalar `maxDurationMs`; `null` means unbounded. Mirrors the canonical
// runner's `duration_limit_ms`.
export function durationLimitMs(testCase: ProtocolCase, adapterName: string): number | null {
  const perAdapter = testCase.maxDurationMsByAdapter;
  if (perAdapter && adapterName in perAdapter) return perAdapter[adapterName];
  return testCase.maxDurationMs ?? null;
}

// Expand every vendored vector into the flat list of protocol cases a
// runner must satisfy. Each scenario's `tests` flags decide which
// directions (parse / format) are exercised; roundtrip is covered by
// running both parse and format.
export function collectProtocolCases(): ProtocolCase[] {
  const cases: ProtocolCase[] = [];

  const pushHeader = (
    parseOp: ProtocolOperation,
    formatOp: ProtocolOperation,
    file: VectorFile<HeaderScenario>,
  ) => {
    for (const s of file.scenarios) {
      const wire = materializeWire(s.wire);
      // Adapter allow-list and duration budgets carry through to every
      // case derived from the scenario.
      const limits = {
        adapters: s.adapters,
        maxDurationMs: s.maxDurationMs,
        maxDurationMsByAdapter: s.maxDurationMsByAdapter,
      };

      // Parse direction.
      const parseErr = expectsError(s.tests.parse);
      if (parseErr) {
        cases.push({
          op: parseOp,
          scenario: s.name,
          input: { header: wire },
          expectSuccess: false,
          errorType: parseErr,
          ...limits,
        });
      } else if (expectsSuccess(s.tests.parse) && s.object) {
        cases.push({
          op: parseOp,
          scenario: s.name,
          input: { header: wire },
          expectSuccess: true,
          golden: s.object,
          ...limits,
        });
      }

      // Format direction.
      const formatErr = expectsError(s.tests.format);
      if (formatErr && s.object) {
        cases.push({
          op: formatOp,
          scenario: s.name,
          input: s.object,
          expectSuccess: false,
          errorType: formatErr,
          ...limits,
        });
      } else if (expectsSuccess(s.tests.format) && s.object) {
        cases.push({
          op: formatOp,
          scenario: s.name,
          input: s.object,
          expectSuccess: true,
          golden: { header: wire },
          reparseWith: parseOp,
          ...limits,
        });
      }
    }
  };

  pushHeader("challenge.parse", "challenge.format", loadWwwAuthenticate());
  pushHeader("credential.parse", "credential.format", loadAuthorization());
  pushHeader("receipt.parse", "receipt.format", loadReceipt());

  for (const s of loadBase64Url().scenarios) {
    const encErr = expectsError(s.tests.format);
    if (encErr) {
      cases.push({
        op: "base64url.encode",
        scenario: s.name,
        input: { text: s.decoded },
        expectSuccess: false,
        errorType: encErr,
      });
    } else if (expectsSuccess(s.tests.format)) {
      cases.push({
        op: "base64url.encode",
        scenario: s.name,
        input: { text: s.decoded },
        expectSuccess: true,
        golden: { text: s.encoded },
      });
    }

    const decErr = expectsError(s.tests.parse);
    if (decErr) {
      cases.push({
        op: "base64url.decode",
        scenario: s.name,
        input: { text: s.encoded },
        expectSuccess: false,
        errorType: decErr,
      });
    } else if (expectsSuccess(s.tests.parse)) {
      cases.push({
        op: "base64url.decode",
        scenario: s.name,
        input: { text: s.encoded },
        expectSuccess: true,
        golden: { text: s.decoded },
      });
    }
  }

  for (const s of loadChallengeId().scenarios) {
    cases.push({
      op: "challenge.id",
      scenario: s.name,
      input: s.input,
      expectSuccess: true,
      golden: { id: s.expected },
    });
  }

  return cases;
}
