import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

type KnownBadVector = {
  id: string;
  protocol: string;
  ownerLane: string;
  artifactKind: string;
  bugClass: string;
  labels: string[];
  summary: string;
  minimalRepro: Record<string, unknown>;
  expected: {
    status: string;
    httpStatus?: number;
    rejectionClass: string;
    runnerRejectCode?: string;
    x402ExactRejectCode?: string;
  };
};

type RegressionBankManifest = {
  schemaVersion: number;
  ownerLane: string;
  description: string;
  vectors: KnownBadVector[];
};

const here = dirname(fileURLToPath(import.meta.url));
const harnessDir = join(here, "..");
const manifestPath = join(
  harnessDir,
  "vectors",
  "known-bad",
  "regression-bank.json",
);
const vectorsReadmePath = join(harnessDir, "vectors", "README.md");

const REQUIRED_BUG_CLASSES = [
  "wrong-network",
  "wrong-route",
  "wrong-mint",
  "wrong-amount",
  "malformed-envelope",
  "invalid-signature",
  "expired-voucher",
  "wrong-account-order",
  "wrong-signer-writable-flags",
] as const;

const ALLOWED_PROTOCOLS = new Set(["x402-exact", "mpp-charge", "mpp-session"]);
const ALLOWED_ARTIFACT_KINDS = new Set(["schema-repro", "signed-artifact"]);
const ALLOWED_STATUSES = new Set(["reject"]);
const ALLOWED_HTTP_STATUSES = new Set([400, 401, 402, 403, 422]);

function loadManifest(): RegressionBankManifest {
  return JSON.parse(readFileSync(manifestPath, "utf8")) as RegressionBankManifest;
}

function expectNonEmptyString(value: unknown, label: string): asserts value is string {
  expect(typeof value, `${label} should be a string`).toBe("string");
  expect((value as string).trim(), `${label} should be non-empty`).not.toBe("");
}

describe("known-bad regression bank", () => {
  const manifest = loadManifest();

  it("covers the required escaped-bug classes", () => {
    expect(manifest.schemaVersion).toBe(1);
    expect(manifest.ownerLane).toBe("regression-vectors");
    expect(manifest.vectors.length).toBeGreaterThanOrEqual(
      REQUIRED_BUG_CLASSES.length,
    );

    const covered = new Set(manifest.vectors.map((vector) => vector.bugClass));
    for (const bugClass of REQUIRED_BUG_CLASSES) {
      expect(covered.has(bugClass), `missing known-bad vector for ${bugClass}`).toBe(
        true,
      );
    }
  });

  it("keeps every vector attributable, labeled, and rejection-shaped", () => {
    const ids = new Set<string>();

    for (const vector of manifest.vectors) {
      expect(vector.id).toMatch(/^known-bad-[a-z0-9-]+$/);
      expect(ids.has(vector.id), `duplicate vector id ${vector.id}`).toBe(false);
      ids.add(vector.id);

      expect(ALLOWED_PROTOCOLS.has(vector.protocol), vector.id).toBe(true);
      expect(vector.ownerLane, vector.id).toBe(manifest.ownerLane);
      expect(ALLOWED_ARTIFACT_KINDS.has(vector.artifactKind), vector.id).toBe(
        true,
      );

      expectNonEmptyString(vector.bugClass, `${vector.id}.bugClass`);
      expect(vector.labels, `${vector.id}.labels`).toContain("known-bad");
      expect(vector.labels, `${vector.id}.labels`).toContain("negative");
      expect(vector.labels, `${vector.id}.labels`).toContain(vector.bugClass);

      expectNonEmptyString(vector.summary, `${vector.id}.summary`);
      expect(vector.minimalRepro, `${vector.id}.minimalRepro`).toBeDefined();
      expect(Array.isArray(vector.minimalRepro), `${vector.id}.minimalRepro`).toBe(
        false,
      );
      expect(
        Object.keys(vector.minimalRepro).length,
        `${vector.id}.minimalRepro should carry a minimal scenario shape`,
      ).toBeGreaterThan(0);

      expect(ALLOWED_STATUSES.has(vector.expected.status), vector.id).toBe(true);
      expect(vector.expected.rejectionClass, vector.id).toBe(vector.bugClass);
      if (vector.expected.httpStatus !== undefined) {
        expect(
          ALLOWED_HTTP_STATUSES.has(vector.expected.httpStatus),
          `${vector.id}.expected.httpStatus`,
        ).toBe(true);
      }
    }
  });

  it("documents the regression-bank coverage policy", () => {
    const readme = readFileSync(vectorsReadmePath, "utf8");

    expect(readme).toContain("## Regression Bank Policy");
    expect(readme).toContain("minimal repro scenario/vector");
    expect(readme).toMatch(/before the fix is considered\s+covered/);
  });
});
