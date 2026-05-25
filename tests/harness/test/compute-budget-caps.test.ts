import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

/**
 * Cross-SDK compute-budget cap conformance.
 *
 * Asserts every server-side SDK enforces byte-identical caps on
 * ComputeBudget `SetComputeUnitLimit` and `SetComputeUnitPrice`
 * instructions. The canonical pair is taken from the Rust spine:
 *
 *   MAX_COMPUTE_UNIT_LIMIT                = 200_000
 *   MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS  = 5_000_000
 *
 * Rationale: an attacker-supplied transaction can otherwise burn the
 * server's fee-payer balance via an unbounded priority fee (cu_limit *
 * cu_price * lamports_per_signature_fee_payer). The cap pins worst-case
 * fee cost per settled charge. See docs/security/compute-budget-caps.md.
 *
 * Adapters not yet on `main` (Go #101, Python #106) are gated behind
 * existence checks so this suite passes today and tightens automatically
 * when those SDKs merge.
 *
 * Issue: #109.
 */

const REPO_ROOT = resolve(__dirname, "..", "..", "..");

const CANONICAL_LIMIT = 200_000;
const CANONICAL_PRICE_MICROLAMPORTS = 5_000_000;

type Sdk = {
  language: string;
  file: string;
  // Regex must capture the limit and price literals from a known
  // declaration site. Underscores in numeric literals are normalized
  // away before parsing.
  limitPattern: RegExp;
  pricePattern: RegExp;
  // Optional flag: when true, the SDK is not yet on main and the test
  // skips silently if the file does not exist.
  optional?: boolean;
};

const SDKS: Sdk[] = [
  {
    language: "rust",
    file: "rust/src/server/charge.rs",
    limitPattern: /MAX_COMPUTE_UNIT_LIMIT\s*:\s*u32\s*=\s*([0-9_]+)/,
    pricePattern: /MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS\s*:\s*u64\s*=\s*([0-9_]+)/,
  },
  {
    language: "typescript",
    file: "typescript/packages/mpp/src/server/Charge.ts",
    limitPattern: /const\s+MAX_COMPUTE_UNIT_LIMIT\s*=\s*([0-9_]+)/,
    pricePattern: /const\s+MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS\s*=\s*([0-9_]+)n?/,
  },
  {
    language: "php",
    file: "php/src/Server/SolanaChargeTransactionVerifier.php",
    limitPattern: /MAX_COMPUTE_UNIT_LIMIT\s*=\s*([0-9_]+)/,
    pricePattern: /MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS\s*=\s*([0-9_]+)/,
  },
  {
    language: "ruby",
    file: "ruby/lib/mpp/methods/solana/verifier.rb",
    limitPattern: /MAX_COMPUTE_UNIT_LIMIT\s*=\s*([0-9_]+)/,
    pricePattern: /MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS\s*=\s*([0-9_]+)/,
  },
  {
    language: "lua",
    file: "lua/mpp/server/solana_verify.lua",
    limitPattern: /MAX_COMPUTE_UNIT_LIMIT\s*=\s*([0-9]+)/,
    pricePattern: /MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS\s*=\s*([0-9]+)/,
  },
  // Lua PR #103 lands the same caps at the instruction-decoder layer in
  // lua/mpp/methods/solana/instructions.lua; gated until merge.
  {
    language: "lua-instructions",
    file: "lua/mpp/methods/solana/instructions.lua",
    limitPattern: /MAX_COMPUTE_UNIT_LIMIT\s*=\s*([0-9]+)/,
    pricePattern: /MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS\s*=\s*([0-9]+)/,
    optional: true,
  },
  // Go #101 lands `maxComputeUnitLimit` / `maxComputeUnitPriceMicroLamports`
  // in go/server/server.go; gated until merge.
  {
    language: "go",
    file: "go/server/server.go",
    limitPattern: /maxComputeUnitLimit\s+uint32\s*=\s*([0-9_]+)/,
    pricePattern: /maxComputeUnitPriceMicroLamports\s+uint64\s*=\s*([0-9_]+)/,
    optional: true,
  },
  // Python #106 lands MAX_COMPUTE_UNIT_* in python/src/solana_mpp/server/mpp.py;
  // gated until merge.
  {
    language: "python",
    file: "python/src/solana_mpp/server/mpp.py",
    limitPattern: /MAX_COMPUTE_UNIT_LIMIT\s*=\s*([0-9_]+)/,
    pricePattern: /MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS\s*=\s*([0-9_]+)/,
    optional: true,
  },
];

function readIfPresent(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw err;
  }
}

function parseLiteral(match: RegExpMatchArray | null, label: string, sdk: string): number {
  if (!match) {
    throw new Error(`${sdk}: ${label} declaration not found`);
  }
  const raw = match[1].replace(/_/g, "");
  const value = Number(raw);
  if (!Number.isFinite(value)) {
    throw new Error(`${sdk}: ${label} literal ${match[1]} is not a finite number`);
  }
  return value;
}

describe("compute-budget cap conformance (issue #109)", () => {
  it("canonical pair documented in docs/security/compute-budget-caps.md", () => {
    const doc = readFileSync(
      resolve(REPO_ROOT, "docs/security/compute-budget-caps.md"),
      "utf8",
    );
    expect(doc).toContain(String(CANONICAL_LIMIT));
    expect(doc).toContain(String(CANONICAL_PRICE_MICROLAMPORTS));
  });

  for (const sdk of SDKS) {
    it(`${sdk.language} server enforces canonical caps`, () => {
      const path = resolve(REPO_ROOT, sdk.file);
      const source = readIfPresent(path);
      if (source === null) {
        if (sdk.optional) {
          // SDK not yet on main; future PR will surface this row.
          return;
        }
        throw new Error(`${sdk.language}: required source file missing at ${sdk.file}`);
      }
      const limitMatch = source.match(sdk.limitPattern);
      const priceMatch = source.match(sdk.pricePattern);
      if (sdk.optional && limitMatch === null && priceMatch === null) {
        // SDK source file exists on main but neither cap constant has
        // landed yet (open PR introduces them as a pair). A partial match
        // (one constant present, the other missing) is a real regression
        // and must surface as a failure rather than be silently skipped.
        return;
      }
      const limit = parseLiteral(limitMatch, "limit", sdk.language);
      const price = parseLiteral(priceMatch, "price", sdk.language);
      expect(limit, `${sdk.language} MAX_COMPUTE_UNIT_LIMIT drift`).toBe(CANONICAL_LIMIT);
      expect(price, `${sdk.language} MAX_COMPUTE_UNIT_PRICE_MICROLAMPORTS drift`).toBe(
        CANONICAL_PRICE_MICROLAMPORTS,
      );
    });
  }
});
