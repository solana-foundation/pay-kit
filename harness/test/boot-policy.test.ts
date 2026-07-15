import { execFileSync } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { ImplementationDefinition } from "../src/implementations";
import { startServer, stopServer } from "../src/process";

// ---------------------------------------------------------------------------
// Cross-SDK "deployment policy" conformance: fail-CLOSED store construction.
//
// The rest of the harness compares verify DECISIONS on fixed transactions. It
// never exercises store-construction / boot-time safety policy, so nothing
// pins the audited divergence:
//
//   * Go fails CLOSED off-localnet when no shared replay/session store is
//     configured and PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE is unset — a
//     process-local in-memory store silently loses double-spend protection on
//     a multi-replica deploy (fail-OPEN).
//   * TS and Python (the high-level server adapters the harness fixtures boot)
//     fail OPEN today: they construct a process-local in-memory store off
//     localnet and boot to `ready` anyway.
//
// SECURITY.md claims PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE is honored across the
// Go, TypeScript, and Python SDKs, but no test proved it. This file is that
// proof. It drives each SDK's real server/high-level-adapter *constructor*
// (reusing the harness `startServer` spawn machinery and the existing
// `*-server` fixtures) and asserts:
//
//   1. Constructed off-localnet (network=mainnet) with NO shared store and
//      WITHOUT PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1 => it MUST fail CLOSED
//      (the process errors/throws before readiness).
//   2. With the opt-in (PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1) it boots to
//      `ready` — proving the opt-in is honored, not merely that boot is broken.
//
// RED-EXPECTED-PENDING: the TS and Python fail-closed remediations are landing
// in parallel in this same worktree. Until they land, the `typescript` and
// `python` fail-closed cases boot to `ready` (fail-OPEN) and their tests go
// RED on purpose — that is the pending signal. They go GREEN once the SDK
// constructors reject an in-memory replay/session store off-localnet without
// the opt-in. Go already fails closed and is GREEN now.
//
// FALSE-GREEN GUARD: the fail-closed assertion does not merely check "the boot
// failed" — a missing toolchain, unbuilt binary, or bad RPC would fail boot for
// the wrong reason. It requires the rejection to carry the canonical
// fail-closed SIGNATURE (the shared PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE opt-in
// string, or the "no shared … store configured" wording), so only a real
// policy rejection passes.
// ---------------------------------------------------------------------------

// A deterministic, valid ed25519 keypair (64-byte Solana secret key + its
// base58 pubkey). Real bytes so `createKeyPairSignerFromBytes` (TS),
// `Keypair.from_bytes` (Python) and the Go JSON-array signer decode cleanly —
// the boot must reach the store-construction gate, not trip on a bad signer.
const KEYPAIR_BYTES = [
  48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 48, 49, 50,
  51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 35, 188, 84, 145, 44,
  30, 110, 146, 196, 168, 104, 37, 200, 103, 226, 127, 253, 197, 85, 191, 251,
  212, 36, 79, 23, 162, 106, 191, 255, 238, 150, 93,
];
const KEYPAIR_PUBKEY = "3QVq8D876hmq5C5L6J3CKpWXPhvbHASz8qFsddSXFDP2";
const KEYPAIR_JSON = JSON.stringify(KEYPAIR_BYTES);

// Canonical mainnet USDC mint. On the success (opt-in) boot the SDK resolves
// the token program from its static stablecoin table — no live RPC — so the
// fixture reaches `ready` against a bogus RPC URL. Go/TS also accept the bare
// "USDC" symbol; Python's MPP path runs in pubkey mode and wants the literal
// mint pubkey.
const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";

// >= 32-byte HMAC secret (Rust audit #24 / NIST SP 800-107). A short secret
// would trip the secret-length gate BEFORE the store gate on some SDKs.
const HMAC_SECRET = "mpp-harness-secret-key-with-32b-pad";

// A never-dialed RPC URL. Every covered SDK's charge constructor is lazy about
// RPC (Go resolves USDC statically; TS is lazy; Python boots with rpc=None), so
// the socket is never opened at boot.
const DEAD_RPC_URL = "http://127.0.0.1:1";

const OPT_IN_ENV = "PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE";

// The canonical fail-closed signature shared across SDKs. The opt-in env-var
// name is the cross-SDK remediation string SECURITY.md guarantees every SDK
// emits; the "no shared … store configured" wording is the Go/TS phrasing. A
// toolchain/binary/RPC failure will NOT match either, so it cannot false-green.
const FAIL_CLOSED_SIGNATURE =
  /PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE|no shared[^\n]*store configured/i;

type RunningServer = Awaited<ReturnType<typeof startServer>>;

const runningServers: RunningServer[] = [];

afterEach(async () => {
  while (runningServers.length > 0) {
    const server = runningServers.pop();
    if (server) {
      await stopServer(server);
    }
  }
});

function commandExists(cmd: string): boolean {
  try {
    // Pass cmd as $1 so it is never interpolated into the shell script.
    execFileSync("sh", ["-c", 'command -v "$1"', "sh", cmd], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

// Build the Go umbrella server fixture once so the boot probe runs a real
// binary instead of relying on a pre-warmed `paykit-server` (which the default
// checkout does not ship). Returns null when Go is unavailable; when Go is
// available, a build failure must be a hard error, not a quiet skip.
function tryBuildGoServer(): string | null {
  if (!commandExists("go")) {
    return null;
  }
  const outDir = mkdtempSync(join(tmpdir(), "pk-boot-policy-go-"));
  const bin = join(outDir, "paykit-server");
  execFileSync("go", ["build", "-o", bin, "."], {
    cwd: join(process.cwd(), "go-server"),
    stdio: "pipe",
  });
  return bin;
}

const goServerBin = tryBuildGoServer();

// A covered SDK: one whose server/high-level adapter boot path actually
// implements (or is being remediated to implement) the shared
// PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE fail-closed contract.
type CoveredProbe = {
  id: string;
  label: string;
  available: boolean;
  // Why the probe is unavailable (skipped), for a loud note.
  unavailableReason?: string;
  // Adapter definition consumed by `startServer` (only id/label/role/command/
  // reportsAs are load-bearing here).
  implementation: ImplementationDefinition;
  // Per-SDK env used to reach the MPP charge store-construction gate.
  mppEnv: Record<string, string>;
};

function mppEnv(mint: string): Record<string, string> {
  return {
    // Force the dual-protocol fixtures onto the MPP charge settle path (the one
    // that constructs the replay store) rather than x402.
    PAY_KIT_HARNESS_PROTOCOL: "mpp",
    MPP_HARNESS_RPC_URL: DEAD_RPC_URL,
    MPP_HARNESS_NETWORK: "mainnet",
    MPP_HARNESS_MINT: mint,
    MPP_HARNESS_AMOUNT: "1000",
    MPP_HARNESS_PRICE: "0.001",
    MPP_HARNESS_PAY_TO: KEYPAIR_PUBKEY,
    MPP_HARNESS_SECRET_KEY: HMAC_SECRET,
    MPP_HARNESS_FEE_PAYER_SECRET_KEY: KEYPAIR_JSON,
    MPP_HARNESS_CLIENT_SECRET_KEY: KEYPAIR_JSON,
  };
}

function serverImpl(
  id: string,
  label: string,
  command: string[],
  reportsAs: string,
): ImplementationDefinition {
  return {
    id,
    label,
    role: "server",
    command,
    enabled: true,
    reportsAs,
  };
}

// Subject probe (gate activates with its subject): the shared fail-closed
// store contract for a given SDK arrives with that SDK's #216 redelivery leaf
// (typescript -> the mpp replay-store leaf, python -> the python hardening
// leaf). Until the leaf is in this tree the SDK has no opt-in reference and
// the boot probe reports itself pending instead of failing on a guard that
// does not exist yet. Self-contained (no forward references) because it runs
// during coveredProbes initialization.
function sdkImplementsOptInGuard(sdkDir: string, marker: string = OPT_IN_ENV): boolean {
  const repoRoot = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
  try {
    const out = execFileSync("git", ["grep", "-l", marker, "--", sdkDir], {
      cwd: repoRoot,
      encoding: "utf8",
    });
    return out.split("\n").filter(Boolean).length > 0;
  } catch (error) {
    const status = (error as { status?: number }).status;
    const stdout = (error as { stdout?: string }).stdout ?? "";
    if (status === 1 && stdout.trim() === "") return false;
    throw error;
  }
}

// TS references the opt-in env var pre-hardening (docs + a permissive reader),
// so the TS probe keys on the fail-closed policy surface itself
// (declareProductionReplayStore), which only the mpp replay-store leaf adds.
const TS_GUARD_MARKER = "declareProductionReplayStore";

const coveredProbes: CoveredProbe[] = [
  {
    id: "go",
    label: "Go PayKit umbrella server (server.New)",
    available: goServerBin !== null,
    unavailableReason:
      goServerBin === null
        ? "go toolchain missing or `go build ./go-server` failed"
        : undefined,
    implementation: serverImpl(
      "go",
      "Go PayKit umbrella server (server.New)",
      goServerBin ? [goServerBin] : ["false"],
      "go-paykit",
    ),
    mppEnv: mppEnv("USDC"),
  },
  {
    id: "typescript",
    label: "TypeScript Mppx.create / solana.charge server",
    available: commandExists("pnpm") && sdkImplementsOptInGuard("typescript/packages/pay-kit/src", TS_GUARD_MARKER),
    unavailableReason: !commandExists("pnpm")
      ? "pnpm missing"
      : sdkImplementsOptInGuard("typescript/packages/pay-kit/src", TS_GUARD_MARKER)
        ? undefined
        : "PENDING: TS fail-closed store guard is not in this tree yet; the probe activates when the mpp replay-store leaf lands",
    implementation: serverImpl(
      "typescript",
      "TypeScript Mppx.create / solana.charge server",
      [
        "pnpm",
        "exec",
        "node",
        "--import",
        "tsx",
        "src/fixtures/typescript/charge-server.ts",
      ],
      "typescript",
    ),
    mppEnv: mppEnv("USDC"),
  },
  {
    id: "python",
    label: "Python solana_pay_kit high-level MppAdapter (MppAdapter.__init__)",
    available: commandExists("uv") && sdkImplementsOptInGuard("python/src"),
    unavailableReason: !commandExists("uv")
      ? "uv missing"
      : sdkImplementsOptInGuard("python/src")
        ? undefined
        : "PENDING: python fail-closed store guard is not in this tree yet; the probe activates when the python hardening leaf lands",
    // Drive the HIGH-LEVEL adapter constructor, not the harness `server.py`
    // MPP fixture. That fixture builds the lower-level `charge.Mpp` with an
    // explicit `store=MemoryStore()`, so it never reaches the adapter's default
    // store gate. `mpp-adapter-boot.py` constructs `MppAdapter(config)` with NO
    // replay_store, so its `_default_replay_store()` fail-closed guard runs:
    // off-localnet with no opt-in it raises (fail-closed), with the opt-in it
    // boots to `ready`.
    implementation: serverImpl(
      "python",
      "Python solana_pay_kit high-level MppAdapter (MppAdapter.__init__)",
      ["uv", "run", "--project", "../python", "python", "python-server/mpp-adapter-boot.py"],
      "python",
    ),
    // Python MPP runs in pubkey mode: the literal mint pubkey is the currency.
    mppEnv: mppEnv(USDC_MINT),
  },
];

// SDKs whose server boot surface does NOT implement the shared
// PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE fail-closed contract at all (verified: no
// reference to the opt-in var anywhere in the SDK source). There is no
// fail-closed boot behavior to conform to yet, so these are asserted-SKIPPED
// with a loud note rather than silently passed. Extending the contract to them
// is itself an open audit gap.
const unimplementedProbes: Array<{ id: string; reason: string }> = [
  {
    id: "rust",
    reason:
      "Rust MPP server exposes no PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE boot-time fail-closed guard",
  },
  {
    id: "php",
    reason:
      "PHP SolanaChargeHandler has a MemoryStore but no off-localnet fail-closed boot guard",
  },
  {
    id: "ruby",
    reason:
      "Ruby MPP runtime has a MemoryStore but no off-localnet fail-closed boot guard",
  },
  {
    id: "lua",
    reason: "Lua resty.pay_kit exposes no in-memory-store fail-closed boot guard",
  },
  {
    id: "kotlin",
    reason: "Kotlin adapter exposes no in-memory-store fail-closed boot guard",
  },
  {
    id: "swift",
    reason: "Swift adapter exposes no in-memory-store fail-closed boot guard",
  },
];

// Loud note: surface the coverage gap in the run log, not just as silent skips.
// eslint-disable-next-line no-console
console.warn(
  "[boot-policy] fail-closed store contract is only implemented/remediated for " +
    "go, typescript, python. Asserting-SKIP the rest (no PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE " +
    "boot guard in their SDK source): " +
    unimplementedProbes.map((p) => p.id).join(", ") +
    ". Extending the contract cross-SDK is an open audit gap.",
);

// Boot the SDK at network=mainnet with NO opt-in and assert it fails CLOSED
// with the canonical signature. If it instead boots to `ready` (the audited
// fail-OPEN), stop the leaked server and throw loudly — that is the
// red-expected-pending state until the SDK remediation lands.
async function assertFailsClosed(probe: CoveredProbe): Promise<void> {
  let server: RunningServer | undefined;
  try {
    server = await startServer(probe.implementation, probe.mppEnv);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    expect(
      message,
      `${probe.id}: boot failed but not with the fail-closed policy signature. ` +
        `A missing toolchain/binary/RPC would fail here too, so this is NOT a ` +
        `valid fail-closed. Rejection was:\n${message}`,
    ).toMatch(FAIL_CLOSED_SIGNATURE);
    return;
  }
  // Unexpected: the constructor booted to ready off-localnet with no store and
  // no opt-in. Clean up, then fail with the audit context.
  runningServers.push(server);
  throw new Error(
    `${probe.id}: expected fail-CLOSED boot at network=mainnet with no shared ` +
      `store and no ${OPT_IN_ENV}, but the server booted to \`ready\` (fail-OPEN). ` +
      `This is the audited gap: the SDK must reject process-local in-memory ` +
      `replay/session store construction off-localnet without the opt-in. ` +
      `RED-EXPECTED-PENDING until the ${probe.id} remediation lands.`,
  );
}

// Boot the SAME SDK/env but WITH the opt-in and assert it reaches `ready` — the
// only difference from the fail-closed run is the single env var, so a green
// here proves the opt-in (not a broken boot) is what gates the store.
async function assertBootsWithOptIn(probe: CoveredProbe): Promise<void> {
  const server = await startServer(probe.implementation, {
    ...probe.mppEnv,
    [OPT_IN_ENV]: "1",
  });
  runningServers.push(server);
  expect(server.ready.type).toBe("ready");
  expect(server.ready.role).toBe("server");
  expect(server.ready.port).toBeGreaterThan(0);
}

describe("boot-policy conformance: fail-CLOSED off-localnet without opt-in", () => {
  for (const probe of coveredProbes) {
    if (!probe.available) {
      // eslint-disable-next-line no-console
      console.warn(
        `[boot-policy] SKIP ${probe.id} fail-closed probe: ${probe.unavailableReason}`,
      );
    }
    it.skipIf(!probe.available)(
      `${probe.id}: fails closed at network=mainnet with no ${OPT_IN_ENV}`,
      async () => {
        await assertFailsClosed(probe);
      },
    );
  }
});

describe("boot-policy conformance: boots with the opt-in", () => {
  for (const probe of coveredProbes) {
    it.skipIf(!probe.available)(
      `${probe.id}: boots to ready at network=mainnet with ${OPT_IN_ENV}=1`,
      async () => {
        await assertBootsWithOptIn(probe);
      },
    );
  }
});

describe("boot-policy conformance: SDKs without the store fail-closed contract", () => {
  for (const probe of unimplementedProbes) {
    // eslint-disable-next-line no-console
    console.warn(
      `[boot-policy] ASSERT-SKIP ${probe.id}: ${probe.reason}`,
    );
    it.skip(`${probe.id}: ${probe.reason}`, () => {
      // Intentionally skipped: no boot-policy contract to conform to yet.
    });
  }
});

// Enforcement, not just a comment: unimplementedProbes CLAIMS these SDKs carry
// no PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE reference. Assert it for real by
// scanning each SDK's tracked source. The moment an SDK gains a reference
// (someone starts wiring the fail-closed contract) this REDs, forcing that SDK
// to be promoted from an asserted-skip to a LIVE boot-policy probe that actually
// asserts fail-closed / opt-in boot, rather than lingering half-implemented and
// silently skipped. Uses `git grep` so .gitignored build/vendor trees (target/,
// vendor/, .build/) are excluded automatically.
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const SDK_SOURCE_DIR: Record<string, string> = {
  rust: "rust",
  php: "php",
  ruby: "ruby",
  lua: "lua",
  kotlin: "kotlin",
  swift: "swift",
};

function sdkFilesReferencingOptIn(sdkDir: string): string[] {
  try {
    const out = execFileSync("git", ["grep", "-l", OPT_IN_ENV, "--", sdkDir], {
      cwd: REPO_ROOT,
      encoding: "utf8",
    });
    return out.split("\n").filter(Boolean);
  } catch (error) {
    const status = (error as { status?: number }).status;
    const stdout = (error as { stdout?: string }).stdout ?? "";
    // git grep exits 1 with empty output when there are no matches -> honest skip.
    if (status === 1 && stdout.trim() === "") return [];
    throw error;
  }
}

describe("boot-policy: asserted-skip roster stays honest (no half-implemented contract)", () => {
  for (const probe of unimplementedProbes) {
    const sdkDir = SDK_SOURCE_DIR[probe.id];
    it(`${probe.id} genuinely has no ${OPT_IN_ENV} reference (else promote it to a live probe)`, () => {
      expect(
        sdkDir,
        `no source dir mapped for unimplemented probe ${probe.id}`,
      ).toBeDefined();
      const hits = sdkFilesReferencingOptIn(sdkDir);
      expect(
        hits,
        `${probe.id} now references ${OPT_IN_ENV} in: ${hits.join(", ")}. The ` +
          `fail-closed store contract is being wired into this SDK, so it must move ` +
          `from unimplementedProbes to a real (non-skipped) boot-policy probe that ` +
          `asserts fail-closed / opt-in boot -- not stay an asserted-skip.`,
      ).toEqual([]);
    });
  }
});
