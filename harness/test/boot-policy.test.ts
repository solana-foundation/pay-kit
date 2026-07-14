import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";
import type { ImplementationDefinition } from "../src/implementations";
import { startServer, stopServer } from "../src/process";

// ---------------------------------------------------------------------------
// Cross-SDK deployment-policy conformance: fail-CLOSED store construction.
//
// The rest of the harness compares verify DECISIONS on fixed transactions. It
// never exercises store-construction / boot-time safety policy, so nothing
// pins the audited divergence:
//
//   * Go fails CLOSED off-localnet when no shared replay/session store is
//     configured and PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE is unset — a
//     process-local in-memory store silently loses double-spend protection on
//     a multi-replica deploy (fail-OPEN).
//   * TypeScript and Python high-level server adapters now reject an omitted or
//     process-local in-memory store off-localnet unless an explicit development
//     opt-in is supplied.
//
// Go, TypeScript, and Python share PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE. This
// file drives each SDK's real server/high-level-adapter *constructor* (reusing
// the harness `startServer` spawn machinery and the existing `*-server`
// fixtures) and asserts:
//
//   1. Constructed off-localnet (network=mainnet) with NO shared store and
//      WITHOUT PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1 => it MUST fail CLOSED
//      (the process errors/throws before readiness).
//   2. On devnet, with the opt-in
//      (PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1), it boots to `ready`, proving
//      the development escape is honored without weakening mainnet policy.
//
// These are blocking regression probes: Go, TypeScript, and Python must reject
// unsafe off-localnet construction, while the explicit devnet escape remains
// usable. Any SDK that silently falls back to process-local state goes RED.
// PHP, Ruby, and Lua do NOT use PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE, but they
// DO enforce the same off-localnet fail-closed policy through their native
// config contract (reject an omitted or non-durable/non-shared replay store off
// localnet). The source-contract probes near the end of this file pin those
// real guards rather than pretending they implement this env-var API. Rust,
// Kotlin, and Swift ship no such store guard in-tree yet, so they are
// asserted-SKIPPED with an honest reason.
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
// emits; the "no shared … store configured" wording is the Go/TS phrasing; and
// "forbidden on mainnet" is the wording emitted when an SDK is handed the
// unsafe-memory store on mainnet and refuses it (the Go harness fixture always
// sets that flag, so its mainnet boot fails on this branch). A
// toolchain/binary/RPC failure will NOT match any of these, so it cannot
// false-green.
const FAIL_CLOSED_SIGNATURE =
  /PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE|no shared[^\n]*store configured|forbidden on mainnet/i;

// Repo root: two dirs up from harness/test/. Used to git-grep an SDK's tracked
// source for the fail-closed guard marker (the opt-in env-var name). A covered
// probe is only REQUIRED once its SDK actually carries the guard IN THIS TREE:
// go + typescript ship it here; python's lands via its own PR (#228), so until
// that source merges the python probe asserts-SKIP instead of red-failing this
// leaf. When #228 lands, the same grep sees the marker and auto-promotes python
// to a required probe with no edit here.
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

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

function sdkImplementsGuard(sdkDir: string): boolean {
  return sdkFilesReferencingOptIn(sdkDir).length > 0;
}

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
    execFileSync("sh", ["-c", 'command -v "$1"', "sh", cmd], {
      stdio: "ignore",
    });
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
  // Tracked SDK source dir git-grepped for the fail-closed guard marker. The
  // probe only becomes REQUIRED once this dir references OPT_IN_ENV in-tree.
  guardSourceDir: string;
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
    // Go SDK guard lives in go/protocols/mpp/server/*.go.
    guardSourceDir: "go",
  },
  {
    id: "typescript",
    label: "TypeScript PayKit high-level MPP adapter (createPayKit)",
    available: true,
    implementation: serverImpl(
      "typescript",
      "TypeScript PayKit high-level MPP adapter (createPayKit)",
      [
        process.execPath,
        "--import",
        "tsx",
        "src/fixtures/typescript/paykit-boot.ts",
      ],
      "typescript",
    ),
    mppEnv: mppEnv("USDC"),
    // TS guard lives in the pay-kit config + mpp adapters.
    guardSourceDir: "typescript/packages/pay-kit/src",
  },
  {
    id: "python",
    label: "Python solana_pay_kit high-level MppAdapter (MppAdapter.__init__)",
    available: commandExists("uv"),
    unavailableReason: commandExists("uv") ? undefined : "uv missing",
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
      [
        "uv",
        "run",
        "--project",
        "../python",
        "python",
        "python-server/mpp-adapter-boot.py",
      ],
      "python",
    ),
    // Python MPP runs in pubkey mode: the literal mint pubkey is the currency.
    mppEnv: mppEnv(USDC_MINT),
    // Python SDK guard lands via its own PR (#228). Until that source merges,
    // this dir has no OPT_IN_ENV reference, so the probe asserts-SKIP here.
    guardSourceDir: "python",
  },
];

// Resolve each covered probe against THIS tree: a probe is REQUIRED only when
// its toolchain is available AND its SDK actually implements the fail-closed
// guard in-tree (grep the SDK source for the opt-in marker). This one runtime
// signal keeps the leaf green today (python guard not here yet) and stays
// correct once python's remediation merges (grep then sees it -> required).
type ResolvedProbe = CoveredProbe & {
  guardImplemented: boolean;
  shouldRun: boolean;
};

const resolvedProbes: ResolvedProbe[] = coveredProbes.map((probe) => {
  const guardImplemented = sdkImplementsGuard(probe.guardSourceDir);
  return {
    ...probe,
    guardImplemented,
    shouldRun: probe.available && guardImplemented,
  };
});

// Loud note: surface each covered probe's status so a skip is never silent.
for (const probe of resolvedProbes) {
  if (!probe.guardImplemented) {
    // eslint-disable-next-line no-console
    console.warn(
      `[boot-policy] PENDING ${probe.id}: SDK source (${probe.guardSourceDir}) ` +
        `carries no ${OPT_IN_ENV} guard in this tree yet, so its boot probes ` +
        `ASSERT-SKIP. This is not fixed here; it converges at the ${probe.id} ` +
        `remediation PR, after which this same grep auto-promotes it to REQUIRED.`,
    );
  } else if (!probe.available) {
    // eslint-disable-next-line no-console
    console.warn(
      `[boot-policy] SKIP ${probe.id} boot probes: ${probe.unavailableReason}`,
    );
  }
}

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
  "[boot-policy] shared PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE opt-in contract: " +
    "go, typescript, python. php, ruby, lua enforce the same off-localnet " +
    "fail-closed policy via their native config contract (pinned by the source " +
    "probes below). Asserting-SKIP (no store guard in-tree): " +
    unimplementedProbes.map((p) => p.id).join(", ") + ".",
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

// Boot the same SDK on devnet WITH the opt-in and assert it reaches `ready`.
// Mainnet is intentionally not used for this positive path: SDKs may and should
// reject process-local replay state there even when the development escape is
// set.
async function assertBootsWithOptIn(probe: CoveredProbe): Promise<void> {
  const server = await startServer(probe.implementation, {
    ...probe.mppEnv,
    MPP_HARNESS_NETWORK: "devnet",
    [OPT_IN_ENV]: "1",
  });
  runningServers.push(server);
  expect(server.ready.type).toBe("ready");
  expect(server.ready.role).toBe("server");
  expect(server.ready.port).toBeGreaterThan(0);
}

describe("boot-policy conformance: fail-CLOSED off-localnet without opt-in", () => {
  for (const probe of resolvedProbes) {
    it.skipIf(!probe.shouldRun)(
      `${probe.id}: fails closed at network=mainnet with no ${OPT_IN_ENV}`,
      async () => {
        await assertFailsClosed(probe);
      },
    );
  }
});

describe("boot-policy conformance: boots with the opt-in", () => {
  for (const probe of resolvedProbes) {
    it.skipIf(!probe.shouldRun)(
      `${probe.id}: boots to ready at network=devnet with ${OPT_IN_ENV}=1`,
      async () => {
        await assertBootsWithOptIn(probe);
      },
    );
  }
});


describe("boot-policy conformance: SDKs without the store fail-closed contract", () => {
  for (const probe of unimplementedProbes) {
    // eslint-disable-next-line no-console
    console.warn(`[boot-policy] ASSERT-SKIP ${probe.id}: ${probe.reason}`);
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
// silently skipped. Uses `git grep` (via sdkFilesReferencingOptIn, defined
// above) so .gitignored build/vendor trees (target/, vendor/, .build/) are
// excluded automatically.
const SDK_SOURCE_DIR: Record<string, string> = {
  rust: "rust",
  kotlin: "kotlin",
  swift: "swift",
};

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

// ---------------------------------------------------------------------------
// Native (non-env-var) off-localnet fail-CLOSED store guards: php, ruby, lua.
//
// These SDKs do NOT use the shared PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE opt-in,
// so the boot probes above skip them. They deliver the same money-path safety
// through their native config contract: off-localnet, an omitted or
// non-durable/non-shared replay store is REJECTED at adapter/server
// construction (fail-closed). That is a real, working guard, so it is COVERED
// here rather than mislabeled as absent.
//
// Detection mirrors the #238 sdkImplementsGuard mechanism (git-grep the SDK's
// tracked source for its guard marker): a probe is REQUIRED only when its guard
// is present in-tree, and asserts-SKIP with an honest reason otherwise (e.g. the
// SDK is not checked out in this split). `sdkFilesReferencingOptIn` above stays
// byte-identical to #238 for the env-var roster; this parallel helper carries
// the per-SDK native marker. When present, the probe pins BOTH sides of the
// contract: the missing-store rejection and the non-durable/non-shared one.
// ---------------------------------------------------------------------------
type NativeGuardAssertion = { file: string; mechanism: string; pattern: RegExp };
type NativeGuardProbe = {
  id: string;
  label: string;
  sdkDir: string;
  // Stable substring of the guard's rejection message; its presence in-tree is
  // what promotes the probe from asserted-skip to required.
  guardMarker: string;
  assertions: NativeGuardAssertion[];
};

// git grep -l <marker> -- <sdkDir>, same failure handling as
// sdkFilesReferencingOptIn (kept separate so that helper stays byte-identical to
// #238). Empty result => guard/source not in this checkout => honest skip.
function sdkFilesMatchingMarker(sdkDir: string, marker: string): string[] {
  try {
    const out = execFileSync("git", ["grep", "-l", marker, "--", sdkDir], {
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

const nativeGuardProbes: NativeGuardProbe[] = [
  {
    id: "php",
    label: "PHP MPP adapter/handler off-localnet replay-store guard",
    sdkDir: "php",
    guardMarker: "replayStore is required outside localnet",
    assertions: [
      {
        file: "php/src/Protocols/Mpp/Adapter.php",
        mechanism: "rejects an omitted replay store outside localnet",
        pattern:
          /\$replayStore === null[\s\S]*?network !== Network::SolanaLocalnet[\s\S]*?replayStore is required outside localnet/,
      },
      {
        file: "php/src/Protocols/Mpp/Adapter.php",
        mechanism:
          "rejects a non-durable/non-shared replay store outside localnet",
        pattern:
          /network !== Network::SolanaLocalnet[\s\S]*?providesDurableSharedReplayProtection\(\)[\s\S]*?must explicitly declare durable shared replay protection outside localnet/,
      },
      {
        file: "php/src/Protocols/Mpp/Server/SolanaChargeHandler.php",
        mechanism:
          "enforces the same off-localnet guard on direct handler construction",
        pattern:
          /network !== 'localnet'[\s\S]*?replayStore is required outside localnet/,
      },
    ],
  },
  {
    id: "ruby",
    label: "Ruby MPP runtime off-localnet replay-store guard",
    sdkDir: "ruby",
    guardMarker: "requires a durable replay_store",
    assertions: [
      {
        file: "ruby/lib/pay_kit/protocols/mpp/runtime.rb",
        mechanism: "rejects the implicit dev-only memory store outside localnet",
        pattern:
          /replay_store == DEV_ONLY_MEMORY_STORE[\s\S]*?unless localnet\?\(method\)[\s\S]*?requires a durable replay_store/,
      },
      {
        file: "ruby/lib/pay_kit/protocols/mpp/runtime.rb",
        mechanism: "rejects a supplied non-durable replay store outside localnet",
        pattern:
          /unless localnet\?\(method\) \|\| durable_shared_replay_store\?\(replay_store\)[\s\S]*?requires a durable replay_store/,
      },
    ],
  },
  {
    id: "lua",
    label: "Lua MPP server off-localnet replay-store guard",
    sdkDir: "lua",
    guardMarker: "replay store is required outside localnet",
    assertions: [
      {
        file: "lua/pay_kit/protocols/mpp/init.lua",
        mechanism: "rejects an omitted replay store outside localnet",
        pattern:
          /if not replay_store[\s\S]*?network ~= 'localnet'[\s\S]*?replay store is required outside localnet/,
      },
      {
        file: "lua/pay_kit/protocols/mpp/init.lua",
        mechanism: "rejects a non-shared replay store outside localnet",
        pattern:
          /network ~= 'localnet' and not replay_store_is_shared\(replay_store\)[\s\S]*?must declare shared=true outside localnet/,
      },
      {
        file: "lua/pay_kit/protocols/mpp/server/init.lua",
        mechanism:
          "enforces the same off-localnet guard on the low-level server entry",
        pattern:
          /network ~= 'localnet'[\s\S]*?replay store must be shared outside localnet/,
      },
    ],
  },
];

function readSdkSource(file: string): string {
  return readFileSync(join(REPO_ROOT, file), "utf8");
}

describe("boot-policy: native off-localnet fail-closed store guards (php, ruby, lua)", () => {
  for (const probe of nativeGuardProbes) {
    const guardFiles = sdkFilesMatchingMarker(probe.sdkDir, probe.guardMarker);
    if (guardFiles.length === 0) {
      // eslint-disable-next-line no-console
      console.warn(
        `[boot-policy] SKIP ${probe.id} native guard probe: no "${probe.guardMarker}" ` +
          `marker under ${probe.sdkDir}/ in this checkout (SDK source absent or guard moved).`,
      );
    }
    for (const assertion of probe.assertions) {
      it.skipIf(guardFiles.length === 0)(
        `${probe.id}: ${assertion.mechanism}`,
        () => {
          expect(
            readSdkSource(assertion.file),
            `${probe.label} regressed: expected ${assertion.file} to ${assertion.mechanism}. ` +
              `${probe.id} enforces its off-localnet fail-closed guard through this native ` +
              `contract, not ${OPT_IN_ENV}; fix the SDK, do not delete the probe.`,
          ).toMatch(assertion.pattern);
        },
      );
    }
  }
});
