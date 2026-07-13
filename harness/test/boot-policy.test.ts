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
//   2. With the opt-in (PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1) it boots to
//      `ready` — proving the opt-in is honored, not merely that boot is broken.
//
// Rust, PHP, Ruby, and Lua use different real contracts. Their source-level
// probes below assert the relevant capability declaration and the non-local
// rejection path rather than pretending that they implement this env-var API.
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
  },
  {
    id: "typescript",
    label: "TypeScript Pay Kit configure() server",
    available: commandExists("pnpm"),
    unavailableReason: commandExists("pnpm") ? undefined : "pnpm missing",
    implementation: serverImpl(
      "typescript",
      "TypeScript Pay Kit configure() server",
      [
        "pnpm",
        "exec",
        "node",
        "--import",
        "tsx",
        "src/fixtures/typescript/pay-kit-adapter-boot.ts",
      ],
      "typescript",
    ),
    mppEnv: mppEnv("USDC"),
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
  },
];

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

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");

type SourceAssertion = {
  file: string;
  mechanism: string;
  pattern: RegExp;
};

type SourceContractProbe = {
  id: "rust" | "php" | "ruby" | "lua";
  label: string;
  assertions: SourceAssertion[];
};

// These SDKs deliberately use their native configuration contracts rather than
// PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE. Each probe checks both sides of that
// contract: volatile stores explicitly identify as unsafe, and server setup
// rejects them (or a missing store) outside localnet.
const sourceContractProbes: SourceContractProbe[] = [
  {
    id: "rust",
    label: "Rust durable replay and explicit session-store contracts",
    assertions: [
      {
        file: "rust/crates/kit/src/core/store.rs",
        mechanism: "declares unspecified, ephemeral, and durable shared replay capabilities",
        pattern:
          /pub enum ReplayStoreCapability\s*\{[\s\S]*?Unspecified,[\s\S]*?Ephemeral,[\s\S]*?DurableShared,/,
      },
      {
        file: "rust/crates/kit/src/core/store.rs",
        mechanism: "maps only explicitly shared legacy stores to durable shared capability",
        pattern:
          /fn replay_store_capability\(&self\) -> ReplayStoreCapability\s*\{[\s\S]*?if self\.is_shared\(\)[\s\S]*?ReplayStoreCapability::DurableShared[\s\S]*?ReplayStoreCapability::Unspecified/,
      },
      {
        file: "rust/crates/kit/src/core/store.rs",
        mechanism: "marks the built-in memory replay store ephemeral",
        pattern:
          /impl Store for MemoryStore\s*\{\s*fn replay_store_capability\(&self\) -> ReplayStoreCapability\s*\{\s*ReplayStoreCapability::Ephemeral/,
      },
      {
        file: "rust/crates/kit/src/mpp/server/charge.rs",
        mechanism: "requires a durable shared replay store unless explicitly unsafe",
        pattern:
          /store\.replay_store_capability\(\) != ReplayStoreCapability::DurableShared[\s\S]*?&& !config\.allow_unsafe_memory_store/,
      },
      {
        file: "rust/crates/kit/src/mpp/server/charge.rs",
        mechanism: "permits memory fallback only through the explicit unsafe opt-in",
        pattern:
          /None if config\.allow_unsafe_memory_store\s*=>[\s\S]*?Arc::new\(MemoryStore::new\(\)\)[\s\S]*?None\s*=>[\s\S]*?atomic durable shared replay store is required/,
      },
      {
        file: "rust/crates/kit/src/mpp/server/session.rs",
        mechanism: "requires callers to supply a ChannelStore when constructing sessions",
        pattern:
          /pub struct SessionServer<S:\s*ChannelStore>[\s\S]*?pub fn new\(config: SessionConfig, store: S\) -> Self/,
      },
    ],
  },
  {
    id: "php",
    label: "PHP durable shared replay-store contract",
    assertions: [
      {
        file: "php/src/Store/ReplayStoreCapability.php",
        mechanism: "requires an explicit durable shared capability declaration",
        pattern:
          /interface ReplayStoreCapability[\s\S]*?function providesDurableSharedReplayProtection\(\): bool;/,
      },
      {
        file: "php/src/Store/MemoryStore.php",
        mechanism: "marks the built-in memory store as not durable and shared",
        pattern:
          /class MemoryStore implements [^{]*ReplayStoreCapability[\s\S]*?function providesDurableSharedReplayProtection\(\): bool[\s\S]*?return false;/,
      },
      {
        file: "php/src/Store/FileStore.php",
        mechanism: "does not misrepresent the single-host file store as shared",
        pattern:
          /function providesDurableSharedReplayProtection\(\): bool[\s\S]*?return false;/,
      },
      {
        file: "php/src/Protocols/Mpp/Adapter.php",
        mechanism: "rejects an absent MPP replay store without explicit unsafe opt-in",
        pattern:
          /if \(\$replayStore === null\)[\s\S]*?MPP requires an injected atomic durable\/shared replay store/,
      },
      {
        file: "php/src/Protocols/Mpp/Adapter.php",
        mechanism: "rejects a replay store without the durable shared capability",
        pattern:
          /!\$replayStore instanceof ReplayStoreCapability[\s\S]*?!\$replayStore->providesDurableSharedReplayProtection\(\)[\s\S]*?does not affirm durable\/shared capability/,
      },
      {
        file: "php/src/Protocols/Mpp/Server/SolanaChargeHandler.php",
        mechanism: "enforces the same shared-capability guard on direct handler construction",
        pattern:
          /!\$replayStore instanceof ReplayStoreCapability[\s\S]*?!\$replayStore->providesDurableSharedReplayProtection\(\)[\s\S]*?does not affirm durable\/shared capability/,
      },
    ],
  },
  {
    id: "ruby",
    label: "Ruby durable replay-store contract",
    assertions: [
      {
        file: "ruby/lib/pay_kit/protocols/mpp/store.rb",
        mechanism: "makes the base store capability opt out by default",
        pattern: /class Store[\s\S]*?def durable\?\s*\n\s*false/,
      },
      {
        file: "ruby/lib/pay_kit/protocols/mpp/store.rb",
        mechanism: "marks the built-in memory store non-durable",
        pattern: /class MemoryStore < Store[\s\S]*?def durable\?\s*\n\s*false/,
      },
      {
        file: "ruby/lib/pay_kit/protocols/mpp/store.rb",
        mechanism: "marks the file-backed store durable across process restarts",
        pattern: /class FileStore < Store[\s\S]*?def durable\?\s*\n\s*true/,
      },
      {
        file: "ruby/lib/pay_kit/protocols/mpp/runtime.rb",
        mechanism: "rejects an implicit memory store outside localnet",
        pattern:
          /if replay_store == DEV_ONLY_MEMORY_STORE[\s\S]*?unless localnet\?\(method\)[\s\S]*?requires a durable replay_store/,
      },
      {
        file: "ruby/lib/pay_kit/protocols/mpp/runtime.rb",
        mechanism: "rejects supplied stores that do not explicitly report durability",
        pattern:
          /unless localnet\?\(method\) \|\| durable_(?:shared_)?replay_store\?\(replay_store\)[\s\S]*?requires a durable replay_store/,
      },
      {
        file: "ruby/lib/pay_kit/protocols/mpp/runtime.rb",
        mechanism: "uses the store's durable? declaration rather than its class name",
        pattern: /store\.respond_to\?\(:durable\?\) && store\.durable\?/,
      },
    ],
  },
  {
    id: "lua",
    label: "Lua shared replay-store contract",
    assertions: [
      {
        file: "lua/pay_kit/protocols/mpp/store.lua",
        mechanism: "marks the process-local memory store as non-shared",
        pattern: /function MemoryStore:is_shared\(\)\s*\n\s*return false/,
      },
      {
        file: "lua/pay_kit/protocols/mpp/server/store_shared_dict.lua",
        mechanism: "marks the atomic ngx shared-dict store as shared",
        pattern: /function SharedDictStore:is_shared\(\)\s*\n\s*return true/,
      },
      {
        file: "lua/pay_kit/protocols/mpp/server/store_shared_dict.lua",
        mechanism: "fails closed when the shared dictionary cannot atomically reserve a replay key",
        pattern:
          /self\.dict:add\(key, json\.encode\(value\), self\.ttl_seconds\)[\s\S]*?if err == 'exists' then[\s\S]*?error\('shared dict put_if_absent failed:/,
      },
      {
        file: "lua/pay_kit/protocols/mpp/server/init.lua",
        mechanism: "rejects a missing replay store outside localnet",
        pattern:
          /if replay_store == nil then[\s\S]*?if network ~= 'localnet' then[\s\S]*?replay store is required outside localnet/,
      },
      {
        file: "lua/pay_kit/protocols/mpp/server/init.lua",
        mechanism: "rejects a non-shared replay store outside localnet",
        pattern:
          /if network ~= 'localnet' and not replay_store_is_shared\(replay_store\) then[\s\S]*?replay store must be shared outside localnet/,
      },
      {
        file: "lua/pay_kit/protocols/mpp/init.lua",
        mechanism: "passes the validated MPP replay store into both settlement layers",
        pattern:
          /replay_store\s*=\s*replay_store,[\s\S]*?store\s*=\s*replay_store,[\s\S]*?verify_payment\s*=\s*handler:as_callback\(\)/,
      },
    ],
  },
];

function readSdkSource(file: string): string {
  return readFileSync(join(REPO_ROOT, file), "utf8");
}

describe("boot-policy: native replay/session-store contracts", () => {
  for (const probe of sourceContractProbes) {
    for (const assertion of probe.assertions) {
      it(`${probe.id}: ${assertion.mechanism}`, () => {
        expect(
          readSdkSource(assertion.file),
          `${probe.label} regressed: expected ${assertion.file} to ${assertion.mechanism}. ` +
            "This SDK uses its native replay/session-store contract; do not replace " +
            `the assertion with ${OPT_IN_ENV} or an asserted skip.`,
        ).toMatch(assertion.pattern);
      });
    }
  }
});

type ClientOnlyExemption = {
  owner: string;
  reason: string;
  lastReviewed: string;
  removalCondition: string;
  evidenceFile: string;
};

// Kotlin and Swift ship only payment clients. They have no server boot or
// replay/session-store construction surface to probe. Keep that exception
// explicit and reviewable instead of encoding it as a permanent skipped test.
const clientOnlyExemptions: Record<"kotlin" | "swift", ClientOnlyExemption> = {
  kotlin: {
    owner: "Pay Kit Kotlin SDK maintainers",
    reason: "The shipped Kotlin package is documented as client-only.",
    lastReviewed: "2026-07-10",
    removalCondition:
      "Remove this exemption when Kotlin adds a server adapter or replay/session-store constructor.",
    evidenceFile: "kotlin/README.md",
  },
  swift: {
    owner: "Pay Kit Swift SDK maintainers",
    reason: "The shipped Swift package is documented as client-only.",
    lastReviewed: "2026-07-10",
    removalCondition:
      "Remove this exemption when Swift adds a server adapter or replay/session-store constructor.",
    evidenceFile: "swift/README.md",
  },
};

describe("boot-policy: explicit client-only exemptions", () => {
  for (const [id, exemption] of Object.entries(clientOnlyExemptions)) {
    it(`${id}: exemption metadata and client-only evidence stay current`, () => {
      expect(exemption.owner, `${id} exemption needs an owner`).not.toBe("");
      expect(exemption.reason, `${id} exemption needs a reason`).not.toBe("");
      expect(
        exemption.lastReviewed,
        `${id} exemption needs an ISO last-reviewed date`,
      ).toMatch(/^\d{4}-\d{2}-\d{2}$/);
      expect(
        exemption.removalCondition,
        `${id} exemption needs a removal condition`,
      ).not.toBe("");
      expect(
        readSdkSource(exemption.evidenceFile),
        `${id} is exempt only while ${exemption.evidenceFile} explicitly says it is client-only. ` +
          exemption.removalCondition,
      ).toMatch(/client-only/i);
    });
  }
});
