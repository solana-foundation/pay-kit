import { accessSync, constants, statSync } from "node:fs";
import { resolve } from "node:path";

/** Compilers needed to produce portable harness adapter artifacts. */
export type NativeToolchain = "rust" | "go" | "swift" | "kotlin";
/** Artifact role; payment adapters and conformance runners have separate IDs. */
export type AdapterRole = "client" | "server" | "conformance";
/** A distinct build target, shared by all protocol aliases. Paths are harness-relative. */
export type NativeTarget = {
  readonly key: string;
  readonly toolchain: NativeToolchain;
  readonly role: AdapterRole;
  readonly ids: readonly string[];
  readonly directory: string;
  readonly product: string;
  readonly executable: string;
};

function target(
  toolchain: NativeToolchain,
  role: AdapterRole,
  ids: string[],
  directory: string,
  product: string,
): NativeTarget {
  const key = `${toolchain}-${role}-${ids[0]}`;
  return {
    key, toolchain, role, ids, directory, product,
    executable: `${key}/${toolchain === "kotlin" ? "bin/" : ""}${product}`,
  };
}

/** SDK-independent build metadata. Aliases intentionally share one target. */
export const nativeTargets: readonly NativeTarget[] = [
  ...(["client", "server"] as const).flatMap((role) =>
    [
      ["rust", "mpp_harness"],
      ["rust-x402", "x402_harness"],
      ["rust-x402-upto", "x402_harness_upto"],
    ].map(([id, prefix]) => target("rust", role, [id], "../rust", `${prefix}_${role}`))),
  target("go", "client", ["go", "go-x402", "go-x402-upto"], "go-client", "paykit-client"),
  target("go", "server", ["go", "go-x402-upto"], "go-server", "paykit-server"),
  target("swift", "client", ["swift"], "swift-client", "SwiftHarnessClient"),
  target("swift", "client", ["swift-x402"], "swift-x402-client", "SwiftX402Client"),
  target("swift", "client", ["swift-x402-upto"], "swift-x402-upto-client", "SwiftX402UptoClient"),
  ...["kotlin", "kotlin-x402", "kotlin-x402-upto"].map((id) =>
    target("kotlin", "client", [id], `${id}-client`, `mpp-${id}-harness-client`)),
  target("swift", "conformance", ["swift"], "../swift", "mpp-conformance"),
  target("kotlin", "conformance", ["kotlin"], "kotlin-conformance", "mpp-kotlin-conformance"),
  target("go", "conformance", ["go"], "../go/cmd/conformance", "paykit-conformance"),
];

// Source-run commands are deliberate exceptions, never inferred from missing
// native metadata.
const sourceTargets: Record<AdapterRole, readonly string[]> = {
  client: ["typescript", "ts-x402", "python-x402", "python-session", "python-x402-upto"],
  server: ["typescript", "ts-x402", "php", "ruby", "lua", "python", "ruby-x402-server", "python-x402-upto"],
  conformance: ["lua", "php", "python", "ruby", "typescript"],
};

/** Looks up the compiler and artifact layout without importing any SDK. */
export function getNativeTarget(role: AdapterRole, id: string): NativeTarget | undefined {
  return nativeTargets.find((entry) => entry.role === role && entry.ids.includes(id));
}

/** Resolve a native command in strict prebuilt mode; interpreted commands stay unchanged. */
export function resolveAdapterCommand(
  role: AdapterRole,
  id: string,
  developerCommand: string[],
  prebuiltDirectory = process.env.HARNESS_PREBUILT_DIR,
): string[] {
  if (!prebuiltDirectory) return developerCommand;
  const entry = getNativeTarget(role, id);
  if (!entry) {
    if (sourceTargets[role].includes(id)) return developerCommand;
    throw new Error(`Unclassified ${role} adapter "${id}": HARNESS_PREBUILT_DIR forbids compiler fallback; declare native build metadata or an explicit source-run target.`);
  }
  const executable = resolve(prebuiltDirectory, entry.executable);
  try {
    if (!statSync(executable).isFile()) throw new Error("not a file");
    accessSync(executable, constants.X_OK);
  } catch (cause) {
    throw new Error(
      `Missing or non-executable prebuilt ${role} adapter "${id}": ${executable}. Rebuild with build-adapters.ts; HARNESS_PREBUILT_DIR forbids compiler fallback.`,
      { cause },
    );
  }
  return [executable];
}
