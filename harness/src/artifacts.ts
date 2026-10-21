import { accessSync, constants, statSync } from "node:fs";
import { resolve } from "node:path";

// Native build metadata for the offline conformance runners. The interop
// payment adapters are built and resolved by `pkc adapters build` /
// `pkc run --tier interop` (rust/crates/conformance/src/interop/adapters.rs).

/** Compilers needed to produce portable conformance runner artifacts. */
export type NativeToolchain = "go" | "swift" | "kotlin";
/** Artifact role; only conformance runners are built here. */
export type AdapterRole = "conformance";
/** A distinct build target. Paths are harness-relative. */
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
  ids: string[],
  directory: string,
  product: string,
): NativeTarget {
  const key = `${toolchain}-conformance-${ids[0]}`;
  return {
    key, toolchain, role: "conformance", ids, directory, product,
    executable: `${key}/${toolchain === "kotlin" ? "bin/" : ""}${product}`,
  };
}

/** SDK-independent build metadata. */
export const nativeTargets: readonly NativeTarget[] = [
  target("swift", ["swift"], "../swift", "mpp-conformance"),
  target("kotlin", ["kotlin"], "kotlin-conformance", "mpp-kotlin-conformance"),
  target("go", ["go"], "../go/cmd/conformance", "paykit-conformance"),
];

// Source-run commands are deliberate exceptions, never inferred from missing
// native metadata.
const sourceTargets: readonly string[] = ["lua", "php", "python", "ruby", "typescript"];

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
    if (sourceTargets.includes(id)) return developerCommand;
    throw new Error(`Unclassified ${role} runner "${id}": HARNESS_PREBUILT_DIR forbids compiler fallback; declare native build metadata or an explicit source-run target.`);
  }
  const executable = resolve(prebuiltDirectory, entry.executable);
  try {
    if (!statSync(executable).isFile()) throw new Error("not a file");
    accessSync(executable, constants.X_OK);
  } catch (cause) {
    throw new Error(
      `Missing or non-executable prebuilt ${role} runner "${id}": ${executable}. Rebuild with build-adapters.ts; HARNESS_PREBUILT_DIR forbids compiler fallback.`,
      { cause },
    );
  }
  return [executable];
}
