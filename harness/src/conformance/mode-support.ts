import type { ConformanceVector, RunnerResult } from "./schema";
import type { ModeCapabilities } from "./runners";

export function declaresModeSupport(
  modesByIntent: ModeCapabilities | undefined,
  vector: Pick<ConformanceVector, "intent" | "mode">,
): boolean {
  return modesByIntent?.[vector.intent]?.includes(vector.mode) ?? false;
}

export function isUnsupportedMode(result: RunnerResult): boolean {
  return (
    result.outcome === "unsupported-mode" ||
    (result.outcome === "reject" && (result.error ?? "").startsWith("unsupported-mode"))
  );
}

export function assertDeclaredModeWasExecuted(
  language: string,
  modesByIntent: ModeCapabilities | undefined,
  vector: Pick<ConformanceVector, "id" | "intent" | "mode">,
  result: RunnerResult,
): void {
  if (declaresModeSupport(modesByIntent, vector) && isUnsupportedMode(result)) {
    throw new Error(
      `${language} declares ${vector.intent}:${vector.mode} support but returned unsupported-mode for eligible vector ${vector.id}`,
    );
  }
}
