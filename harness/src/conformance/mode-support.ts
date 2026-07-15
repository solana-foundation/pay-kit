import type {
  ConformanceVector,
  RunnerResult,
  VectorMode,
  VectorOutcome,
} from "./schema";
import type { ModeCapabilities } from "./runners";

export type ModeExecutionCounts = Map<string, number>;

const REQUIRED_STRICT_OUTCOMES = ["accept", "reject"] as const;

function executionKey(
  language: string,
  intent: ConformanceVector["intent"],
  mode: VectorMode,
  outcome: VectorOutcome,
): string {
  return `${language}:${intent}:${mode}:${outcome}`;
}

export function recordModeExecution(
  counts: ModeExecutionCounts,
  language: string,
  vector: Pick<ConformanceVector, "intent" | "mode">,
  outcome: RunnerResult["outcome"],
): void {
  if (outcome === "unsupported-mode") return;
  const key = executionKey(language, vector.intent, vector.mode, outcome);
  counts.set(key, (counts.get(key) ?? 0) + 1);
}

export function countModeExecutions(
  counts: ReadonlyMap<string, number>,
  language: string,
  intent: ConformanceVector["intent"],
  mode: VectorMode,
): number {
  return REQUIRED_STRICT_OUTCOMES.reduce(
    (total, outcome) =>
      total + (counts.get(executionKey(language, intent, mode, outcome)) ?? 0),
    0,
  );
}

export function assertStrictModeCoverage(
  language: string,
  strictModesByIntent: ModeCapabilities | undefined,
  counts: ReadonlyMap<string, number>,
): void {
  for (const [intent, modes] of Object.entries(strictModesByIntent ?? {})) {
    const declaredIntent = intent as ConformanceVector["intent"];
    for (const mode of modes ?? []) {
      for (const outcome of REQUIRED_STRICT_OUTCOMES) {
        if (
          (counts.get(executionKey(language, declaredIntent, mode, outcome)) ??
            0) === 0
        ) {
          throw new Error(
            `${language} strict mode ${intent}:${mode} executed no ${outcome} vector`,
          );
        }
      }
    }
  }
}

export function declaresModeSupport(
  modesByIntent: ModeCapabilities | undefined,
  vector: Pick<ConformanceVector, "intent" | "mode">,
): boolean {
  return modesByIntent?.[vector.intent]?.includes(vector.mode) ?? false;
}

export function isUnsupportedMode(result: RunnerResult): boolean {
  return (
    result.outcome === "unsupported-mode" ||
    (result.outcome === "reject" &&
      (result.error ?? "").startsWith("unsupported-mode"))
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
