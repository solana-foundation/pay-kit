// Read the GitHub Actions workflows as data: every `run` step with its
// effective environment (workflow, job and step env merged). Shared by
// test/ci-coverage.test.ts.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { parse as parseYaml } from "yaml";

const here = dirname(fileURLToPath(import.meta.url));
export const WORKFLOWS_DIR = join(here, "..", "..", ".github", "workflows");

export type WorkflowStep = {
  origin: string; // "<file>#<job>/<step name>"
  run: string;
  env: Record<string, string>;
  // Set when the step's `env` is an expression such as `${{ matrix.env }}`
  // rather than a map; `env` is then empty.
  envExpression?: string;
};

type RawStep = { name?: string; run?: string; if?: string; env?: Record<string, unknown> | string };
type RawJob = {
  env?: Record<string, unknown>;
  steps?: RawStep[];
  strategy?: { matrix?: unknown };
};

/** A matrix entry of the conformance job, as `pkc plan --tier interop` emits it. */
export type PlannedShard = Record<string, string | boolean | number> & { sdk: string };

/** The matrix `pkc plan --tier interop --github-output` emits, from the committed plan. */
export function plannedMatrix(planFile = join(here, "..", "interop-plan.json")): PlannedShard[] {
  const plan = JSON.parse(readFileSync(planFile, "utf8")) as {
    shards: { id: string; offline: { vector: boolean; protocol: boolean; flow: boolean }; caseCount: number }[];
  };
  return plan.shards.map((s) => ({
    sdk: s.id,
    vector: s.offline.vector,
    protocol: s.offline.protocol,
    flow: s.offline.flow,
    interop: s.caseCount > 0,
  }));
}

// A job whose matrix comes from the conformance planner.
const PLANNED = /fromJSON\(\s*needs\.plan\.outputs\.matrix\s*\)/;

function expand(text: string, entry: PlannedShard): string {
  return text.replace(/\$\{\{\s*matrix\.([A-Za-z]+)\s*\}\}/g, (_, k: string) => String(entry[k]));
}

// `if: matrix.<flag>` (the only form the planned job uses); anything else is
// treated as satisfiable.
function enabled(condition: string | undefined, entry: PlannedShard): boolean {
  const m = condition?.trim().match(/^matrix\.([A-Za-z]+)$/);
  return m ? Boolean(entry[m[1]]) : true;
}

function stringEnv(env: Record<string, unknown> | string | undefined): Record<string, string> {
  // `env: ${{ matrix.env }}` is an expression, not a map; callers that need
  // matrix-driven steps (the charge matrix) model them separately.
  if (!env || typeof env === "string") return {};
  return Object.fromEntries(Object.entries(env).map(([k, v]) => [k, String(v)]));
}

export function workflowRunSteps(dir = WORKFLOWS_DIR): WorkflowStep[] {
  const steps: WorkflowStep[] = [];
  for (const file of readdirSync(dir).filter((f) => /\.ya?ml$/.test(f)).sort()) {
    const doc = parseYaml(readFileSync(join(dir, file), "utf8")) as {
      env?: Record<string, unknown>;
      jobs?: Record<string, RawJob>;
    };
    for (const [jobId, job] of Object.entries(doc.jobs ?? {})) {
      // A planned matrix job runs once per shard of the committed plan.
      const planned = typeof job.strategy?.matrix === "string" && PLANNED.test(job.strategy.matrix);
      const entries: (PlannedShard | undefined)[] = planned ? plannedMatrix() : [undefined];
      for (const entry of entries) {
        for (const [index, step] of (job.steps ?? []).entries()) {
          if (typeof step.run !== "string") continue;
          if (entry && !enabled(step.if, entry)) continue;
          const env = { ...stringEnv(doc.env), ...stringEnv(job.env), ...stringEnv(step.env) };
          steps.push({
            origin: `${file}#${jobId}${entry ? `[${entry.sdk}]` : ""}/${step.name ?? index}`,
            run: entry ? expand(step.run, entry) : step.run,
            env: entry ? Object.fromEntries(Object.entries(env).map(([k, v]) => [k, expand(v, entry)])) : env,
            ...(typeof step.env === "string" ? { envExpression: step.env.trim() } : {}),
          });
        }
      }
    }
  }
  return steps;
}

// The value of a `--testNamePattern "..."` / `-t "..."` flag, if any.
export function testNamePattern(run: string): string | undefined {
  const match = run.match(/(?:--testNamePattern|-t)[ =](?:"([^"]*)"|'([^']*)'|(\S+))/);
  return match ? (match[1] ?? match[2] ?? match[3]) : undefined;
}
