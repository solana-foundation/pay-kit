// Read the GitHub Actions workflows as data: every `run` step with its
// effective environment (workflow, job and step env merged). Shared by
// test/ci-coverage.test.ts and interop-coverage.ts.

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
};

type RawStep = { name?: string; run?: string; env?: Record<string, unknown> | string };
type RawJob = { env?: Record<string, unknown>; steps?: RawStep[] };

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
      for (const [index, step] of (job.steps ?? []).entries()) {
        if (typeof step.run !== "string") continue;
        steps.push({
          origin: `${file}#${jobId}/${step.name ?? index}`,
          run: step.run,
          env: { ...stringEnv(doc.env), ...stringEnv(job.env), ...stringEnv(step.env) },
        });
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
