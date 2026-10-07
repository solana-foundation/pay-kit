import { appendFileSync } from "node:fs";
import { planChargeBuilds, planChargeMatrix } from "./src/ci-matrix";

const matrix = { include: planChargeMatrix() };
const buildMatrix = { include: planChargeBuilds(matrix.include) };
if (process.env.GITHUB_OUTPUT) {
  appendFileSync(process.env.GITHUB_OUTPUT,
    `matrix=${JSON.stringify(matrix)}\nbuild_matrix=${JSON.stringify(buildMatrix)}\n`);
}
console.log(JSON.stringify({ matrix, build_matrix: buildMatrix }, null, 2));
