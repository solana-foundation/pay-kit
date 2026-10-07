import { appendFileSync } from "node:fs";
import { planChargeMatrix } from "./src/ci-matrix";

const matrix = { include: planChargeMatrix() };
const json = JSON.stringify(matrix);
if (process.env.GITHUB_OUTPUT) {
  appendFileSync(process.env.GITHUB_OUTPUT, `matrix=${json}\n`);
}
console.log(JSON.stringify(matrix, null, 2));
