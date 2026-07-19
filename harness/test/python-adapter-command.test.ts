import { describe, expect, it } from "vitest";
import { clientImplementations } from "../src/implementations";

describe("Python x402 adapter commands", () => {
  for (const id of ["python-x402", "python-x402-upto"]) {
    it(`${id} runs inside the frozen uv project environment`, () => {
      const implementation = clientImplementations.find((candidate) => candidate.id === id);
      expect(implementation).toBeDefined();
      expect(implementation?.command.slice(0, 5)).toEqual([
        "uv",
        "run",
        "--project",
        "../python",
        "python",
      ]);
    });
  }
});
