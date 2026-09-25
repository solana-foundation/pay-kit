import { describe, expect, it } from "vitest";
import { clientImplementations, serverImplementations } from "../src/implementations";

const expectedPrefix = ["uv", "run", "--frozen", "--project", "../python", "python"];

describe("Python adapter commands", () => {
  for (const id of ["python-x402", "python-session", "python-x402-upto"]) {
    it(`client ${id} runs inside the frozen uv project environment`, () => {
      const implementation = clientImplementations.find((candidate) => candidate.id === id);
      expect(implementation).toBeDefined();
      expect(implementation?.command.slice(0, expectedPrefix.length)).toEqual(expectedPrefix);
    });
  }

  for (const id of ["python", "python-x402-upto"]) {
    it(`server ${id} runs inside the frozen uv project environment`, () => {
      const implementation = serverImplementations.find((candidate) => candidate.id === id);
      expect(implementation).toBeDefined();
      expect(implementation?.command.slice(0, expectedPrefix.length)).toEqual(expectedPrefix);
    });
  }
});
