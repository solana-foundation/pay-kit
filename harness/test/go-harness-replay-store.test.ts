import { describe, expect, it } from "vitest";
import { serverImplementations } from "../src/implementations";

const replayStoreOptIn = "PAY_KIT_ALLOW_INMEMORY_REPLAY_STORE=1";

describe("Go harness replay-store wiring", () => {
  it("opts Go server launchers into their process-local replay store", () => {
    for (const id of ["go", "go-x402-upto"]) {
      const implementation = serverImplementations.find((entry) => entry.id === id);

      expect(implementation, `missing ${id} harness server`).toBeDefined();
      expect(implementation?.command.join(" ")).toContain(replayStoreOptIn);
    }
  });
});
