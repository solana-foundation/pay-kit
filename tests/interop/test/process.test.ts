import { describe, expect, it } from "vitest";
import type { ImplementationDefinition } from "../src/implementations";
import { runClient, startServer } from "../src/process";

function adapter(command: string): ImplementationDefinition {
  return {
    id: "fixture",
    label: "Fixture adapter",
    role: "server",
    command: [process.execPath, "-e", command],
    enabled: true,
  };
}

describe("adapter process lifecycle", () => {
  it("cleans up server adapters that emit invalid readiness", async () => {
    await expect(
      startServer(
        adapter(`
          console.log(JSON.stringify({ type: "ready", implementation: "fixture", role: "server" }));
          setInterval(() => {}, 1000);
        `),
      ),
    ).rejects.toThrow("Unexpected server readiness payload");
  });

  it("cleans up client adapters that fail after emitting a result", async () => {
    await expect(
      runClient(
        adapter(`
          console.log(JSON.stringify({
            type: "result",
            implementation: "fixture",
            role: "client",
            ok: false,
            status: 0,
            responseHeaders: {},
            responseBody: {}
          }));
          process.exit(2);
        `),
        "http://127.0.0.1:1/protected",
      ),
    ).rejects.toThrow("Client adapter exited with code 2");
  });
});
