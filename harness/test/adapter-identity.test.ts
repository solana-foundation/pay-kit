import { describe, expect, it } from "vitest";
import { startServer, runClient } from "../src/process";
import type { ImplementationDefinition } from "../src/implementations";

// P0 false-green killer coverage: an adapter that reports an
// implementation id different from the one the harness registered it
// under must fail loudly, not run silently under the wrong label.
describe("adapter identity validation", () => {
  const emitReady = (impl: string) =>
    `node -e 'process.stdout.write(JSON.stringify({type:"ready",implementation:"${impl}",role:"server",port:1})+"\\n")'`;

  it("rejects a server that reports the wrong implementation id", async () => {
    const impl: ImplementationDefinition = {
      id: "go-x402",
      label: "mislabeled x402 server",
      role: "server",
      // Reports "typescript" but reportsAs expects "go": this is exactly
      // the wrong-binary class the guard exists to catch.
      command: ["sh", "-c", emitReady("typescript")],
      enabled: true,
      intents: ["x402-exact"],
      reportsAs: "go",
    };

    await expect(startServer(impl)).rejects.toThrow(
      /Adapter identity mismatch: go-x402.*reported implementation="typescript".*expects "go"/s,
    );
  });

  it("accepts a server whose reported id matches reportsAs", async () => {
    const impl: ImplementationDefinition = {
      id: "ts-x402",
      label: "correctly labeled x402 server",
      role: "server",
      command: ["sh", "-c", emitReady("typescript")],
      enabled: true,
      intents: ["x402-exact"],
      reportsAs: "typescript",
    };

    const server = await startServer(impl);
    expect(server.ready.implementation).toBe("typescript");
    server.child.kill("SIGTERM");
  });

  it("rejects a client that reports the wrong implementation id", async () => {
    const impl: ImplementationDefinition = {
      id: "go",
      label: "mislabeled client",
      role: "client",
      command: [
        "sh",
        "-c",
        `node -e 'process.stdout.write(JSON.stringify({type:"result",implementation:"rust",role:"client",ok:true,status:200,responseHeaders:{},responseBody:{}})+"\\n")'`,
      ],
      enabled: true,
    };

    await expect(
      runClient(impl, "http://127.0.0.1:65535/x"),
    ).rejects.toThrow(/Adapter identity mismatch: go.*reported implementation="rust".*expects "go"/s);
  });
});
