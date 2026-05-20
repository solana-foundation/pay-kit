import { spawn } from "node:child_process";
import { describe, expect, it } from "vitest";

const LUA_BIN = process.env.MPP_INTEROP_LUA_BIN ?? "lua";

describe("Lua interop server bridge", () => {
  it("builds a route-bound charge challenge using the Lua SDK", async () => {
    const result = await runLuaBridge({
      command: "challenge",
      currency: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
      feePayer: true,
      feePayerKey: "9hxNoJgeiVownHt9uG7vt6so146STiLs9ewPiMsJP8vQ",
      network: "localnet",
      price: "0.001",
      recipient: "4ZmVSqZZj83WgksBgPWZ6ChLkswYCzagaEAtHfDv7vjX",
      secretKey: "mpp-interop-secret-key",
    });

    expect(result).toMatchObject({
      type: "challenge",
      request: {
        amount: "1000",
        currency: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
        methodDetails: {
          feePayer: true,
          feePayerKey: "9hxNoJgeiVownHt9uG7vt6so146STiLs9ewPiMsJP8vQ",
          network: "localnet",
        },
        recipient: "4ZmVSqZZj83WgksBgPWZ6ChLkswYCzagaEAtHfDv7vjX",
      },
    });
    expect(result.wwwAuthenticate).toMatch(/^Payment /);
  });
});

async function runLuaBridge(input: unknown): Promise<Record<string, unknown>> {
  const child = spawn(LUA_BIN, ["lua-server/bridge.lua"], {
    cwd: process.cwd(),
    stdio: ["pipe", "pipe", "pipe"],
  });

  let stdout = "";
  let stderr = "";
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    stdout += chunk;
  });
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });

  child.stdin.end(`${JSON.stringify(input)}\n`);
  const code = await new Promise<number | null>((resolve) => child.once("exit", resolve));
  if (code !== 0) {
    throw new Error(`Lua bridge exited with ${code}: ${stderr}${stdout}`);
  }

  return JSON.parse(stdout) as Record<string, unknown>;
}
