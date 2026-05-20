import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export function resolveLuaBinary(): string | undefined {
  if (process.env.MPP_INTEROP_LUA_BIN) {
    return process.env.MPP_INTEROP_LUA_BIN;
  }

  const localBuild = join(homedir(), "lua-5.5.0", "src", "lua");
  if (existsSync(localBuild)) {
    return localBuild;
  }

  const pathLua = spawnSync("lua", ["-v"], { stdio: "ignore" });
  if (!pathLua.error) {
    return "lua";
  }

  return undefined;
}
