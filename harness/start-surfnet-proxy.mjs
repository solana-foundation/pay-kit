import net from "node:net";
import { setTimeout as delay } from "node:timers/promises";

import { Surfnet } from "@solana/surfpool";

const rpcPort = Number(process.env.SURFPOOL_PROXY_RPC_PORT ?? 8899);
const wsPort = Number(process.env.SURFPOOL_PROXY_WS_PORT ?? 8900);
// Opt in to a mainnet fork by naming the programs to stream, so a test can run
// against a deployed program (e.g. the subscriptions program) instead of a
// local build. Offline (no programs named) stays the default.
const streamedPrograms = (process.env.SURFPOOL_STREAM_PROGRAMS ?? "")
  .split(",")
  .map((program) => program.trim())
  .filter(Boolean);
const surfnet =
  streamedPrograms.length === 0
    ? Surfnet.start()
    : Surfnet.startWithConfig({
        offline: false,
        remoteRpcUrl:
          process.env.SURFPOOL_DATASOURCE_RPC_URL?.trim() ||
          "https://api.mainnet-beta.solana.com",
      });
for (const program of streamedPrograms) surfnet.streamAccount(program);
const rpcTarget = new URL(surfnet.rpcUrl);
const wsTarget = new URL(surfnet.wsUrl);

const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";
const MINT_ACCOUNT_SIZE = 82;
const STABLECOIN_MINTS = [
  {
    mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    tokenProgram: TOKEN_PROGRAM,
  },
  {
    mint: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    tokenProgram: TOKEN_PROGRAM,
  },
  {
    mint: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
    tokenProgram: TOKEN_PROGRAM,
  },
  {
    mint: "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
    tokenProgram: TOKEN_PROGRAM,
  },
  {
    mint: "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
    tokenProgram: TOKEN_PROGRAM,
  },
  {
    mint: "CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH",
    tokenProgram: TOKEN_2022_PROGRAM,
  },
];

function createSplMintAccountData(decimals) {
  const data = new Uint8Array(MINT_ACCOUNT_SIZE);
  const view = new DataView(data.buffer);
  view.setBigUint64(36, 0n, true);
  data[44] = decimals;
  data[45] = 1;
  return data;
}

// A fork already serves the real mints; only an offline surfnet needs these.
if (streamedPrograms.length === 0) {
  for (const { mint, tokenProgram } of STABLECOIN_MINTS) {
    surfnet.setAccount(
      mint,
      1_461_600,
      createSplMintAccountData(6),
      tokenProgram,
    );
  }
}

function createProxyServer(target) {
  return net.createServer((inbound) => {
    const upstream = net.connect({
      host: target.hostname,
      port: Number(target.port),
    });

    inbound.pipe(upstream);
    upstream.pipe(inbound);

    inbound.on("error", () => upstream.destroy());
    upstream.on("error", () => inbound.destroy());
  });
}

const rpcServer = createProxyServer(rpcTarget);
const wsServer = createProxyServer(wsTarget);

await new Promise((resolve, reject) => {
  rpcServer.once("error", reject);
  rpcServer.listen({ host: "::", port: rpcPort }, () => {
    rpcServer.off("error", reject);
    resolve();
  });
});

await new Promise((resolve, reject) => {
  wsServer.once("error", reject);
  wsServer.listen({ host: "::", port: wsPort }, () => {
    wsServer.off("error", reject);
    resolve();
  });
});

// A streamed account resolves from the datasource a moment after start, so
// hold "ready" until every named program is executable on the fork.
async function streamedProgramsReady() {
  for (const program of streamedPrograms) {
    surfnet.drainEvents();
    const response = await fetch(`http://127.0.0.1:${rpcPort}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "getAccountInfo",
        params: [
          program,
          { encoding: "base64", dataSlice: { offset: 0, length: 0 } },
        ],
      }),
    });
    const body = await response.json();
    if (body?.result?.value?.executable !== true) return false;
  }
  return true;
}

const readyAttempts = streamedPrograms.length === 0 ? 50 : 300; // a fork streams its programs in
for (let attempt = 0; attempt < readyAttempts; attempt++) {
  try {
    const response = await fetch(`http://127.0.0.1:${rpcPort}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "getHealth",
        params: [],
      }),
    });
    const body = await response.json();
    if (body.result === "ok" && (await streamedProgramsReady())) {
      console.log(
        `Surfnet ready at http://127.0.0.1:${rpcPort} -> ${surfnet.rpcUrl}, ws://127.0.0.1:${wsPort} -> ${surfnet.wsUrl}`,
      );
      break;
    }
  } catch {
    // Keep waiting until the proxy and embedded RPC are accepting requests.
  }
  await delay(100);
}

process.on("SIGTERM", () => {
  rpcServer.close(() => {
    wsServer.close(() => process.exit(0));
  });
});

process.on("SIGINT", () => {
  rpcServer.close(() => {
    wsServer.close(() => process.exit(0));
  });
});

setInterval(() => {
  surfnet.drainEvents();
}, 1_000);
