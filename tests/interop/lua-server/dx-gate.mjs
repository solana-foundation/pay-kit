// Manual DX gate helper for the Lua MPP simple-server.
//
// Spawns a Surfpool instance, exposes its RPC on localhost:8899, funds
// the pay-CLI default localnet wallet with SOL + USDC, and prints the
// environment variables a developer copy-pastes into the simple-server
// shell. The script blocks forever until SIGINT / SIGTERM so the
// surfpool RPC stays available for the manual DX run.
//
// Run:
//   cd tests/interop && node lua-server/dx-gate.mjs
// In another terminal, copy-paste the printed env vars and run:
//   cd lua && eval "$(luarocks --lua-version=5.1 --tree lua_modules path)"
//   <printed env> luajit examples/simple-server.lua
// In a third terminal:
//   pay curl -i http://127.0.0.1:4569/paid

import net from "node:net";
import { Surfnet } from "surfpool-sdk";

const PAY_WALLET = "7UZi5YiCCbrJDi1xKr3iRBds9xq3cq59Nd6vrNbP5Ex4";
const RECIPIENT = "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY";
const USDC_MAINNET = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
const TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

const rpcPort = Number(process.env.SURFPOOL_PROXY_RPC_PORT ?? 8899);
const surfnet = Surfnet.start();
const rpcTarget = new URL(surfnet.rpcUrl);

// Seed the USDC mint account so the SPL transferChecked has a valid mint
// reference. The 82-byte SPL mint data shape with decimals=6 is the
// canonical configuration the harness already uses.
const MINT_ACCOUNT_SIZE = 82;
const mintData = new Uint8Array(MINT_ACCOUNT_SIZE);
const view = new DataView(mintData.buffer);
view.setBigUint64(36, 0n, true);
mintData[44] = 6;
mintData[45] = 1;
surfnet.setAccount(USDC_MAINNET, 1461600, mintData, TOKEN_PROGRAM);

// Fund the pay-CLI default wallet with 5 SOL and 1000 USDC, and create the
// recipient's USDC ATA with a small balance so the transferChecked
// destination exists.
surfnet.fundSol(PAY_WALLET, 5_000_000_000);
surfnet.fundToken(PAY_WALLET, USDC_MAINNET, 1_000_000_000, TOKEN_PROGRAM);
surfnet.fundToken(RECIPIENT, USDC_MAINNET, 1000, TOKEN_PROGRAM);

function createProxy(target) {
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

const rpcServer = createProxy(rpcTarget);
await new Promise((resolve, reject) => {
  rpcServer.once("error", reject);
  rpcServer.listen({ host: "::", port: rpcPort }, () => {
    rpcServer.off("error", reject);
    resolve(undefined);
  });
});

const payer = Buffer.from(surfnet.payerSecretKey).toString("hex");
const _ = payer; // unused; the payer is the pre-funded Surfpool payer, not the cosigner

const fee_payer_secret_key = JSON.stringify(
  Array.from(Buffer.from(
    // pay-CLI default localnet wallet secret key, base58:
    // 5wvnBkodUeELUyLt5CCR8Nn7MG9w4v6fZxC6PnK5rcbFezrUXjvbQ9xiMaHmZQGmZar4D7XJESuPfXCnhT1ZJHgG
    // Decoded inline below to avoid pulling base58 here:
    [247,111,101,212,46,244,26,198,131,36,80,35,56,40,120,243,81,8,189,123,27,187,153,143,107,149,82,135,225,11,78,106,96,53,201,103,156,36,67,66,89,139,239,67,145,219,48,194,183,103,206,248,48,194,250,252,156,231,58,212,101,25,243,77],
  )),
);

console.log(`Surfpool ready at http://127.0.0.1:${rpcPort} -> ${surfnet.rpcUrl}`);
console.log(`Pay wallet funded: SOL + 1000 USDC`);
console.log(`Recipient ATA seeded: ${RECIPIENT} +0.001 USDC`);
console.log();
console.log("Copy into a second terminal:");
console.log();
console.log(`export MPP_RPC_URL=http://127.0.0.1:${rpcPort}`);
console.log(`export MPP_NETWORK=localnet`);
console.log(`export MPP_CURRENCY=USDC`);
console.log(`export MPP_PAY_TO=${RECIPIENT}`);
console.log(`export MPP_AMOUNT=0.001`);
console.log(`export MPP_FEE_PAYER_SECRET_KEY='${fee_payer_secret_key}'`);
console.log();

const shutdown = () => {
  rpcServer.close();
  process.exit(0);
};
process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

// Drain surfnet events on a 100 ms timer so the Rust worker keeps
// advancing; otherwise the surfpool instance stalls and the upstream
// RPC stops responding. Mirrors the pattern in
// `tests/interop/start-surfnet-proxy.mjs`.
setInterval(() => {
  try {
    surfnet.drainEvents();
  } catch (_err) {
    /* ignore */
  }
}, 100);
