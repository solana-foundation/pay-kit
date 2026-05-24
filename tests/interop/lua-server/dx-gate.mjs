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
console.log();
console.log("# MPP_FEE_PAYER_SECRET_KEY is intentionally unset: the only");
console.log("# pre-funded wallet in this fixture is the pay-CLI default,");
console.log("# which is already the SPL transfer source. Using it as the");
console.log("# fee payer too would make the same account both payer and");
console.log("# authority, which the verifier rejects (payment_invalid).");
console.log("# Verify-only mode is correct here; pay-CLI pre-cosigns.");
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
