import type { HarnessScenario } from "../contracts";

// Canonical x402 `batch-settlement` intent scenarios. The adapter contract is
// the Rust spine (`rust/crates/harness-bins/src/bin/x402_harness_batch_{client,server}.rs`):
// the client opens one channel with a deposit, pays each later request with a
// cumulative voucher, tops up when the deposit runs out, then asks the server
// to redeem (claim + distribute) or sends a refund (`request_close`).
//
// Every flow runs 3 requests at `amount` each, so the channel escrows
// 3 x amount. Live settlement needs the payment-channels program on surfpool
// (a local .so or a mainnet fork) and pre-existing USDC accounts for the fee
// payer (the zero-share payee seat), payTo and the treasury owner.
//
// `server-signed` and `untrusted-fallback` are Python-only: the Rust bins
// sign client vouchers only. The server holds an operator key in both; only
// the server-signed client trusts it, so the untrusted client pays the dual
// accept's client-signed entry.
const base = {
  intent: "x402-batch-settlement",
  // localnet resolves USDC to the mainnet mint in every SDK, and the
  // payment-channels treasury owner is the mainnet constant on the fork.
  network: "localnet",
  price: "0.001",
  amount: "1000",
  asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
  resourcePath: "/batch",
  settlementHeader: "x-payment-settlement-signature",
  expectedStatus: 200,
} as const;

const pythonOnly = {
  clientIds: ["python-x402-batch"],
  serverIds: ["python-x402-batch"],
};

export const x402BatchSettlementScenarios: readonly HarnessScenario[] = [
  { ...base, id: "x402-batch-basic", batchFlow: "basic" },
  { ...base, id: "x402-batch-top-up", batchFlow: "top-up" },
  { ...base, id: "x402-batch-redeem", batchFlow: "redeem" },
  { ...base, id: "x402-batch-refund", batchFlow: "refund" },
  {
    ...base,
    ...pythonOnly,
    id: "x402-batch-server-signed",
    batchFlow: "server-signed",
    // The operator meters less than the per-request ceiling.
    actualAmount: "400",
  },
  {
    ...base,
    ...pythonOnly,
    id: "x402-batch-untrusted-fallback",
    batchFlow: "untrusted-fallback",
  },
];
