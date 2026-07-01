import type { HarnessScenario } from "../contracts";

// Canonical x402 `upto` intent scenarios. The harness contract mirrors
// the Rust spine (`rust/crates/x402/src/bin/harness_upto_{client,server}.rs`).
// The matrix pairs each x402 upto client against each x402 upto server
// registered in `implementations.ts`.
//
// `upto` is a payment-channel flow: the client opens a channel depositing
// the authorized ceiling; the server broadcasts the open, then settles
// the metered actual amount with a voucher after the handler runs.
// Live settlement requires the payment-channels program on surfpool.
export const x402UptoScenarios: readonly HarnessScenario[] = [
  {
    id: "x402-upto-basic",
    intent: "x402-upto",
    network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    price: "0.10",
    amount: "100000",
    actualAmount: "50000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/usage",
    settlementHeader: "x-payment-settlement-signature",
    expectedStatus: 200,
  },
  {
    id: "x402-upto-zero-actual",
    intent: "x402-upto",
    network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    price: "0.10",
    amount: "100000",
    actualAmount: "0",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/usage",
    settlementHeader: "x-payment-settlement-signature",
    expectedStatus: 200,
    // Protocol-level zero settlement is valid and should close the channel
    // with a refund. PayKit's public usage middleware intentionally treats
    // Charge(0) as fail-closed, so keep this scenario on the low-level Rust
    // x402 server while Go covers the same transaction shape in engine tests.
    serverIds: ["rust-x402-upto"],
  },
];
