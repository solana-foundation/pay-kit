import type { InteropScenario } from "../contracts";

// Canonical x402 `exact` intent scenarios. The harness contract (env
// vars, ready/result JSON shapes, capabilities) mirrors the Rust spine
// (`rust/crates/x402/src/bin/interop_{client,server}.rs`). The matrix
// pairs each x402 client against each x402 server registered in
// `implementations.ts`; the default-matrix pair set is restricted in
// `test/x402-exact.e2e.test.ts` while the TS reference adapter ships
// without a full Solana signing path. Adding language adapters that
// carry a real PaymentProof expands the matrix.
//
// Reject codes (cross-server portability / replay / network mismatch)
// reuse the canonical L6 set declared in `canonical-codes.ts`; the
// matrix asserts each x402 server adapter classifies the failure
// to the same canonical snake_case code as every other adapter.
export const x402ExactScenarios: readonly InteropScenario[] = [
  {
    id: "x402-exact-basic",
    intent: "x402-exact",
    network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected",
    settlementHeader: "x-fixture-settlement",
    expectedStatus: 200,
  },
  {
    // Network mismatch: client signs against localnet but the challenge
    // requires devnet (or vice versa). Server must reject the credential
    // with canonical `wrong_network`.
    id: "x402-exact-network-mismatch",
    intent: "x402-exact",
    network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected/network-mismatch",
    settlementHeader: "x-fixture-settlement",
    expectedStatus: 402,
    expectedCode: "wrong_network",
    clientIds: ["ts-x402", "rust-x402"],
    serverIds: ["ts-x402", "rust-x402", "lua"],
  },
  {
    // Cross-route replay: credential issued for /protected/cheap is
    // re-submitted against /protected/expensive. Server must reject with
    // `charge_request_mismatch` because the credential's pinned route /
    // amount does not match the served route.
    id: "x402-exact-cross-route-replay",
    intent: "x402-exact",
    network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected/expensive",
    settlementHeader: "x-fixture-settlement",
    replaySource: {
      resourcePath: "/protected/cheap",
      price: "0.0005",
      amount: "500",
    },
    expectedStatus: 402,
    expectedCode: "charge_request_mismatch",
    clientIds: ["ts-x402"],
    // Lua omitted intentionally: the lua x402 server does full
    // settlement (cosign + broadcast), so it cannot accept ts-x402's
    // stub credential which carries no real Solana transaction. The
    // rust-x402 client drives the lua server end-to-end against
    // surfpool in the lua interop matrix step. Re-add lua here once
    // ts-x402 emits a typed PaymentProof.
    serverIds: ["ts-x402", "rust-x402"],
  },
  {
    // Cross-server credential portability. Client pays server A and
    // re-submits the same payment header to server B. B must reject with
    // canonical `challenge_verification_failed` because B's verifier
    // does not accept A's challenge issuance.
    id: "x402-exact-cross-server-portability",
    intent: "x402-exact",
    kind: "cross-server-portability",
    network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected",
    settlementHeader: "x-fixture-settlement",
    expectedStatus: 402,
    expectedCode: "challenge_verification_failed",
    // The portability runner parameterizes the client per pair via
    // `crossServerPairs[].clientId`. ts-stub pair uses the TS reference
    // client; real-settling pairs use rust-x402 which now echoes the
    // sent credential under `payment-signature-sent` so the runner can
    // replay it to server B.
    clientIds: ["ts-x402", "rust-x402"],
    serverIds: ["ts-x402", "rust-x402", "lua", "php"],
    crossServerPairs: [
      ["ts-x402", "ts-x402"],
      // Real-settling cross-server pairs. Server A settles a real
      // Solana tx; server B receives the captured credential, fails
      // its own HMAC challenge verification, and returns
      // `challenge_verification_failed`. Driven by the rust-x402
      // client (typed PaymentProof emitter).
      ["rust-x402", "php"],
      ["php", "rust-x402"],
      ["rust-x402", "lua"],
      ["lua", "rust-x402"],
      ["php", "lua"],
      ["lua", "php"],
    ],
  },
  {
    // Same-server idempotent resubmit. Client pays server A, then
    // re-submits the same payment header. Server must reject with
    // `signature_consumed`.
    id: "x402-exact-idempotent-resubmit",
    intent: "x402-exact",
    kind: "idempotent-resubmit",
    network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected",
    settlementHeader: "x-fixture-settlement",
    expectedStatus: 402,
    expectedCode: "signature_consumed",
    // ts-x402 client drives ts-x402 server (stub payload). rust-x402
    // client drives real-settling servers (php / lua / rust-x402) now
    // that it echoes the sent credential under `payment-signature-sent`.
    // The runner picks the client per server via `idempotentResubmitClients`.
    clientIds: ["ts-x402", "rust-x402"],
    serverIds: ["ts-x402", "rust-x402", "lua", "php"],
  },
] as const;
