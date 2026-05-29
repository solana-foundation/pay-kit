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
    // The pay_kit rust/python x402 servers stamp `extra.recentBlockhash` and
    // `extra.memo` (the resource path) into the offer; the basic happy path
    // therefore already exercises both the recentBlockhash-present and memo
    // bindings end-to-end. The token-2022 and ATA-create variants below add
    // the remaining shapes. These full-settlement scenarios only run against
    // full-settling client+server pairs (see the matrix `allowedPair`
    // restriction); the default x402 e2e matrix runs `x402-exact-basic` only.
    expectedStatus: 200,
  },
  {
    // Token-2022 mint. PYUSD on localnet/devnet is owned by the Token-2022
    // program; the harness deploys the mint under that program. The pay_kit
    // server advertises `extra.tokenProgram = TOKEN_2022_PROGRAM` and the
    // client builds the transferChecked against the Token-2022 program and
    // the Token-2022-derived ATA. Exercises the verifier's Rule 11 token
    // program bind on the Token-2022 branch.
    id: "x402-exact-token2022",
    intent: "x402-exact",
    network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    price: "0.001",
    amount: "1000",
    asset: "CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM",
    tokenProgram: "TOKEN_2022_PROGRAM",
    resourcePath: "/protected/token2022",
    settlementHeader: "x-fixture-settlement",
    expectedStatus: 200,
    clientIds: ["rust-x402", "python-x402"],
    serverIds: ["rust-x402", "python"],
  },
  {
    // ATA-create: the platform recipient's ATA is pre-created with a zero
    // balance before the test, so the settled transferChecked lands in an
    // already-existing destination ATA (the verifier accepts the bare
    // transferChecked; no client-side create-idempotent instruction needed).
    // This exercises the destination-ATA derivation + Rule 7 recipient match
    // against an on-chain account that exists at settle time.
    id: "x402-exact-ata-precreated",
    intent: "x402-exact",
    network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected/ata-precreated",
    settlementHeader: "x-fixture-settlement",
    preCreatePlatformAta: true,
    expectedStatus: 200,
    clientIds: ["rust-x402", "python-x402"],
    serverIds: ["rust-x402", "python"],
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
    clientIds: ["ts-x402"],
    // Only the TS reference client today implements the
    // capture/re-submit flow that e2e.test.ts's cross-server runner
    // expects (reads MPP_INTEROP_RESUBMIT_URL, emits firstStatus).
    // The rust-x402 client's `payment-signature-sent` echo (added in
    // this PR) is consumed by the alternate runner in
    // harness/test/cross-server-scenarios.test.ts which is gated
    // behind X402_INTEROP_CROSS_SERVER=1 and not run in this CI step.
    // Re-add rust-x402 to clientIds when the rust spine grows
    // resubmit-URL support so e2e.test.ts can drive it.
    serverIds: ["ts-x402"],
    crossServerPairs: [["ts-x402", "ts-x402"]],
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
    // Driven by the TS client only: e2e.test.ts's idempotent runner
    // requires the client to read MPP_INTEROP_RESUBMIT_URL and emit a
    // `firstStatus` field, which the rust spine client does not do
    // yet. Real-settling-server coverage of signature_consumed lives
    // in the rust crate's own integration tests until the rust client
    // grows resubmit support.
    clientIds: ["ts-x402"],
    serverIds: ["ts-x402"],
  },
] as const;
