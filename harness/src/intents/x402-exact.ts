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
    serverIds: ["ts-x402", "rust-x402"],
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
    serverIds: ["ts-x402", "rust-x402"],
    // Cross-server portability requires the client adapter to expose the
    // credential it sent so the runner can replay it. The TS reference
    // client echoes `payment-signature-sent`; the Rust spine adapter does
    // not (and is preserved as the canonical settlement-signing path
    // rather than a credential-capturing one). Pairs that use the TS
    // client cover the asymmetric direction too: TS pays server A, then
    // replays the captured credential against server B.
    //
    // Symmetry: the TS-to-TS pair is the control case — two independent
    // TS reference server instances issue disjoint challenge id sets, so
    // server B rejects A's credential with `challenge_verification_failed`
    // through the same code path real adapters exercise. The TS-to-Rust
    // pair widens the assertion onto the rust spine (which classifies
    // the stub credential at the proof layer; the harness accepts any
    // canonical 402 reject token for that pair via its message
    // classifier). The reverse Rust-to-TS direction requires a credential
    // capture path that the Rust spine adapter intentionally does not
    // expose (settlement-signing only, not credential-echoing); the
    // canonical Rust→TS portability assertion lives in the live matrix
    // (`x402-exact.live.matrix.test.ts`) where a real signed transaction
    // is exchanged end-to-end.
    crossServerPairs: [
      ["ts-x402", "ts-x402"],
      ["ts-x402", "rust-x402"],
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
    // Driven by the TS client (the only one that echoes the sent
    // credential back to the harness). The first paid request must
    // reach 200, which constrains us to the TS reference server in
    // the default matrix because that server is what speaks the TS
    // client's stub payload. Rust server coverage of `signature_consumed`
    // lives in the Rust crate's own integration tests.
    clientIds: ["ts-x402"],
    serverIds: ["ts-x402"],
  },
] as const;
