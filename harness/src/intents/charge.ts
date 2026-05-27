import type { InteropScenario } from "../contracts";

export type CanonicalJsonVector = {
  id: string;
  value: Record<string, unknown>;
  canonicalJson: string;
  base64Url: string;
};

export const chargeCanonicalJsonVectors: readonly CanonicalJsonVector[] = [
  {
    id: "nested-object-key-order",
    value: {
      b: 2,
      a: [
        {
          b: true,
          a: false,
        },
      ],
    },
    canonicalJson: '{"a":[{"a":false,"b":true}],"b":2}',
    base64Url: "eyJhIjpbeyJhIjpmYWxzZSwiYiI6dHJ1ZX1dLCJiIjoyfQ",
  },
  {
    // RFC 8785 sec 3.2.3: UTF-16 code-unit ordering. 'f' (0x66) < 'é' (0xE9) < 'ƒ' (0x192).
    id: "utf16-key-ordering",
    value: { "é": 1, f: 2, "ƒ": 3 },
    canonicalJson: '{"f":2,"é":1,"ƒ":3}',
    base64Url: "eyJmIjoyLCLDqSI6MSwixpIiOjN9",
  },
  {
    // RFC 8785 sec 3.2.2.3: ES6 ToString. 1e21 must canonicalize as "1e+21".
    id: "number-1e21",
    value: { n: 1e21 },
    canonicalJson: '{"n":1e+21}',
    base64Url: "eyJuIjoxZSsyMX0",
  },
  {
    // 0.1 round-trips as "0.1" under ES6 ToString.
    id: "number-0_1",
    value: { n: 0.1 },
    canonicalJson: '{"n":0.1}',
    base64Url: "eyJuIjowLjF9",
  },
  {
    // Negative zero collapses to "0".
    id: "number-negative-zero",
    value: { n: -0 },
    canonicalJson: '{"n":0}',
    base64Url: "eyJuIjowfQ",
  },
  {
    // Codex P2 on PR #102. ES6 ToString shortest-roundtrip needs exactly 16 significant
    // digits for this value; encoders that stop at 15 digits and fall back to 17 emit
    // "333333333.33333331" which diverges from JS, Ruby, and Rust.
    id: "number-16-digit-shortest",
    value: { n: 333333333.33333329 },
    canonicalJson: '{"n":333333333.3333333}',
    base64Url: "eyJuIjozMzMzMzMzMzMuMzMzMzMzM30",
  },
];

/**
 * Vectors that every JCS implementation must reject (RFC 8785 sec 3.2.2).
 * Reserved for a future cross-SDK harness loop that asserts each
 * implementation's encoder rejects these inputs; today the per-language
 * rejection coverage lives inline in each SDK's own unit suite plus the
 * reference encoder check in `harness/test/canonical-json.test.ts`.
 * Kept here so the spec-mandated reject set has a single source of truth.
 */
export const chargeCanonicalJsonRejectVectors: readonly { id: string; reason: string }[] = [
  { id: "lone-surrogate", reason: "lone surrogate" },
  { id: "nan", reason: "NaN" },
  { id: "infinity", reason: "Infinity" },
];

export const chargeScenarios: readonly InteropScenario[] = [
  {
    id: "charge-basic",
    intent: "charge",
    network: "localnet",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected",
    settlementHeader: "x-fixture-settlement",
    expectedStatus: 200,
  },
  {
    id: "charge-split-ata",
    intent: "charge",
    network: "localnet",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected/split-ata",
    settlementHeader: "x-fixture-settlement",
    splits: [
      {
        recipientKey: "platform",
        amount: "250",
        ataCreationRequired: true,
        memo: "interop split",
      },
    ],
    expectedStatus: 200,
  },
  {
    // Push-mode end-to-end. The TS client signs, broadcasts, and
    // awaits confirmation on-chain via the surfpool RPC, then sends
    // only the signature as a `type=signature` credential. Each
    // server adapter re-fetches the on-chain transaction by signature
    // and re-runs its structural verifier against the settled artifact.
    // Push-mode B34: the server route is built WITHOUT
    // methodDetails.feePayer so the credential is not rejected by the
    // server-side fee payer guard (see charge.rs / SolanaChargeHandler).
    // Server fixtures honour MPP_INTEROP_PAYMENT_MODE=push by omitting
    // the fee payer signer when constructing the charge method.
    // Excluded: lua and python ship push support in their SDKs but do
    // not yet have an interop server fixture under harness/.
    id: "charge-push",
    intent: "charge",
    paymentMode: "push",
    network: "localnet",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected/push",
    settlementHeader: "x-fixture-settlement",
    expectedStatus: 200,
    clientIds: ["typescript"],
    serverIds: ["typescript", "rust", "php", "ruby"],
  },
  {
    id: "charge-network-mismatch",
    intent: "charge",
    network: "devnet",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected/network-mismatch",
    settlementHeader: "x-fixture-settlement",
    expectedStatus: 402,
    // G39: cross-SDK agreement on the canonical code for a network
    // mismatch failure class. Gated on serverIds = ts+rust because PHP,
    // Ruby, Lua, Go, Python interop servers have not yet wired the
    // canonical code injection at the 402 boundary. Each L6 follow-up
    // PR adds its server id here.
    expectedCode: "wrong_network",
    clientIds: ["typescript"],
    serverIds: ["typescript", "rust", "ruby"],
  },
  {
    id: "charge-cross-route-replay",
    intent: "charge",
    network: "localnet",
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
    // G39: cross-route replay surfaces as a pinned-field mismatch on
    // the credential. Canonical code is charge_request_mismatch in
    // every shipped SDK (the credential's claimed charge does not
    // match the route's expected charge).
    expectedCode: "charge_request_mismatch",
    clientIds: ["typescript"],
    serverIds: ["typescript", "rust", "ruby"],
  },
  {
    // Symbol mode: harness sends the literal string "USDC" as currency,
    // adapters must call their `Mints.resolve` (or equivalent) to get a
    // mint pubkey. The Ruby `MINTS["USDC"]["localnet"] = devnet mint` bug
    // would have surfaced here. The harness deploys the mint at the
    // expected pubkey so the resolved address must match for the
    // transferChecked assertion to pass.
    id: "charge-symbol-usdc-localnet",
    intent: "charge",
    network: "localnet",
    price: "0.001",
    amount: "1000",
    asset: "USDC",
    currencyMode: "symbol",
    // Surfpool localnet mirrors mainnet, so USDC on localnet resolves to
    // the mainnet USDC mint (EPjFWdd5...). Every SDK with a stablecoin
    // table must agree on this.
    expectedMint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    resourcePath: "/protected/symbol-usdc",
    settlementHeader: "x-fixture-settlement",
    expectedStatus: 200,
  },
  {
    // PYUSD mainnet mint, which every SDK (Ruby, PHP, Rust, TypeScript)
    // already classifies as Token-2022 via the built-in TOKEN_2022_SYMBOLS
    // list, so no SDK API change is required. The harness deploys this mint
    // under the Token-2022 program in beforeAll.
    id: "charge-token2022-split-ata",
    intent: "charge",
    network: "localnet",
    price: "0.001",
    amount: "1000",
    asset: "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo",
    resourcePath: "/protected/token2022-split-ata",
    settlementHeader: "x-fixture-settlement",
    tokenProgram: "TOKEN_2022_PROGRAM",
    splits: [
      {
        recipientKey: "platform",
        amount: "250",
        ataCreationRequired: true,
        memo: "interop token2022 split",
      },
    ],
    expectedStatus: 200,
  },
  {
    // G07. 9-decimal SPL mint. Harness deploys the mint with data[44]=9,
    // adapters receive MPP_INTEROP_DECIMALS=9 and must build the
    // challenge with `decimals: 9`. Assertion helper checks
    // transferChecked data[9] equals 9.
    id: "charge-decimals-9",
    intent: "charge",
    network: "localnet",
    price: "0.001",
    amount: "1000",
    asset: "KTHzp63RATgvE5RoRRqVbY7hMWntARQ6dPQhMtfY9oA",
    resourcePath: "/protected/decimals-9",
    settlementHeader: "x-fixture-settlement",
    decimals: 9,
    // The Rust interop server fixture computes amount as
    // `price * 10^decimals`, which diverges from the TS fixture's
    // env-driven amount. Restricting to TS plus env-driven adapters
    // keeps the assertion's primary delta aligned with the on-wire
    // amount. ruby reads MPP_INTEROP_AMOUNT directly
    // and threads MPP_INTEROP_DECIMALS into the SDK, so it inherits
    // the TS-compatible shape.
    serverIds: ["typescript", "ruby"],
    expectedStatus: 200,
  },
  {
    // G13. Idempotent ATA create instruction must still pass when the
    // platform recipient's ATA already exists. Harness pre-creates the
    // ATA with a zero balance via `surfnet.fundToken(platform, mint, 0,
    // programAddress)` before the test runs. Assertions otherwise
    // identical to charge-split-ata.
    id: "charge-split-ata-idempotent",
    intent: "charge",
    network: "localnet",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected/split-ata-idempotent",
    settlementHeader: "x-fixture-settlement",
    preCreatePlatformAta: true,
    splits: [
      {
        recipientKey: "platform",
        amount: "250",
        ataCreationRequired: true,
        memo: "interop split idempotent",
      },
    ],
    expectedStatus: 200,
  },
  {
    // G14. TypeScript client injects an over-cap compute budget
    // (limit 200_001, over the 200_000 server cap). Server must reject
    // with the compute-budget allowlist error. Rust/Ruby/PHP clients
    // cannot inject custom compute budget through the env-driven
    // harness path, so this scenario is TypeScript-client only. Every
    // active server is expected to enforce the cap.
    id: "charge-compute-budget-over-cap",
    intent: "charge",
    network: "localnet",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected/compute-budget-over-cap",
    settlementHeader: "x-fixture-settlement",
    clientIds: ["typescript"],
    clientComputeUnitLimit: 200_001,
    expectedStatus: 402,
    // G39 deferred: mppx (TS client) throws "Missing WWW-Authenticate
    // header" before exposing the server's 402 body to the harness, so
    // the synthetic client_rejected_credential body carries no server
    // code. Restoring code propagation through the client error path is
    // a separate follow-up; the harness still asserts the 402 status.
  },
  {
    // G27. Native SOL transfer path. Currency is the lowercase string
    // `sol`, decimals 9, asset kind sol, no SPL mint deploy. The
    // settled transaction must contain a System Program transfer
    // (discriminator u32 LE = 2) instead of an SPL transferChecked.
    // The harness funds the client with lamports via `surfnet.fundSol`.
    id: "charge-sol-native",
    intent: "charge",
    network: "localnet",
    price: "0.001",
    amount: "1000000",
    asset: "sol",
    resourcePath: "/protected/sol-native",
    settlementHeader: "x-fixture-settlement",
    assetKind: "sol",
    decimals: 9,
    // Only the TS server fixture currently threads currency="sol"
    // through the env. Rust/Ruby/PHP server fixtures default decimals
    // to 6 and pass MPP_INTEROP_MINT straight to the SDK.
    // ruby reads MPP_INTEROP_ASSET_KIND and maps "sol"
    // to currency="SOL" + MPP_INTEROP_DECIMALS=9, so it joins the
    // SOL-native pair list too.
    serverIds: ["typescript", "ruby"],
    expectedStatus: 200,
  },
  {
    // G28a. Splits > 8. Server (every SDK) must reject before
    // emitting a challenge. The TypeScript client is the only one that
    // can drive a 9-split request through the env-only path, so this
    // is typescript-client only. Splits are intentionally tiny so the
    // sum stays well under amount.
    id: "charge-splits-too-many",
    intent: "charge",
    network: "localnet",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected/splits-too-many",
    settlementHeader: "x-fixture-settlement",
    clientIds: ["typescript"],
    splits: [
      { recipientKey: "platform", amount: "1" },
      { recipientKey: "platform", amount: "1" },
      { recipientKey: "platform", amount: "1" },
      { recipientKey: "platform", amount: "1" },
      { recipientKey: "platform", amount: "1" },
      { recipientKey: "platform", amount: "1" },
      { recipientKey: "platform", amount: "1" },
      { recipientKey: "platform", amount: "1" },
      { recipientKey: "platform", amount: "1" },
    ],
    expectedStatus: 402,
    // G39 deferred: same as charge-compute-budget-over-cap above. The
    // client throws on missing WWW-Authenticate before the server's 402
    // body reaches the harness.
  },
  {
    // G28b. Single split whose amount equals total amount, so the
    // primary recipient delta is zero. Server (every SDK) must reject
    // because the primary amount must be strictly positive.
    id: "charge-splits-sum-equals-amount",
    intent: "charge",
    network: "localnet",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected/splits-sum-equals-amount",
    settlementHeader: "x-fixture-settlement",
    clientIds: ["typescript"],
    splits: [{ recipientKey: "platform", amount: "1000" }],
    expectedStatus: 402,
    // G39 deferred: G28b is a client-side pre-broadcast rejection, the
    // server is never reached so no server code is available. The
    // synthetic client_rejected_credential body is fixture-internal.
  },
  {
    // Cross-server credential portability. The client pays server A
    // and captures the Authorization header from the successful charge.
    // The same Authorization is then submitted to server B (different
    // language, different HMAC secret). Server B must reject because
    // the HMAC over the challenge id does not verify against B's
    // secret, surfacing as canonical `challenge_verification_failed`.
    // Only TS client is wired because the manual capture/re-submit
    // flow lives in the TS adapter. PHP/Ruby/Go servers are not in
    // any pair yet because their interop fixtures don't reject HMAC
    // mismatches with the canonical code; this is a tracked gap.
    id: "charge-cross-server-portability",
    intent: "charge",
    kind: "cross-server-portability",
    network: "localnet",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected",
    settlementHeader: "x-fixture-settlement",
    expectedStatus: 402,
    expectedCode: "challenge_verification_failed",
    clientIds: ["typescript"],
    serverIds: ["typescript", "rust", "ruby"],
    crossServerPairs: [
      ["typescript", "rust"],
      ["rust", "typescript"],
      ["typescript", "ruby"],
      ["ruby", "typescript"],
    ],
  },
  {
    // Same-server idempotent resubmit. Client pays server A, then
    // re-submits the same Authorization to server A. Canonical
    // behavior per the L4 replay store is to reject with
    // `signature_consumed`. In pull mode both the rust and TS SDKs
    // reserve the signature in the replay store *after* broadcast,
    // so a same-credential resubmit actually trips the RPC's
    // "already been processed" error before the store check fires.
    // Both signals are mapped to canonical signature_consumed at
    // the 402 boundary.
    id: "charge-idempotent-resubmit",
    intent: "charge",
    kind: "idempotent-resubmit",
    network: "localnet",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected",
    settlementHeader: "x-fixture-settlement",
    expectedStatus: 402,
    expectedCode: "signature_consumed",
    clientIds: ["typescript"],
    serverIds: ["typescript", "rust", "ruby"],
  },
] as const;
