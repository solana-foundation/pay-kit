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
];

/**
 * Vectors that every JCS implementation must reject (RFC 8785 sec 3.2.2).
 * Lone high surrogate U+D834 outside a surrogate pair.
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
    id: "charge-network-mismatch",
    intent: "charge",
    network: "devnet",
    price: "0.001",
    amount: "1000",
    asset: "4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU",
    resourcePath: "/protected/network-mismatch",
    settlementHeader: "x-fixture-settlement",
    expectedStatus: 402,
    clientIds: ["typescript"],
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
    clientIds: ["typescript"],
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
    // env-driven amount. Restricting to the TS server keeps the
    // assertion's primary delta aligned with the on-wire amount.
    // The Rust SDK itself is exercised via the client adapter against
    // the TS server in this scenario.
    serverIds: ["typescript"],
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
    // to 6 and pass MPP_INTEROP_MINT straight to the SDK, so for now
    // this scenario runs against the TS server only.
    serverIds: ["typescript"],
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
  },
] as const;
