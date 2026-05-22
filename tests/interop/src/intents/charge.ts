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
] as const;
