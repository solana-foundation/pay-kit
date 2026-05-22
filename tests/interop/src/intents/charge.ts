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
 * Reserved for a future cross-SDK harness loop that asserts each
 * implementation's encoder rejects these inputs; today the per-language
 * rejection coverage lives inline in each SDK's own unit suite plus the
 * reference encoder check in `tests/interop/test/canonical-json.test.ts`.
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
] as const;
