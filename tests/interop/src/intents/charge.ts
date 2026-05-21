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
] as const;
