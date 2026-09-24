import type { HarnessScenario } from "../contracts";

// Activation (subscribe + first charge in one transaction, with a same-tx
// SubscriptionAuthority init) followed by an access with the bearer proof.
// Each server adapter publishes its own on-chain Plan before it reports
// ready, so the settlement assertion is the payTo delta of one `amount`.
export const subscriptionScenarios: readonly HarnessScenario[] = [
  {
    id: "subscription-activate-access",
    intent: "subscription",
    network: "localnet",
    price: "0.01",
    amount: "10000",
    asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
    resourcePath: "/subscription",
    settlementHeader: "x-subscription-reference",
    expectedStatus: 200,
    clientIds: ["python-subscription"],
    serverIds: ["python", "rust-subscription"],
  },
] as const;
