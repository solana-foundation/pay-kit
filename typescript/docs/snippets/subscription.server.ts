// Server-side subscription: gate a route with a `subscription` pricing gate.
// See ./README.md for the snippet:start/end convention.

import express from 'express';
import type { KeyPairSigner } from '@solana/kit';
import { createPayKit, subscription, usd, type AtomicSubscriptionReplayStore } from '@solana/pay-kit';

declare const signer: KeyPairSigner;
declare const RECIPIENT: string;
declare const PLAN_ID: string;
declare const PLAN_BUMP: number;
declare const PLAN_CREATED_AT: bigint;
declare const PLAN_ID_NUMERIC: bigint;
declare const PLAN_MERCHANT: string;
declare const replayStore: AtomicSubscriptionReplayStore;
declare const rpcUrl: string;

// snippet:start
const pay = await createPayKit({
    network: 'mainnet',
    operator: { recipient: RECIPIENT, signer },
    replayStore, // shared/durable store with an atomic reserve() operation
    pricing: {
        feed: subscription(usd('0.10'), {
            merchant: PLAN_MERCHANT,
            planBump: PLAN_BUMP,
            planCreatedAt: PLAN_CREATED_AT,
            planId: PLAN_ID, // on-chain Plan PDA, created ahead of time
            planIdNumeric: PLAN_ID_NUMERIC,
            puller: signer.address, // entity allowed to pull renewals
            periodUnit: 'day',
            periodCount: 1,
        }),
    },
    rpcUrl,
});

const app = express();

// First call activates the plan on-chain; `pay.express` gates the rest.
app.get('${PATH}', pay.express('feed'), (_req, res) => {
    res.json({
        items: [
            /* … */
        ],
    });
});
// snippet:end

void app;
