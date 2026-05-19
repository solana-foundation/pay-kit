import { selectSolanaChargeChallenge } from './ChallengeSelection.js';
import { buildChargeTransaction, charge as charge_ } from './Charge.js';
import { session as session_ } from './Session.js';
import { buildSubscriptionActivationTransaction, subscription as subscription_ } from './Subscription.js';

/**
 * Creates a Solana `charge` method for usage on the client.
 *
 * Intercepts 402 responses, sends a Solana transaction to pay the challenge,
 * and retries with the transaction signature as credential automatically.
 *
 * @example
 * ```ts
 * import { Mppx, solana } from 'solana-mpp-sdk/client'
 *
 * const method = solana.charge({ signer })
 * const mppx = Mppx.create({ methods: [method] })
 *
 * const response = await mppx.fetch('https://api.example.com/paid-content')
 * ```
 */
export const solana: {
    (parameters: solana.Parameters): ReturnType<typeof charge_>;
    buildChargeTransaction: typeof buildChargeTransaction;
    buildSubscriptionActivationTransaction: typeof buildSubscriptionActivationTransaction;
    charge: typeof charge_;
    selectChargeChallenge: typeof selectSolanaChargeChallenge;
    session: typeof session_;
    subscription: typeof subscription_;
} = Object.assign((parameters: solana.Parameters) => charge_(parameters), {
    buildChargeTransaction,
    buildSubscriptionActivationTransaction,
    charge: charge_,
    selectChargeChallenge: selectSolanaChargeChallenge,
    session: session_,
    subscription: subscription_,
});

export declare namespace solana {
    type Parameters = charge_.Parameters;
    type SessionParameters = session_.Parameters;
    type SubscriptionParameters = subscription_.Parameters;
}
