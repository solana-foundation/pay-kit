import { charge as charge_ } from './Charge.js';
import { subscription as subscription_ } from './Subscription.js';

/**
 * Creates Solana payment methods for usage on the server.
 *
 * @example
 * ```ts
 * import { Mppx, solana } from 'solana-mpp-sdk/server'
 *
 * const mppx = Mppx.create({
 *   methods: [solana.charge({ recipient: '...', network: 'devnet' })],
 * })
 * ```
 */
export const solana: {
    (parameters: solana.Parameters): ReturnType<typeof charge_>;
    charge: typeof charge_;
    subscription: typeof subscription_;
} = Object.assign((parameters: solana.Parameters) => solana.charge(parameters), {
    charge: charge_,
    subscription: subscription_,
});

export declare namespace solana {
    type Parameters = charge_.Parameters;
    type SubscriptionParameters = subscription_.Parameters;
}
