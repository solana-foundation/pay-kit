/**
 * The "Musebook Unlimited" plan definition (see
 * `docs/musebook-subscription-plan.md`): $19.99/month, unlimited AI and
 * services, payable in USDC on Solana or in $CLAWD at the USD-equivalent
 * amount priced at charge time.
 */

/** $CLAWD mint (Solana mainnet). A classic SPL Token mint. */
export const CLAWD_MINT = '8cHzQHUS2s2h8TzCmfqPKYiM4dSt4roa3n7MyRLApump';

/** Plan price in whole USD cents — the single source of truth for pricing. */
export const PLAN_PRICE_USD_CENTS = 1999;

/** 19.99 USDC in base units (USDC: 6 decimals). */
export const PLAN_PRICE_USDC_BASE_UNITS = 19_990_000n;

/** Two price sources may disagree by at most this much before we refuse. */
const PRICE_TOLERANCE = 0.05;

/**
 * Read the $CLAWD USD price from Jupiter (primary) cross-checked against
 * DexScreener. Fail closed: no fresh price from either source, or a
 * disagreement beyond tolerance, throws instead of guessing — a
 * subscription charge is never priced off a stale or contested quote.
 */
export async function clawdUsdPrice(): Promise<number> {
    const [jupiter, dexscreener] = await Promise.allSettled([jupiterPrice(), dexscreenerPrice()]);
    const jup = jupiter.status === 'fulfilled' ? jupiter.value : undefined;
    const dex = dexscreener.status === 'fulfilled' ? dexscreener.value : undefined;
    if (jup !== undefined && dex !== undefined) {
        const drift = Math.abs(jup - dex) / Math.max(jup, dex);
        if (drift > PRICE_TOLERANCE) {
            throw new Error(`$CLAWD price sources disagree (jupiter ${jup}, dexscreener ${dex}); refusing to price`);
        }
        return jup;
    }
    const price = jup ?? dex;
    if (price === undefined || !(price > 0)) {
        throw new Error('$CLAWD price unavailable from Jupiter and DexScreener; refusing to price');
    }
    return price;
}

async function jupiterPrice(): Promise<number> {
    const response = await fetch(`https://api.jup.ag/price/v3?ids=${CLAWD_MINT}`);
    if (!response.ok) throw new Error(`jupiter price: HTTP ${response.status}`);
    const body = (await response.json()) as { data?: Record<string, { usdPrice?: number }> };
    const price = body.data?.[CLAWD_MINT]?.usdPrice;
    if (typeof price !== 'number' || !(price > 0)) throw new Error('jupiter price: no quote');
    return price;
}

async function dexscreenerPrice(): Promise<number> {
    const response = await fetch(`https://api.dexscreener.com/latest/dex/tokens/${CLAWD_MINT}`);
    if (!response.ok) throw new Error(`dexscreener price: HTTP ${response.status}`);
    const body = (await response.json()) as { pairs?: { priceUsd?: string }[] };
    const price = Number(body.pairs?.[0]?.priceUsd);
    if (!(price > 0)) throw new Error('dexscreener price: no quote');
    return price;
}

/**
 * USD-equivalent $CLAWD amount in base units for one monthly charge,
 * rounded up so the subscriber never underpays through rounding. The
 * token count is computed at charge time from a live price — it is never
 * hard-coded.
 */
export function clawdBaseUnitsForPlan(usdPrice: number, mintDecimals: number): bigint {
    const tokens = PLAN_PRICE_USD_CENTS / 100 / usdPrice;
    return BigInt(Math.ceil(tokens * 10 ** mintDecimals));
}
