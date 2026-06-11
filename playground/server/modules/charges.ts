import type { Express, Request, Response as ExpressResponse, RequestHandler } from 'express'
import { type PayKitConfig, type Price, createPayKit, toSolanaNetwork, usd } from '@solana/pay-kit'
import { payment, requirePayment } from '@solana/pay-kit/express'
import { Mppx, solana } from '@solana/mpp/server'
import YahooFinance from 'yahoo-finance2'
import { logPayment, logTx, toWebRequest } from '../shared/utils.js'
import { USDC_DECIMALS, USDC_MINT } from '../shared/constants.js'

const yahoo = new YahooFinance({ suppressNotices: ['yahooSurvey'] })

const WEATHER: Record<string, { temperature: number; conditions: string; humidity: number }> = {
  'san-francisco': { temperature: 15, conditions: 'Foggy', humidity: 85 },
  'new-york': { temperature: 22, conditions: 'Partly Cloudy', humidity: 60 },
  'london': { temperature: 12, conditions: 'Rainy', humidity: 90 },
  'tokyo': { temperature: 26, conditions: 'Sunny', humidity: 55 },
  'paris': { temperature: 18, conditions: 'Overcast', humidity: 70 },
  'sydney': { temperature: 24, conditions: 'Clear', humidity: 45 },
  'berlin': { temperature: 10, conditions: 'Cloudy', humidity: 75 },
  'dubai': { temperature: 38, conditions: 'Sunny', humidity: 30 },
}

const PRODUCTS: Record<string, { name: string; price: Price; seller: string; description: string }> = {
  'sol-hoodie': {
    name: 'Solana Hoodie',
    price: usd('2.00'),
    seller: '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU',
    description: 'Premium Solana-branded hoodie',
  },
  'validator-mug': {
    name: 'Validator Mug',
    price: usd('1.00'),
    seller: '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU',
    description: 'Ceramic mug for node operators',
  },
  'nft-sticker-pack': {
    name: 'NFT Sticker Pack',
    price: usd('0.50'),
    seller: '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU',
    description: 'Holographic sticker collection',
  },
}

const PLATFORM_FEE_BPS = 500 // 5%
const REFERRAL_FEE_BPS = 200 // 2%

const FORTUNES = [
  'A beautiful, smart, and loving person will be coming into your life.',
  'A faithful friend is a strong defense.',
  'A golden egg of opportunity falls into your lap this month.',
  'All your hard work will soon pay off.',
  'Curiosity kills boredom. Nothing can kill curiosity.',
  'Every day in your life is a special occasion.',
  'Good news will come to you by mail.',
  'If you continually give, you will continually have.',
]

/** Percentage of a price in basis points, e.g. bps(usd('2.00'), 500) → usd('0.10'). */
function bps(price: Price, basisPoints: number): Price {
  const units = (price.baseUnits() * BigInt(basisPoints)) / 10_000n
  return usd(`${units / 1_000_000n}.${(units % 1_000_000n).toString().padStart(6, '0')}`)
}

function display(price: Price): string {
  return `${Number(price.amount).toFixed(2)} USDC`
}

/** Last path segment of the request URL — the express `:param` for our routes. */
function lastSegment(request: globalThis.Request): string {
  return decodeURIComponent(new URL(request.url).pathname.split('/').pop() ?? '')
}

/** Express 5 types route params as `string | string[]`; ours are single-valued. */
function param(value: string | string[] | undefined): string {
  return Array.isArray(value) ? (value[0] ?? '') : (value ?? '')
}

export function registerCharges(app: Express, config: PayKitConfig): void {
  const platform = config.operator.recipient

  const paykit = createPayKit(config, {
    pricing: {
      stockQuote: (request) => ({
        amount: usd('0.01'),
        description: `Stock quote: ${lastSegment(request)}`,
      }),
      stockSearch: (request) => ({
        amount: usd('0.01'),
        description: `Stock search: ${new URL(request.url).searchParams.get('q') ?? ''}`,
      }),
      stockHistory: (request) => ({
        amount: usd('0.05'),
        description: `Stock history: ${lastSegment(request)}`,
      }),
      weather: (request) => ({
        amount: usd('0.01'),
        description: `Weather for ${lastSegment(request)}`,
      }),
      marketplaceBuy: (request) => {
        const product = PRODUCTS[lastSegment(request)]! // validated before payment, below
        const referrer = new URL(request.url).searchParams.get('referrer')
        return {
          amount: product.price,
          payTo: product.seller,
          description: `Purchase: ${product.name}`,
          feeOnTop: {
            [platform]: bps(product.price, PLATFORM_FEE_BPS),
            ...(referrer ? { [referrer]: bps(product.price, REFERRAL_FEE_BPS) } : {}),
          },
        }
      },
    },
  })

  /** Log the settlement signature once a gated handler runs. */
  const logged =
    (handler: RequestHandler): RequestHandler =>
    (req, res, next) => {
      const tx = payment(req)?.transaction
      if (tx) logTx(req.path, tx)
      return handler(req, res, next)
    }

  // ── Stocks ──

  app.get(
    '/api/v1/stocks/quote/:symbol',
    requirePayment(paykit, 'stockQuote'),
    logged(async (req, res) => {
      try {
        res.json(await yahoo.quote(param(req.params.symbol)))
      } catch (err) {
        console.error('stocks/quote error:', err)
        res.status(500).json({ error: 'Failed to fetch quote' })
      }
    }),
  )

  const requireQuery = (name: string): RequestHandler => (req, res, next) => {
    if (typeof req.query[name] !== 'string' || !req.query[name]) {
      res.status(400).json({ error: `Missing ?${name}= parameter` })
      return
    }
    next()
  }

  app.get(
    '/api/v1/stocks/search',
    requireQuery('q'),
    requirePayment(paykit, 'stockSearch'),
    logged(async (req, res) => {
      try {
        const { quotes } = await yahoo.search(req.query.q as string)
        res.json(quotes)
      } catch (err) {
        console.error('stocks/search error:', err)
        res.status(500).json({ error: 'Failed to search' })
      }
    }),
  )

  const RANGE_TO_DAYS: Record<string, number> = { '1d': 1, '5d': 5, '1mo': 30, '3mo': 90, '6mo': 180, '1y': 365 }

  app.get(
    '/api/v1/stocks/history/:symbol',
    requirePayment(paykit, 'stockHistory'),
    logged(async (req, res) => {
      try {
        const days = RANGE_TO_DAYS[(req.query.range as string) ?? '1mo'] ?? 30
        const period1 = new Date(Date.now() - days * 86_400_000)
        res.json(await yahoo.chart(param(req.params.symbol), { period1 }))
      } catch (err) {
        console.error('stocks/history error:', err)
        res.status(500).json({ error: 'Failed to fetch history' })
      }
    }),
  )

  // ── Weather ──

  const cityKey = (value: string | string[] | undefined) => param(value).toLowerCase().replace(/\s+/g, '-')

  const requireKnownCity: RequestHandler = (req, res, next) => {
    if (!WEATHER[cityKey(req.params.city)]) {
      res.status(404).json({ error: `City not found. Available: ${Object.keys(WEATHER).join(', ')}` })
      return
    }
    next()
  }

  app.get(
    '/api/v1/weather/:city',
    requireKnownCity,
    requirePayment(paykit, 'weather'),
    logged((req, res) => {
      res.json({ city: param(req.params.city), ...WEATHER[cityKey(req.params.city)]! })
    }),
  )

  // ── Marketplace (multi-recipient fees) ──

  app.get('/api/v1/marketplace/products', (_req: Request, res: ExpressResponse) => {
    res.json(
      Object.entries(PRODUCTS).map(([id, p]) => ({
        id,
        name: p.name,
        description: p.description,
        price: display(p.price),
        priceRaw: p.price.baseUnits().toString(),
      })),
    )
  })

  const requireKnownProduct: RequestHandler = (req, res, next) => {
    if (!PRODUCTS[param(req.params.productId)]) {
      res.status(404).json({ error: 'Product not found' })
      return
    }
    next()
  }

  app.get(
    '/api/v1/marketplace/buy/:productId',
    requireKnownProduct,
    requirePayment(paykit, 'marketplaceBuy'),
    logged((req, res) => {
      const product = PRODUCTS[param(req.params.productId)]!
      const referrer = req.query.referrer as string | undefined
      const platformFee = bps(product.price, PLATFORM_FEE_BPS)
      const referralFee = referrer ? bps(product.price, REFERRAL_FEE_BPS) : undefined
      const total = referralFee
        ? product.price.plus(platformFee).plus(referralFee)
        : product.price.plus(platformFee)
      res.json({
        product: product.name,
        breakdown: {
          seller: display(product.price),
          platformFee: display(platformFee),
          ...(referralFee ? { referralFee: display(referralFee) } : {}),
          total: display(total),
        },
        status: 'purchased',
      })
    }),
  )

  // ── Fortune (payment link with HTML challenge) ──
  //
  // Stays on the protocol layer directly: `html: true` serves an interactive
  // payment page on 402, a protocol-level feature the pay-kit dispatcher
  // (which renders the cross-SDK JSON challenge body) deliberately does not
  // wrap. Dropping down a layer is the intended escape hatch.

  const fortuneMppx = Mppx.create({
    secretKey: config.mpp.challengeBindingSecret,
    methods: [
      solana.charge({
        recipient: config.operator.recipient,
        network: toSolanaNetwork(config.network),
        rpcUrl: config.rpcUrl,
        signer: config.operator.signer.signer,
        currency: USDC_MINT,
        decimals: USDC_DECIMALS,
        html: true,
      }),
    ],
  })

  app.get('/api/v1/fortune', async (req: Request, res: ExpressResponse) => {
    const result = await fortuneMppx.charge({
      amount: '10000',
      currency: USDC_MINT,
      description: 'Open a fortune cookie',
    })(toWebRequest(req))

    if (result.status === 402) {
      const challenge = result.challenge as globalThis.Response
      const headers = Object.fromEntries(challenge.headers)
      if (headers['content-type']?.includes('javascript')) {
        headers['service-worker-allowed'] = '/'
      }
      res.writeHead(challenge.status, headers)
      res.end(await challenge.text())
      return
    }

    const fortune = FORTUNES[Math.floor(Math.random() * FORTUNES.length)]
    const response = result.withReceipt(globalThis.Response.json({ fortune })) as globalThis.Response
    logPayment(req.path, response)
    res.writeHead(response.status, Object.fromEntries(response.headers))
    res.end(await response.text())
  })
}
