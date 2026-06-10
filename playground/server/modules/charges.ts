import type { Express, Request, Response as ExpressResponse } from 'express'
import type { KeyPairSigner } from '@solana/kit'
import { Mppx, solana } from '@solana/mpp/server'
import YahooFinance from 'yahoo-finance2'
import { toWebRequest, logPayment } from '../shared/utils.js'
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

const PRODUCTS: Record<string, { name: string; price: number; seller: string; description: string }> = {
  'sol-hoodie': {
    name: 'Solana Hoodie',
    price: 2_000_000,
    seller: '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU',
    description: 'Premium Solana-branded hoodie',
  },
  'validator-mug': {
    name: 'Validator Mug',
    price: 1_000_000,
    seller: '7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU',
    description: 'Ceramic mug for node operators',
  },
  'nft-sticker-pack': {
    name: 'NFT Sticker Pack',
    price: 500_000,
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

interface RegisterOptions {
  recipient: string
  network: string
  secretKey: string
  feePayerSigner: KeyPairSigner
  rpcUrl?: string
}

const Web = globalThis

function asString(v: unknown): string {
  return Array.isArray(v) ? String(v[0] ?? '') : String(v ?? '')
}

async function forward(res: ExpressResponse, response: globalThis.Response): Promise<void> {
  res.writeHead(response.status, Object.fromEntries(response.headers))
  res.end(await response.text())
}

export function registerCharges(app: Express, opts: RegisterOptions): void {
  const { recipient, network, secretKey, feePayerSigner, rpcUrl } = opts

  // ── Stocks ──
  const stocksMppx = Mppx.create({
    secretKey,
    methods: [
      solana.charge({
        recipient,
        network,
        ...(rpcUrl && { rpcUrl }),
        signer: feePayerSigner,
        currency: USDC_MINT,
        decimals: USDC_DECIMALS,
      }),
    ],
  })

  app.get('/api/v1/stocks/quote/:symbol', async (req: Request, res: ExpressResponse) => {
    const symbol = asString(req.params.symbol)
    const result = await stocksMppx.charge({
      amount: '10000',
      currency: USDC_MINT,
      description: `Stock quote: ${symbol}`,
    })(toWebRequest(req))

    if (result.status === 402) return forward(res, result.challenge as globalThis.Response)

    try {
      const quote = await yahoo.quote(symbol)
      const response = result.withReceipt(Web.Response.json(quote)) as globalThis.Response
      logPayment(req.path, response)
      await forward(res, response)
    } catch (err) {
      console.error('stocks/quote error:', err)
      res.status(500).json({ error: 'Failed to fetch quote' })
    }
  })

  app.get('/api/v1/stocks/search', async (req: Request, res: ExpressResponse) => {
    const q = req.query.q as string | undefined
    if (!q) {
      res.status(400).json({ error: 'Missing ?q= parameter' })
      return
    }
    const result = await stocksMppx.charge({
      amount: '10000',
      currency: USDC_MINT,
      description: `Stock search: ${q}`,
    })(toWebRequest(req))

    if (result.status === 402) return forward(res, result.challenge as globalThis.Response)

    try {
      const { quotes } = await yahoo.search(q)
      await forward(res, result.withReceipt(Web.Response.json(quotes)) as globalThis.Response)
    } catch (err) {
      console.error('stocks/search error:', err)
      res.status(500).json({ error: 'Failed to search' })
    }
  })

  app.get('/api/v1/stocks/history/:symbol', async (req: Request, res: ExpressResponse) => {
    const symbol = asString(req.params.symbol)
    const result = await stocksMppx.charge({
      amount: '50000',
      currency: USDC_MINT,
      description: `Stock history: ${symbol}`,
    })(toWebRequest(req))

    if (result.status === 402) return forward(res, result.challenge as globalThis.Response)

    try {
      const range = (req.query.range as string) || '1mo'
      const rangeToDays: Record<string, number> = {
        '1d': 1,
        '5d': 5,
        '1mo': 30,
        '3mo': 90,
        '6mo': 180,
        '1y': 365,
      }
      const days = rangeToDays[range] ?? 30
      const period1 = new Date(Date.now() - days * 86_400_000)
      const chart = await yahoo.chart(symbol, { period1 })
      await forward(res, result.withReceipt(Web.Response.json(chart)) as globalThis.Response)
    } catch (err) {
      console.error('stocks/history error:', err)
      res.status(500).json({ error: 'Failed to fetch history' })
    }
  })

  // ── Weather ──
  const weatherMppx = Mppx.create({
    secretKey,
    methods: [
      solana.charge({
        recipient,
        network,
        ...(rpcUrl && { rpcUrl }),
        signer: feePayerSigner,
        currency: USDC_MINT,
        decimals: USDC_DECIMALS,
      }),
    ],
  })

  app.get('/api/v1/weather/:city', async (req: Request, res: ExpressResponse) => {
    const rawCity = asString(req.params.city)
    const city = rawCity.toLowerCase().replace(/\s+/g, '-')
    const result = await weatherMppx.charge({
      amount: '10000',
      currency: USDC_MINT,
      description: `Weather for ${rawCity}`,
    })(toWebRequest(req))

    if (result.status === 402) return forward(res, result.challenge as globalThis.Response)

    const data = WEATHER[city]
    if (!data) {
      res.status(404).json({
        error: `City not found. Available: ${Object.keys(WEATHER).join(', ')}`,
      })
      return
    }
    await forward(
      res,
      result.withReceipt(Web.Response.json({ city: rawCity, ...data })) as globalThis.Response,
    )
  })

  // ── Marketplace (splits) ──
  app.get('/api/v1/marketplace/products', (_req: Request, res: ExpressResponse) => {
    res.json(
      Object.entries(PRODUCTS).map(([id, p]) => ({
        id,
        name: p.name,
        description: p.description,
        price: `${(p.price / 1_000_000).toFixed(2)} USDC`,
        priceRaw: String(p.price),
      })),
    )
  })

  app.get('/api/v1/marketplace/buy/:productId', async (req: Request, res: ExpressResponse) => {
    const productId = asString(req.params.productId)
    const product = PRODUCTS[productId]
    if (!product) {
      res.status(404).json({ error: 'Product not found' })
      return
    }
    const referrer = req.query.referrer as string | undefined
    const platformFee = Math.floor((product.price * PLATFORM_FEE_BPS) / 10_000)
    const referralFee = referrer ? Math.floor((product.price * REFERRAL_FEE_BPS) / 10_000) : 0
    const total = product.price + platformFee + referralFee

    const splits: Array<{ recipient: string; amount: string; memo?: string }> = [
      { recipient, amount: String(platformFee), memo: 'platform fee (5%)' },
    ]
    if (referrer) splits.push({ recipient: referrer, amount: String(referralFee), memo: 'referral (2%)' })

    const marketMppx = Mppx.create({
      secretKey,
      methods: [
        solana.charge({
          recipient: product.seller,
          network,
          ...(rpcUrl && { rpcUrl }),
          signer: feePayerSigner,
          currency: USDC_MINT,
          decimals: USDC_DECIMALS,
          splits,
        }),
      ],
    })

    const result = await marketMppx.charge({
      amount: String(total),
      currency: USDC_MINT,
      description: `Purchase: ${product.name}`,
    })(toWebRequest(req))

    if (result.status === 402) return forward(res, result.challenge as globalThis.Response)

    const response = result.withReceipt(
      Web.Response.json({
        product: product.name,
        breakdown: {
          seller: `${(product.price / 1_000_000).toFixed(2)} USDC`,
          platformFee: `${(platformFee / 1_000_000).toFixed(2)} USDC`,
          ...(referrer ? { referralFee: `${(referralFee / 1_000_000).toFixed(2)} USDC` } : {}),
          total: `${(total / 1_000_000).toFixed(2)} USDC`,
        },
        status: 'purchased',
      }),
    ) as globalThis.Response
    logPayment(req.path, response)
    await forward(res, response)
  })

  // ── Fortune (payment link with HTML challenge) ──
  const fortuneMppx = Mppx.create({
    secretKey,
    methods: [
      solana.charge({
        recipient,
        network,
        ...(rpcUrl && { rpcUrl }),
        signer: feePayerSigner,
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
    const response = result.withReceipt(Web.Response.json({ fortune })) as globalThis.Response
    logPayment(req.path, response)
    await forward(res, response)
  })
}
