import type { Express, Request, Response as ExpressResponse } from 'express'
import { createSolanaRpc, type KeyPairSigner } from '@solana/kit'
import { Mppx, session, createMemorySessionStore, type SessionStore } from '@solana/mpp/server'
import { toWebRequest, logPayment } from '../shared/utils.js'
import { USDC_DECIMALS, USDC_MINT } from '../shared/constants.js'

const Web = globalThis

interface RegisterOptions {
  recipient: string
  network: string
  secretKey: string
  feePayerSigner: KeyPairSigner
  rpcUrl: string
}

const TOKEN_CHUNKS = [
  'A payment channel ',
  'lets a client and server ',
  'authorize many small ',
  'off-chain debits ',
  'against a single on-chain ',
  'deposit, settling the highest ',
  'cumulative voucher at close.',
]

/**
 * Register the two session-gated demo endpoints using the in-process
 * `session()` MPP method. Replaces the prior `pay` CLI sidecar reverse-proxy
 * with a fully in-process payment-channel session implementation.
 *
 * Routes:
 * - GET  /sessions/stream  — pay-per-chunk SSE, cap 1.00 USDC, 0.0001 USDC/chunk
 * - POST /sessions/stream  — voucher commits for the stream endpoint
 * - POST /sessions/compute — pay-per-call compute, cap 0.50 USDC, 0.005 USDC/call
 *                            (also accepts voucher commits)
 * - POST /__402/session/deliveries — SessionFetchClient's delivery reservation
 * - POST /__402/session/commit     — body-voucher commit variant of the above
 * - GET  /sessions/receipt/:channelId — settle-status poll for the UI
 */
export function registerSessions(app: Express, opts: RegisterOptions): void {
  const { recipient, network, secretKey, feePayerSigner, rpcUrl } = opts

  // Shared store across all session() methods so `/sessions/receipt/:channelId`
  // can read the settled signature whichever endpoint opened the channel.
  const sharedStore: SessionStore = createMemorySessionStore()

  // The session() idle-close watchdog and the `close` action only settle
  // on-chain when both a merchant signer AND a kit rpc client are configured.
  const rpc = createSolanaRpc(rpcUrl)

  // ── /sessions/stream — pay-per-chunk SSE ──
  const streamMethod = session({
    cap: 1_000_000n, // 1.00 USDC
    closeDelayMs: 2_000, // settle ~2s after the stream ends so the UI can poll quickly
    currency: USDC_MINT,
    decimals: USDC_DECIMALS,
    // Real on-chain opens: the browser pre-signs a payment-channel open
    // transaction (fee payer = operator) and the server completes the
    // signature, broadcasts, and waits for confirmation before metering.
    modes: ['pull'],
    network,
    openTxSubmitter: 'server',
    operator: feePayerSigner.address,
    paymentChannelPayerSigner: feePayerSigner,
    pricing: { perDelivery: 100n }, // 0.0001 USDC per chunk
    pullVoucherStrategy: 'clientVoucher',
    recipient,
    rpc,
    rpcUrl,
    signer: feePayerSigner,
    store: sharedStore,
  })

  const streamMppx = Mppx.create({
    methods: [streamMethod],
    secretKey,
  }) as unknown as MppxLike

  const streamHandler = streamMppx.session({
    cap: '1000000',
    currency: USDC_MINT,
    description: 'Metered token stream',
  })

  app.get('/sessions/stream', async (req: Request, res: ExpressResponse) => {
    const result = await streamHandler(toWebRequest(req))

    if (result.status === 402) {
      const challenge = result.challenge as globalThis.Response
      res.writeHead(challenge.status, Object.fromEntries(challenge.headers))
      res.end(await challenge.text())
      return
    }

    // Stream tokens as SSE; each chunk costs 0.0001 USDC.
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    })
    for (const chunk of TOKEN_CHUNKS) {
      res.write(`data: ${JSON.stringify({ chunk, cost: '100' })}\n\n`)
      await new Promise(r => setTimeout(r, 80))
    }
    res.write('data: [DONE]\n\n')
    res.end()
  })

  // Voucher commits: SessionFetchClient POSTs each commit back to the URL it
  // opened the session against, with the signed voucher in the Authorization
  // credential. The method's verify path applies it; the body is just an ack.
  app.post('/sessions/stream', async (req: Request, res: ExpressResponse) => {
    const result = await streamHandler(toWebRequest(req))
    if (result.status === 402) {
      const challenge = result.challenge as globalThis.Response
      res.writeHead(challenge.status, Object.fromEntries(challenge.headers))
      res.end(await challenge.text())
      return
    }
    await sendWebResponse(res, result.withReceipt(commitAck(req)) as globalThis.Response)
  })

  // ── /sessions/compute — pay-per-call compute ──
  const computeMethod = session({
    cap: 500_000n, // 0.50 USDC
    closeDelayMs: 2_000,
    currency: USDC_MINT,
    decimals: USDC_DECIMALS,
    modes: ['pull'],
    network,
    openTxSubmitter: 'server',
    operator: feePayerSigner.address,
    paymentChannelPayerSigner: feePayerSigner,
    pricing: { perDelivery: 5_000n }, // 0.005 USDC per call
    pullVoucherStrategy: 'clientVoucher',
    recipient,
    rpc,
    rpcUrl,
    signer: feePayerSigner,
    store: sharedStore,
  })

  const computeMppx = Mppx.create({
    methods: [computeMethod],
    secretKey,
  }) as unknown as MppxLike

  app.post('/sessions/compute', async (req: Request, res: ExpressResponse) => {
    const result = await computeMppx.session({
      cap: '500000',
      currency: USDC_MINT,
      description: 'Voucher-billed inference call',
    })(toWebRequest(req))

    if (result.status === 402) {
      const challenge = result.challenge as globalThis.Response
      res.writeHead(challenge.status, Object.fromEntries(challenge.headers))
      res.end(await challenge.text())
      return
    }

    const body = (req.body ?? {}) as { prompt?: string; deliveryId?: string }
    // Voucher commits arrive on the same URL the session was opened against
    // (see the /sessions/stream POST handler above) — ack instead of computing.
    if (body.deliveryId) {
      await sendWebResponse(res, result.withReceipt(commitAck(req)) as globalThis.Response)
      return
    }

    const prompt = body.prompt ?? ''
    const response = result.withReceipt(
      Web.Response.json({
        prompt,
        output: `Echo: ${prompt} (computed for 0.005 USDC)`,
        computedAt: new Date().toISOString(),
      }),
    ) as globalThis.Response
    logPayment(req.path, response)
    res.writeHead(response.status, Object.fromEntries(response.headers))
    res.end(await response.text())
  })

  // ── Side-channel metering routes ──
  // SessionFetchClient reserves capacity for each metered delivery at
  // /__402/session/deliveries before signing + committing the voucher.
  const sessionRoutes = session.routes({
    cap: 1_000_000n,
    currency: USDC_MINT,
    decimals: USDC_DECIMALS,
    network,
    operator: feePayerSigner.address,
    pricing: { perDelivery: 100n },
    recipient,
    store: sharedStore,
  })

  app.post('/__402/session/deliveries', async (req: Request, res: ExpressResponse) => {
    await sendWebResponse(res, await sessionRoutes.deliveries(toWebRequest(req)))
  })
  app.post('/__402/session/commit', async (req: Request, res: ExpressResponse) => {
    await sendWebResponse(res, await sessionRoutes.commit(toWebRequest(req)))
  })

  // Receipt poll endpoint: the UI hits this after the stream ends to learn
  // the on-chain settle signature. The idle-close watchdog fires
  // ~closeDelayMs after the last voucher and, with `signer` + `rpc`
  // configured above, attempts the on-chain settle-and-distribute.
  app.get('/sessions/receipt/:channelId', async (req: Request, res: ExpressResponse) => {
    const channelIdParam: unknown = req.params.channelId
    if (typeof channelIdParam !== 'string' || channelIdParam.length === 0) {
      return res.status(400).json({ error: 'invalid-channel-id' })
    }
    const state = await sharedStore.getChannel(channelIdParam)
    if (!state) return res.status(404).json({ error: 'channel-not-found' })
    return res.json({
      channelId: state.channelId,
      cumulative: state.cumulative.toString(),
      deposit: state.deposit.toString(),
      finalized: state.finalized,
      settledSignature: state.settledSignature ?? null,
    })
  })
}

/** Minimal JSON ack for a voucher commit — mirrors the CommitReceipt shape
 * the SessionFetchClient parses from the commit response. */
function commitAck(req: Request): globalThis.Response {
  const body = (req.body ?? {}) as { amount?: string; deliveryId?: string }
  return Web.Response.json({
    amount: body.amount ?? '0',
    deliveryId: body.deliveryId ?? '',
    status: 'committed',
  })
}

async function sendWebResponse(res: ExpressResponse, response: globalThis.Response): Promise<void> {
  res.writeHead(response.status, Object.fromEntries(response.headers))
  res.end(await response.text())
}

type MppxLike = {
  session: (params: { amount?: string; cap?: string; currency: string; description: string }) => (
    request: globalThis.Request,
  ) => Promise<{
    status: number
    challenge?: globalThis.Response
    withReceipt: (r: globalThis.Response) => globalThis.Response
  }>
}
