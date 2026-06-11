// Vendored from tempoxyz/mpp-tools `conformance/flows/compliance-server.ts`
// (commit b15fea4ee3f12da7ece735dc778ad84102af679c, MIT). Do not hand-edit
// beyond the deviations below; see README.md in this directory.
//
// Deviations from upstream (exhaustive):
//   1. The dynamic JSON import of MPP_FLOW_CASES uses `with: { type: 'json' }`
//      instead of upstream's `assert: { type: 'json' }`. Node >= 23 removed
//      the legacy `assert` import-assertion keyword, and the harness runs on
//      node >= 20 (node 24 locally). Semantics are identical.
import http from 'node:http'
import { createHash } from 'node:crypto'
import { pathToFileURL } from 'node:url'
import { Challenge, Credential, Method, Receipt, z } from 'mppx'
import * as Server from 'mppx/server'

type ProblemDetails = {
  type: string
  title: string
  status: number
}

type FlowCase = {
  name: string
  path: string
  request?: {
    amount: string
    currency: string
    recipient: string
    expires: string
    [key: string]: unknown
  }
  payload?: {
    type: 'transaction'
    signature: string
    [key: string]: unknown
  }
  expected_signature?: string
  receipt?: {
    status: 'success'
    reference: string
  }
  body?: string
  retry_body?: string
  initial_query?: string
  retry_query?: string
  bind_request_resource?: boolean
  check_expires?: boolean
  accept_payment?: string
  idempotency_key?: string
  check_cache_headers?: boolean
  concurrent_replay?: boolean
  digest_binding?: boolean
  discovery?: boolean
  json_rpc?: boolean
  expect_retry_after?: string
  expect_problem_details?: ProblemDetails
  fail_verification?: boolean
  force_status?: number
  http_method?: string
  invalid_challenge_id?: boolean
  invalid_www_authenticate?: boolean
  omit_challenge_expires?: boolean
  omit_receipt?: boolean
  mismatch_request?: boolean
  no_payment?: boolean
  skip_authorization?: boolean
  verify_body_preserved?: boolean
}

const secretKey = 'conformance-secret'
const realm = 'conformance'
const port = Number(process.env.MPP_FLOW_PORT ?? 43999)
const flowPath = process.env.MPP_FLOW_CASES

if (!flowPath) {
  console.error('Missing MPP_FLOW_CASES')
  process.exit(1)
}

// Deviation 1 (see header): `with` instead of upstream's removed `assert`.
const flowFile = await import(pathToFileURL(flowPath).href, { with: { type: 'json' } }).catch(
  (err) => {
    console.error('Failed to load flow cases:', err)
    process.exit(1)
  },
)

const cases = (flowFile as { default: { cases: FlowCase[] } }).default.cases
const caseByPath = new Map(cases.map((entry) => [entry.path, entry]))
const acceptPaymentByPath = new Map<string, string | null>()
const sideEffectsByKey = new Map<string, number>()
const seenAuthorization = new Set<string>()

const baseMethod = Method.from({
  name: 'tempo',
  intent: 'charge',
  schema: {
    credential: {
      payload: z.object({
        type: z.literal('transaction'),
        signature: z.string(),
      }),
    },
    request: z.object({
      amount: z.string(),
      currency: z.string(),
      recipient: z.string(),
      expires: z.string(),
      resource: z.optional(z.string()),
    }),
  },
})

const method = Method.toServer(baseMethod, {
  async verify({ credential, envelope }) {
    const path = envelope?.capturedRequest.url.pathname
    const flowCase = path ? caseByPath.get(path) : undefined
    if (!flowCase) throw new Error('Unknown flow case')
    if (flowCase.fail_verification) throw new Error('verification failed')
    if (flowCase.check_expires && flowCase.request?.expires) {
      if (new Date(flowCase.request.expires) < new Date())
        throw new Error('request expired')
    }

    const payload = credential.payload as { type: string; signature?: string }
    const signature = payload.signature ?? ''
    if (flowCase.expected_signature && signature !== flowCase.expected_signature)
      throw new Error(`signature mismatch: ${signature}`)

    const receiptConfig = flowCase.receipt ?? { status: 'success', reference: 'ref-default' }
    return Receipt.from({
      method: 'tempo',
      status: receiptConfig.status,
      reference: receiptConfig.reference,
      timestamp: '2026-01-01T00:00:00Z',
    })
  },
})

const mpp = Server.Mppx.create({
  methods: [method],
  realm,
  secretKey,
})

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = []
    req.on('data', (chunk: Buffer) => chunks.push(chunk))
    req.on('end', () => resolve(Buffer.concat(chunks).toString()))
  })
}

function sendProblemDetails(
  res: http.ServerResponse,
  problem: ProblemDetails,
  detail: string,
  headers?: Record<string, string>,
): void {
  const body = JSON.stringify({
    type: problem.type,
    title: problem.title,
    status: problem.status,
    detail,
  })
  const allHeaders: Record<string, string> = {
    'Content-Type': 'application/problem+json',
    ...headers,
  }
  res.writeHead(problem.status, allHeaders)
  res.end(body)
}

function paymentDigest(body: string): string {
  return `sha-256=:${createHash('sha256').update(body).digest('base64')}:`
}

function requestForFlowCase(flowCase: FlowCase, url: URL): FlowCase['request'] {
  const request = {
    ...(flowCase.request ?? {
      amount: '1',
      currency: 'USD',
      recipient: 'merchant',
      expires: '2099-01-01T00:00:00Z',
    }),
  }
  if (flowCase.bind_request_resource) request.resource = `${url.pathname}${url.search}`
  return request
}

function flowChallenge(
  flowCase: FlowCase,
  extra?: Partial<Challenge.Challenge>,
  request = flowCase.request ?? {
    amount: '1',
    currency: 'USD',
    recipient: 'merchant',
    expires: '2099-01-01T00:00:00Z',
  },
): Challenge.Challenge {
  return {
    id: `${flowCase.name}-challenge`,
    realm,
    method: 'tempo',
    intent: 'charge',
    request,
    ...extra,
  }
}

function sendChallenge(res: http.ServerResponse, challenge: Challenge.Challenge): void {
  res.writeHead(402, {
    'WWW-Authenticate': Challenge.serialize(challenge),
    'Cache-Control': 'no-store',
  })
  res.end()
}

function discoveryDocument(): Record<string, unknown> {
  return {
    openapi: '3.1.0',
    info: { title: 'Conformance Service', version: '1.0.0' },
    'x-service-info': {
      categories: ['testing'],
      docs: { homepage: 'https://paymentauth.org' },
    },
    paths: {
      '/charge/success': {
        get: {
          responses: {
            '200': { description: 'OK' },
            '402': { description: 'Payment Required' },
          },
          'x-payment-info': {
            offers: [
              { method: 'tempo', intent: 'charge', amount: '1000', currency: 'USD' },
              { method: 'tempo', intent: 'charge', amount: null, currency: 'USD' },
            ],
          },
        },
      },
    },
  }
}

function sendJsonRpc(res: http.ServerResponse, body: unknown): void {
  res.writeHead(200, { 'Content-Type': 'application/json' })
  res.end(JSON.stringify(body))
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
  const flowCase = caseByPath.get(url.pathname)

  if (!flowCase) {
    res.statusCode = 404
    res.end('not found')
    return
  }

  if (flowCase.discovery) {
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    })
    res.end(JSON.stringify(discoveryDocument()))
    return
  }

  if (flowCase.json_rpc) {
    const raw = await readBody(req)
    const message = raw ? JSON.parse(raw) : {}
    const credential = message?._meta?.['org.paymentauth/credential']
    if (!credential) {
      sendJsonRpc(res, {
        jsonrpc: '2.0',
        id: message.id,
        error: {
          code: -32042,
          message: 'Payment required',
          data: { challenges: [flowChallenge(flowCase)] },
        },
      })
      return
    }
    sendJsonRpc(res, {
      jsonrpc: '2.0',
      id: message.id,
      result: {
        content: [{ type: 'text', text: 'paid' }],
        _meta: {
          'org.paymentauth/receipt': {
            status: 'success',
            method: 'tempo',
            timestamp: '2026-01-01T00:00:00Z',
            challengeId: credential.challenge.id,
            reference: 'json-rpc-ref',
          },
        },
      },
    })
    return
  }

  if (flowCase.force_status) {
    res.statusCode = flowCase.force_status
    res.end('forced status')
    return
  }

  if (flowCase.no_payment) {
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ ok: true, name: flowCase.name }))
    return
  }

  // Read request body for POST flows
  const requestBody = req.method === 'POST' ? await readBody(req) : undefined
  if (!req.headers.authorization) acceptPaymentByPath.set(url.pathname, req.headers['accept-payment'] ?? null)
  if (flowCase.concurrent_replay && req.headers.authorization) {
    const authorization = `${req.headers['x-flow-client'] ?? 'unknown'}:${req.headers.authorization}`
    if (seenAuthorization.has(authorization)) {
      sendProblemDetails(
        res,
        {
          type: 'https://paymentauth.org/problems/invalid-challenge',
          title: 'Invalid Challenge',
          status: 402,
        },
        'Credential already used.',
        {
          'WWW-Authenticate': Challenge.serialize(flowChallenge(flowCase)),
          'Cache-Control': 'no-store',
        },
      )
      return
    }
    seenAuthorization.add(authorization)
  }

  const flowRequest = requestForFlowCase(flowCase, url)
  if (!flowRequest) {
    res.statusCode = 500
    res.end('invalid flow case')
    return
  }

  const handler = mpp.charge({
    ...flowRequest,
  })

  const nodeRequest = Server.Request.fromNodeListener(req, res)
  const result = await handler(nodeRequest)

  if (result.status === 402) {
    const challenge = result.challenge as Response
    const headers = new Headers(challenge.headers)
    headers.set('Cache-Control', 'no-store')
    if (flowCase.invalid_www_authenticate) {
      headers.set(
        'WWW-Authenticate',
        'Payment id="bad", realm="conformance", method="tempo", intent="charge"',
      )
    } else if (flowCase.invalid_challenge_id) {
      const header = headers.get('WWW-Authenticate')
      if (header) {
        try {
          const parsed = Challenge.deserialize(header)
          headers.set('WWW-Authenticate', Challenge.serialize({ ...parsed, id: 'invalid-challenge-id' }))
        } catch {
          headers.set('WWW-Authenticate', 'Payment bad')
        }
      }
    }
    if (flowCase.digest_binding) {
      const header = headers.get('WWW-Authenticate')
      if (header) {
        const parsed = Challenge.deserialize(header)
        const { id: _id, ...challengeInput } = parsed
        headers.set(
          'WWW-Authenticate',
          Challenge.serialize(
            Challenge.from({
              ...challengeInput,
              secretKey,
              digest: paymentDigest(requestBody ?? ''),
            }),
          ),
        )
      }
    }

    // Send Problem Details for specific error conditions on retry (has Authorization but failed)
    if (flowCase.expect_problem_details && req.headers.authorization) {
      const wwwAuth = headers.get('WWW-Authenticate')
      const problemHeaders: Record<string, string> = {}
      if (wwwAuth) problemHeaders['WWW-Authenticate'] = wwwAuth
      problemHeaders['Cache-Control'] = 'no-store'
      if (flowCase.expect_retry_after) problemHeaders['Retry-After'] = flowCase.expect_retry_after
      sendProblemDetails(
        res,
        flowCase.expect_problem_details,
        `Payment verification failed for ${flowCase.name}`,
        problemHeaders,
      )
      return
    }

    // Send Problem Details for missing-credential on initial 402 (no Authorization)
    if (flowCase.expect_problem_details && !req.headers.authorization) {
      const wwwAuth = headers.get('WWW-Authenticate')
      const problemHeaders: Record<string, string> = {}
      if (wwwAuth) problemHeaders['WWW-Authenticate'] = wwwAuth
      problemHeaders['Cache-Control'] = 'no-store'
      if (flowCase.expect_retry_after) problemHeaders['Retry-After'] = flowCase.expect_retry_after
      sendProblemDetails(
        res,
        flowCase.expect_problem_details,
        `Payment credential required for ${flowCase.name}`,
        problemHeaders,
      )
      return
    }

    res.writeHead(402, Object.fromEntries(headers))
    const body = await challenge.text()
    if (body) res.write(body)
    res.end()
    return
  }

  if (flowCase.digest_binding) {
    const credential = req.headers.authorization
      ? Credential.deserialize(req.headers.authorization)
      : undefined
    if (credential?.challenge.digest !== paymentDigest(requestBody ?? '')) {
      sendChallenge(res, flowChallenge(flowCase))
      return
    }
  }

  if (flowCase.bind_request_resource) {
    const credential = req.headers.authorization
      ? Credential.deserialize(req.headers.authorization)
      : undefined
    const challengeRequest = credential?.challenge.request as Record<string, unknown> | undefined
    if (challengeRequest?.resource !== `${url.pathname}${url.search}`) {
      sendChallenge(res, flowChallenge(flowCase, undefined, flowRequest))
      return
    }
  }

  let sideEffectCount: number | undefined
  let idempotencyKeyObserved: string | null | undefined
  if (flowCase.idempotency_key) {
    const rawIdempotencyKey = req.headers['idempotency-key']
    idempotencyKeyObserved = Array.isArray(rawIdempotencyKey)
      ? rawIdempotencyKey[0] ?? null
      : rawIdempotencyKey ?? null
    const key = idempotencyKeyObserved ? `${url.pathname}:${idempotencyKeyObserved}` : undefined
    if (!key) {
      sendProblemDetails(
        res,
        {
          type: 'https://paymentauth.org/problems/bad-request',
          title: 'Bad Request',
          status: 400,
        },
        'Missing Idempotency-Key header.',
        { 'Cache-Control': 'no-store' },
      )
      return
    }
    sideEffectCount = sideEffectsByKey.get(key) ?? 0
    if (sideEffectCount === 0) sideEffectsByKey.set(key, 1)
    sideEffectCount = sideEffectsByKey.get(key)
  }

  const responseBody: Record<string, unknown> = { ok: true, name: flowCase.name }
  // Echo back received body for verify_body_preserved flows
  if (flowCase.verify_body_preserved && requestBody) {
    responseBody.received_body = requestBody
  }
  if (acceptPaymentByPath.has(url.pathname)) {
    responseBody.accept_payment_observed = acceptPaymentByPath.get(url.pathname)
  }
  if (sideEffectCount !== undefined) responseBody.side_effect_count = sideEffectCount
  if (idempotencyKeyObserved !== undefined) {
    responseBody.idempotency_key_observed = idempotencyKeyObserved
  }

  const baseResponse = new Response(JSON.stringify(responseBody), {
    status: 200,
    headers: { 'Content-Type': 'application/json', 'Cache-Control': 'private' },
  })
  const response = flowCase.omit_receipt
    ? baseResponse
    : (result.withReceipt(baseResponse) as Response)

  res.statusCode = response.status
  response.headers.forEach((value, key) => res.setHeader(key, value))
  res.end(await response.text())
})

server.listen(port, () => {
  console.log(`compliance-server listening on ${port}`)
})

process.on('SIGINT', () => server.close())
