import {
  generateKeyPairSigner,
  getBase64EncodedWireTransaction,
  getBase64Encoder,
  getTransactionDecoder,
  partiallySignTransaction,
  type Transaction,
} from '@solana/kit'
import {
  Challenge,
  createPaymentChannelSessionOpener,
  serializeSessionCredential,
  type SessionAction,
  type SessionChallenge,
  type SignedVoucher,
} from '@solana/mpp/client'
import { nativeFetch } from './flow'
import { getSigner, RPC_URL } from './wallet'

/** `GET /api/v1/credits/status`. */
export interface CreditsStatus {
  enabled: boolean
  reason?: string
  channelProgram?: string
  credits?: string
  deposit?: string
  issuer?: string
  mint?: string
  price?: string
  provider?: string
  recipient?: string
}

/** `GET /api/v1/credits/:customer/state`. */
export interface CreditsState {
  balances: { customer: string | null; escrow: string | null; merchant: string | null; vault: string | null }
  ledger: { active: boolean; credits: string; funded: string; refunded: string; sequence: string } | null
  served: number
}

export type CreditsEvent =
  | { type: 'step'; key: CreditsStepKey; status: 'in-progress' | 'completed' | 'failed' }
  | { type: 'log'; kind: 'req' | 'x402' | 'ok' | 'error' | 'info' | 'dim'; message: string; detail?: string; signature?: string }
  | { type: 'state'; state: CreditsState }
  | { type: 'response'; status: number; body: unknown; headers: Record<string, string> }

export type CreditsStepKey = 'enroll' | 'challenge' | 'authorize' | 'open' | 'requests' | 'close'

export const CREDITS_STEPS: { key: CreditsStepKey; label: string }[] = [
  { key: 'enroll', label: 'Customer holds credits' },
  { key: 'challenge', label: '402 with the provider hooks' },
  { key: 'authorize', label: 'Provider approves the channel' },
  { key: 'open', label: 'openWithHooks: preFund' },
  { key: 'requests', label: 'Voucher-paid requests' },
  { key: 'close', label: 'distributeWithHooks: postDistribute' },
]

export const REQUESTS = 3

/** A local-validator explorer link for a signature. */
export function explorerTx(signature: string): string {
  const rpc = new URL(RPC_URL, location.origin).toString()
  return `https://explorer.solana.com/tx/${signature}?cluster=custom&customUrl=${encodeURIComponent(rpc)}`
}

async function json<T>(response: Response): Promise<T> {
  const body = (await response.json().catch(() => ({}))) as T & { error?: string }
  if (!response.ok) throw new Error(body.error ?? `HTTP ${response.status}`)
  return body
}

export async function creditsStatus(): Promise<CreditsStatus> {
  return json<CreditsStatus>(await nativeFetch('/api/v1/credits/status'))
}

export async function creditsState(customer: string, channel?: string): Promise<CreditsState> {
  const query = channel ? `?channel=${channel}` : ''
  return json<CreditsState>(await nativeFetch(`/api/v1/credits/${customer}/state${query}`))
}

function post<T>(path: string, body: unknown): Promise<T> {
  return nativeFetch(path, {
    body: JSON.stringify(body),
    headers: { 'Content-Type': 'application/json' },
    method: 'POST',
  }).then((response) => json<T>(response))
}

function headersOf(response: Response): Record<string, string> {
  const out: Record<string, string> = {}
  response.headers.forEach((value, key) => {
    out[key] = value
  })
  return out
}

/** The receipt's `txHash` (the close's settlement signature), when present. */
function receiptTxHash(response: Response): string | undefined {
  const header = response.headers.get('payment-receipt')
  if (!header) return undefined
  try {
    const padded = header.replace(/-/g, '+').replace(/_/g, '/')
    return (JSON.parse(atob(padded)) as { txHash?: string }).txHash
  } catch {
    return undefined
  }
}

/**
 * The full credit-funded session, step by step, as the browser wallet (the
 * customer): enroll, 402, the provider's approval, the hooked open, three
 * voucher-paid requests and the hooked close.
 */
export async function* runCreditsFlow(): AsyncGenerator<CreditsEvent> {
  const customer = await getSigner()
  const quoteUrl = `/api/v1/credits/${customer.address}/quote`
  const state = async (channel?: string): Promise<CreditsEvent> => ({
    state: await creditsState(customer.address, channel),
    type: 'state',
  })

  // 1. Credits with the provider (the state its initialize + deposit produce).
  yield { key: 'enroll', status: 'in-progress', type: 'step' }
  const enrolled = await post<{ ledger: string; vault: string }>('/api/v1/credits/enroll', { customer: customer.address })
  yield { kind: 'ok', message: `Ledger ${enrolled.ledger.slice(0, 8)}… holds 2 USDC of credits; the vault holds the backing`, type: 'log' }
  yield await state()
  yield { key: 'enroll', status: 'completed', type: 'step' }

  // 2. The merchant's 402 advertises the provider's hooks.
  yield { key: 'challenge', status: 'in-progress', type: 'step' }
  yield { kind: 'req', message: `GET ${quoteUrl}`, type: 'log' }
  const first = await nativeFetch(quoteUrl)
  if (first.status !== 402) throw new Error(`expected 402, got ${first.status}`)
  const challenge = Challenge.fromResponse(first) as unknown as SessionChallenge
  const details = challenge.request.methodDetails
  const hooks = details.channelHooks ?? {}
  yield {
    detail: JSON.stringify({ channelHooks: hooks, channelVersion: details.channelVersion }, null, 2),
    kind: 'x402',
    message: `402: channelVersion ${details.channelVersion}, hooks ${Object.keys(hooks).join(' + ')} on ${hooks.preFund?.programId.slice(0, 8)}…`,
    type: 'log',
  }
  yield { key: 'challenge', status: 'completed', type: 'step' }

  // 3. The provider approves this exact channel; the customer co-signs.
  yield { key: 'authorize', status: 'in-progress', type: 'step' }
  const sessionKey = await generateKeyPairSigner()
  const approval = await post<{ authorization: Record<string, string>; transaction: string }>('/api/v1/credits/authorize', {
    customer: customer.address,
    openSlot: details.recentSlot,
    sessionKey: sessionKey.address,
  })
  yield {
    detail: JSON.stringify(approval.authorization, null, 2),
    kind: 'info',
    message: 'Issuer signed: exact-cap refund approval + authorize (cap 1 USDC, session key, open slot, salt 7)',
    type: 'log',
  }
  const tx = getTransactionDecoder().decode(getBase64Encoder().encode(approval.transaction)) as Transaction
  const signed = await partiallySignTransaction([customer.keyPair], tx)
  const { signature: approvalSignature } = await post<{ signature: string }>('/api/v1/credits/authorize/submit', {
    customer: customer.address,
    transaction: getBase64EncodedWireTransaction(signed),
  })
  yield { kind: 'ok', message: `Provider approval landed: ${approvalSignature.slice(0, 16)}…`, signature: approvalSignature, type: 'log' }
  yield await state()
  yield { key: 'authorize', status: 'completed', type: 'step' }

  // 4. The hooked open: preFund debits credits and backs the deposit.
  yield { key: 'open', status: 'in-progress', type: 'step' }
  const opened = await createPaymentChannelSessionOpener({
    deposit: 1_000_000n,
    rpcUrl: RPC_URL,
    salt: 7n,
    sessionSigner: sessionKey,
    signer: customer,
  })({ challenge } as Parameters<ReturnType<typeof createPaymentChannelSessionOpener>>[0])
  const channelId = (opened.payload as { channelId: string }).channelId
  const pay = async (payload: SessionAction): Promise<Response> =>
    nativeFetch(quoteUrl, { headers: { Authorization: serializeSessionCredential({ challenge, payload }) } })
  const openResponse = await pay(opened.payload)
  if (!openResponse.ok) throw new Error(`open refused: ${await openResponse.text()}`)
  yield { kind: 'ok', message: `Channel ${channelId.slice(0, 8)}… opened with openWithHooks; preFund moved 1 USDC of backing`, type: 'log' }
  yield await state(channelId)
  yield { key: 'open', status: 'completed', type: 'step' }

  // 5. Requests paid with vouchers signed by the session key.
  yield { key: 'requests', status: 'in-progress', type: 'step' }
  let last: SignedVoucher | undefined
  for (let n = 1; n <= REQUESTS; n += 1) {
    const action = await opened.session.voucherAction(10_000n)
    last = (action as { voucher: SignedVoucher }).voucher
    const response = await pay(action)
    const body = await response.json().catch(() => null)
    if (!response.ok) throw new Error(`request ${n} refused: ${JSON.stringify(body)}`)
    yield { body, headers: headersOf(response), status: response.status, type: 'response' }
    yield { kind: 'ok', message: `Request ${n} served (voucher cumulative ${(n * 0.01).toFixed(2)} USDC)`, type: 'log' }
  }
  yield await state(channelId)
  yield { key: 'requests', status: 'completed', type: 'step' }

  // 6. The close: settle, then distributeWithHooks with postDistribute.
  yield { key: 'close', status: 'in-progress', type: 'step' }
  const closeResponse = await pay({ action: 'close', channelId, voucher: last } as SessionAction)
  if (!closeResponse.ok) throw new Error(`close refused: ${await closeResponse.text()}`)
  const settlement = receiptTxHash(closeResponse)
  yield {
    kind: 'ok',
    message: 'Settled and distributed: merchant +0.03 USDC; postDistribute returned 0.97 USDC to custody and restored the credits',
    signature: settlement,
    type: 'log',
  }
  yield await state(channelId)
  yield { key: 'close', status: 'completed', type: 'step' }
}
