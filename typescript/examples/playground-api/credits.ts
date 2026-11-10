/**
 * LOCAL SANDBOX ONLY: a credit provider funds an MPP session.
 *
 * The customer holds credits with a provider program. The merchant's session
 * challenge advertises the provider's lifecycle hooks (`channelVersion: 2`):
 * the channel program calls the provider's `preFund` callback inside the open
 * (it debits credits and moves stablecoin backing to the customer, which the
 * channel then escrows) and its `postDistribute` callback inside the close (it
 * pulls the unspent refund back into custody and restores that many credits).
 *
 * The demo mirrors `rust/crates/integration-tests/tests/credit_provider_session_surfnet.rs`:
 *
 *   - startup writes the hook-enabled channel program (payment-channels#102,
 *     the `stable` channel built with `--features hooks`; it also serves V1
 *     channels) at the canonical address, and the reference provider
 *     (payment-channels `examples/credit-provider`) at a fresh address;
 *   - `POST /api/v1/credits/enroll` plants a ledger with credits and the
 *     matching backing in the provider's vault (the state the provider's
 *     `initialize` + `deposit` produce);
 *   - `POST /api/v1/credits/authorize` returns the provider's approval for one
 *     channel, signed by the issuer: an exact-cap SPL approval (refund
 *     recovery) and `authorize`, for the customer to co-sign;
 *   - `GET /api/v1/credits/:customer/quote` is the merchant's paid route,
 *     gated by `@solana/mpp`'s session method with that customer's hooks.
 *
 * The callback accounts (ledger, vault, customer token account) depend on the
 * customer, so the merchant keeps one session method per customer. A real
 * merchant needs a resolver that derives them from a named provider.
 *
 * Mounted only on localnet with both artifacts:
 *   PAYMENT_CHANNELS_V2_SO=<payment-channels>/target/deploy-v2/payment_channels.so
 *   CREDIT_PROVIDER_SO=<payment-channels>/target/deploy/credit_provider.so
 */
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import type { Express, Request as ExpressRequest, Response as ExpressResponse } from 'express'
import {
  AccountRole,
  address,
  appendTransactionMessageInstructions,
  type Address,
  compileTransaction,
  createSolanaRpc,
  createTransactionMessage,
  generateKeyPairSigner,
  getAddressEncoder,
  getBase64EncodedWireTransaction,
  getBase64Encoder,
  getProgramDerivedAddress,
  getTransactionDecoder,
  getU64Encoder,
  type Instruction,
  type KeyPairSigner,
  partiallySignTransaction,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  type Signature,
  type Transaction,
} from '@solana/kit'
import { findAssociatedTokenPda, TOKEN_PROGRAM_ADDRESS } from '@solana-program/token'
import { resolveStablecoinMint } from '@solana/mpp'
import { createMemorySessionStore, Mppx, PAYMENT_CHANNELS_PROGRAM_ID, session } from '@solana/mpp/server'
import { Credential } from 'mppx'

const USDC_MINT = address(resolveStablecoinMint('USDC', 'mainnet') ?? '')
/** The localnet treasury of the channel build (`Cs2z…`), credited on distribute. */
const TREASURY = address('Cs2zdfUNonRdRGsiZUQQLdTxzxVvJZmgiX2mpLYKuEqP')
const CHANNEL_PROGRAM = address(PAYMENT_CHANNELS_PROGRAM_ID.toString())

/** Provider wire constants (payment-channels `examples/credit-provider`). */
const LEDGER_SEED = new TextEncoder().encode('credit')
const ENTRYPOINT = Array.from(new TextEncoder().encode('credit!!'))
const AUTHORIZE = 2
const LEDGER_LEN = 331

/** 2 USDC of credits, a 1 USDC session, 0.01 USDC per request. */
export const CREDITS = 2_000_000n
export const DEPOSIT = 1_000_000n
export const PRICE = 10_000n
export const SALT = 7n

type Rpc = ReturnType<typeof createSolanaRpc>

interface Provider {
  readonly issuer: KeyPairSigner
  readonly operator: KeyPairSigner
  readonly program: Address
  readonly recipient: Address
  readonly rpc: Rpc
  readonly rpcUrl: string
  readonly secretKey: string
}

/** The merchant's session method for one customer (its hooks). */
interface Merchant {
  readonly handler: (request: Request) => Promise<{ status: number; challenge?: Response; withReceipt?: (r: Response) => Response }>
  readonly hooks: ChannelHooksJson
  served: number
}

interface HookAccountJson {
  address: string
  writable: boolean
}
interface HookDescriptorJson {
  accounts: HookAccountJson[]
  entrypoint: number[]
  programId: string
  staticData: number[]
}
interface ChannelHooksJson {
  postDistribute: HookDescriptorJson
  preFund: HookDescriptorJson
}

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString('hex')

async function cheat(rpcUrl: string, method: string, params: unknown[]): Promise<unknown> {
  const response = await fetch(rpcUrl, {
    body: JSON.stringify({ id: 1, jsonrpc: '2.0', method, params }),
    headers: { 'Content-Type': 'application/json' },
    method: 'POST',
    signal: AbortSignal.timeout(30_000),
  })
  const data = (await response.json()) as { error?: { message: string }; result?: unknown }
  if (data.error) throw new Error(`${method}: ${data.error.message}`)
  return data.result
}

async function rawAccount(rpcUrl: string, key: string): Promise<Uint8Array | null> {
  const result = (await cheat(rpcUrl, 'getAccountInfo', [key, { commitment: 'confirmed', encoding: 'base64' }])) as {
    value: { data: [string, string] } | null
  }
  return result.value ? new Uint8Array(Buffer.from(result.value.data[0], 'base64')) : null
}

/** Base units in an SPL token account, or null when it does not exist. */
async function tokenBalance(rpcUrl: string, account: string): Promise<string | null> {
  const data = await rawAccount(rpcUrl, account)
  if (!data || data.length < 72) return null
  return Buffer.from(data.slice(64, 72)).readBigUInt64LE().toString()
}

const ata = async (owner: Address): Promise<Address> =>
  (await findAssociatedTokenPda({ mint: USDC_MINT, owner, tokenProgram: TOKEN_PROGRAM_ADDRESS }))[0]

const ledgerAddress = async (program: Address, owner: Address): Promise<Address> =>
  (
    await getProgramDerivedAddress({
      programAddress: program,
      seeds: [LEDGER_SEED, getAddressEncoder().encode(owner), getAddressEncoder().encode(USDC_MINT)],
    })
  )[0]

/** The provider's hook pair for one customer: the four accounts its callback touches. */
async function providerHooks(program: Address, customer: Address): Promise<ChannelHooksJson> {
  const ledger = await ledgerAddress(program, customer)
  const descriptor: HookDescriptorJson = {
    accounts: [
      { address: ledger, writable: true },
      { address: await ata(ledger), writable: true },
      { address: await ata(customer), writable: true },
      { address: TOKEN_PROGRAM_ADDRESS, writable: false },
    ],
    entrypoint: ENTRYPOINT,
    programId: program,
    staticData: [],
  }
  return { postDistribute: descriptor, preFund: descriptor }
}

/** The provider's `Ledger` (331 bytes) for a customer who deposited `credits`. */
function ledgerBytes(owner: Address, issuer: Address, credits: bigint): Uint8Array {
  const out = new Uint8Array(LEDGER_LEN)
  const enc = getAddressEncoder()
  out[0] = 1 // version; busy and active stay 0
  out.set(enc.encode(owner), 3)
  out.set(enc.encode(USDC_MINT), 35)
  out.set(enc.encode(issuer), 67)
  // channel (99..131), authorization (131..267), configuration (267..299) zero
  out.set(getU64Encoder().encode(credits), 299)
  return out
}

/** Ledger fields the UI shows (offsets of the 331-byte layout). */
function decodeLedger(data: Uint8Array): Record<string, string | boolean> {
  const view = Buffer.from(data)
  return {
    active: data[2] === 1,
    credits: view.readBigUInt64LE(299).toString(),
    funded: view.readBigUInt64LE(307).toString(),
    refunded: view.readBigUInt64LE(315).toString(),
    sequence: view.readBigUInt64LE(323).toString(),
  }
}

/** SHA-256 of an empty distribution list (no splits): the channel's `distributionHash`. */
const EMPTY_DISTRIBUTION_HASH = new Uint8Array(createHash('sha256').update(new Uint8Array(4)).digest())

function u64(value: bigint): Uint8Array {
  return new Uint8Array(getU64Encoder().encode(value))
}

function approveInstruction(source: Address, delegate: Address, owner: Address, amount: bigint): Instruction {
  return {
    accounts: [
      { address: source, role: AccountRole.WRITABLE },
      { address: delegate, role: AccountRole.READONLY },
      { address: owner, role: AccountRole.READONLY_SIGNER },
    ],
    data: new Uint8Array([4, ...u64(amount)]),
    programAddress: TOKEN_PROGRAM_ADDRESS,
  }
}

interface AuthorizationArgs {
  readonly cap: bigint
  readonly expiresAtSlot: bigint
  readonly nonce: bigint
  readonly openSlot: bigint
  readonly payee: Address
  readonly salt: bigint
  readonly sessionKey: Address
}

async function authorizeInstruction(p: Provider, customer: Address, args: AuthorizationArgs): Promise<Instruction> {
  const ledger = await ledgerAddress(p.program, customer)
  const enc = getAddressEncoder()
  const data = new Uint8Array(1 + 136)
  data[0] = AUTHORIZE
  data.set(enc.encode(args.payee), 1)
  data.set(enc.encode(args.sessionKey), 33)
  data.set(EMPTY_DISTRIBUTION_HASH, 65)
  let at = 97
  for (const value of [args.salt, args.openSlot, args.cap, args.nonce, args.expiresAtSlot]) {
    data.set(u64(value), at)
    at += 8
  }
  return {
    // The canonical channel program: the provider's six-account form.
    accounts: [
      { address: customer, role: AccountRole.READONLY_SIGNER },
      { address: p.issuer.address, role: AccountRole.READONLY_SIGNER },
      { address: ledger, role: AccountRole.WRITABLE },
      { address: await ata(ledger), role: AccountRole.WRITABLE },
      { address: await ata(customer), role: AccountRole.WRITABLE },
      { address: TOKEN_PROGRAM_ADDRESS, role: AccountRole.READONLY },
    ],
    data,
    programAddress: p.program,
  }
}

async function confirm(rpc: Rpc, signature: Signature): Promise<void> {
  for (let i = 0; i < 60; i += 1) {
    const { value } = await rpc.getSignatureStatuses([signature]).send()
    const status = value[0]
    if (status?.err) throw new Error(`transaction ${signature} failed: ${JSON.stringify(status.err, (_k, v) => (typeof v === 'bigint' ? v.toString() : v))}`)
    if (status?.confirmationStatus === 'confirmed' || status?.confirmationStatus === 'finalized') return
    await new Promise((resolve) => setTimeout(resolve, 250))
  }
  throw new Error(`transaction ${signature} not confirmed`)
}

/** Convert an Express request into the Fetch request the session method reads. */
function toFetchRequest(req: ExpressRequest): Request {
  const headers = new Headers()
  for (const [key, value] of Object.entries(req.headers)) {
    if (typeof value === 'string') headers.set(key, value)
    else if (Array.isArray(value)) headers.set(key, value.join(', '))
  }
  return new Request(new URL(req.originalUrl, `http://${req.headers.host ?? 'localhost'}`), {
    headers,
    method: req.method,
  })
}

async function sendFetchResponse(res: ExpressResponse, response: Response): Promise<void> {
  res.status(response.status)
  response.headers.forEach((value, key) => res.setHeader(key, value))
  res.send(Buffer.from(await response.arrayBuffer()))
}

function artifact(variable: string): Uint8Array | null {
  const path = process.env[variable]
  if (!path) return null
  return new Uint8Array(readFileSync(path))
}

/**
 * Mount the credit-provider demo when running on the local sandbox with both
 * program artifacts. Returns false (and mounts only the status route) otherwise.
 */
export async function registerCredits(
  app: Express,
  options: { network: string; operator: KeyPairSigner; recipient: string; rpcUrl: string; secretKey: string },
): Promise<boolean> {
  const channelElf = artifact('PAYMENT_CHANNELS_V2_SO')
  const providerElf = artifact('CREDIT_PROVIDER_SO')
  const disabled = (reason: string): false => {
    app.get('/api/v1/credits/status', (_req, res) => res.json({ enabled: false, reason }))
    return false
  }
  if (options.network !== 'localnet') return disabled('the credit-provider demo runs on the local sandbox only')
  if (!channelElf || !providerElf) {
    return disabled(
      'set PAYMENT_CHANNELS_V2_SO and CREDIT_PROVIDER_SO to the payment-channels artifacts (hook-enabled channel program and examples/credit-provider)',
    )
  }

  const { rpcUrl } = options
  const programKey = await generateKeyPairSigner()
  const p: Provider = {
    issuer: await generateKeyPairSigner(),
    operator: options.operator,
    program: programKey.address,
    recipient: address(options.recipient),
    rpc: createSolanaRpc(rpcUrl),
    rpcUrl,
    secretKey: options.secretKey,
  }
  try {
    await cheat(rpcUrl, 'surfnet_writeProgram', [CHANNEL_PROGRAM, hex(channelElf), 0])
    await cheat(rpcUrl, 'surfnet_writeProgram', [p.program, hex(providerElf), 0])
    await cheat(rpcUrl, 'surfnet_setAccount', [
      p.issuer.address,
      { data: '', executable: false, lamports: 10_000_000_000, owner: '11111111111111111111111111111111', rentEpoch: 0 },
    ])
    // The merchant and the treasury receive payouts on distribute.
    for (const owner of [p.recipient, TREASURY]) {
      if (!(await rawAccount(rpcUrl, await ata(owner)))) {
        await cheat(rpcUrl, 'surfnet_setTokenAccount', [owner, USDC_MINT, { amount: 0, state: 'initialized' }, TOKEN_PROGRAM_ADDRESS])
      }
    }
  } catch (error) {
    return disabled(`program setup failed: ${error instanceof Error ? error.message : String(error)}`)
  }

  const merchants = new Map<string, Merchant>()
  const pending = new Map<string, string>()

  const merchantFor = async (customer: Address): Promise<Merchant> => {
    const known = merchants.get(customer)
    if (known) return known
    const hooks = await providerHooks(p.program, customer)
    const method = session({
      amount: PRICE,
      channelHooks: hooks,
      channelProgram: PAYMENT_CHANNELS_PROGRAM_ID,
      channelVersion: 2,
      currency: USDC_MINT,
      decimals: 6,
      feePayer: true,
      feePayerSigner: p.operator,
      gracePeriodSeconds: 900,
      idleTimeoutSeconds: 600,
      network: 'localnet',
      recipient: p.recipient,
      rpc: p.rpc,
      signer: p.operator,
      store: createMemorySessionStore(),
      suggestedDeposit: DEPOSIT,
    })
    const mppx = Mppx.create({ methods: [method], realm: 'paykit-playground-credits', secretKey: p.secretKey })
    const handler = mppx.session({
      amount: PRICE.toString(),
      currency: USDC_MINT,
      description: 'Credit-funded quote',
      methodDetails: { channelProgram: CHANNEL_PROGRAM, network: 'localnet' },
      recipient: p.recipient,
    }) as Merchant['handler']
    const merchant: Merchant = { handler, hooks, served: 0 }
    merchants.set(customer, merchant)
    return merchant
  }

  const parseCustomer = (value: unknown): Address => {
    if (typeof value !== 'string') throw new Error('missing customer address')
    return address(value)
  }

  app.get('/api/v1/credits/status', (_req, res) => {
    res.json({
      channelProgram: CHANNEL_PROGRAM,
      credits: CREDITS.toString(),
      deposit: DEPOSIT.toString(),
      enabled: true,
      issuer: p.issuer.address,
      mint: USDC_MINT,
      price: PRICE.toString(),
      provider: p.program,
      recipient: p.recipient,
    })
  })

  // Plant the customer's ledger (credits) and the provider's vault (backing).
  app.post('/api/v1/credits/enroll', async (req, res) => {
    try {
      const customer = parseCustomer((req.body as { customer?: unknown }).customer)
      const ledger = await ledgerAddress(p.program, customer)
      await cheat(rpcUrl, 'surfnet_setAccount', [
        ledger,
        { data: hex(ledgerBytes(customer, p.issuer.address, CREDITS)), executable: false, lamports: 10_000_000, owner: p.program, rentEpoch: 0 },
      ])
      await cheat(rpcUrl, 'surfnet_setTokenAccount', [ledger, USDC_MINT, { amount: Number(CREDITS), state: 'initialized' }, TOKEN_PROGRAM_ADDRESS])
      if (!(await rawAccount(rpcUrl, await ata(customer)))) {
        await cheat(rpcUrl, 'surfnet_setTokenAccount', [customer, USDC_MINT, { amount: 0, state: 'initialized' }, TOKEN_PROGRAM_ADDRESS])
      }
      merchants.delete(customer)
      res.json({ hooks: (await merchantFor(customer)).hooks, ledger, vault: await ata(ledger) })
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : String(error) })
    }
  })

  // The provider's approval for one channel: the customer's exact-cap refund
  // approval and `authorize`, fee paid and co-signed by the issuer.
  app.post('/api/v1/credits/authorize', async (req, res) => {
    try {
      const body = req.body as { cap?: string; customer?: unknown; openSlot?: string; sessionKey?: string }
      const customer = parseCustomer(body.customer)
      const openSlot = BigInt(body.openSlot ?? '')
      const cap = BigInt(body.cap ?? DEPOSIT.toString())
      const sessionKey = address(String(body.sessionKey))
      const ledgerData = await rawAccount(rpcUrl, await ledgerAddress(p.program, customer))
      if (!ledgerData) throw new Error('customer is not enrolled')
      // Authorization (131..267): payee, signer, distribution hash, then salt,
      // openSlot, cap, nonce, expiresAtSlot. The next approval is nonce + 1.
      const nonce = Buffer.from(ledgerData).readBigUInt64LE(131 + 96 + 24) + 1n
      const { value: blockhash } = await p.rpc.getLatestBlockhash({ commitment: 'confirmed' }).send()
      const message = pipe(
        createTransactionMessage({ version: 0 }),
        (m) => setTransactionMessageFeePayer(p.issuer.address, m),
        (m) => setTransactionMessageLifetimeUsingBlockhash(blockhash, m),
        async (m) =>
          appendTransactionMessageInstructions(
            [
              approveInstruction(await ata(customer), await ledgerAddress(p.program, customer), customer, cap),
              await authorizeInstruction(p, customer, {
                cap,
                expiresAtSlot: openSlot + 100_000n,
                nonce,
                openSlot,
                payee: p.recipient,
                salt: SALT,
                sessionKey,
              }),
            ],
            m,
          ),
      )
      const signed = await partiallySignTransaction([p.issuer.keyPair], compileTransaction(await message))
      const wire = getBase64EncodedWireTransaction(signed)
      pending.set(customer, Buffer.from(signed.messageBytes).toString('base64'))
      res.json({ authorization: { cap: cap.toString(), expiresAtSlot: (openSlot + 100_000n).toString(), nonce: nonce.toString(), openSlot: openSlot.toString(), salt: SALT.toString(), sessionKey }, transaction: wire })
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : String(error) })
    }
  })

  // Land the approval the customer co-signed. Only the exact message the
  // issuer signed above is relayed.
  app.post('/api/v1/credits/authorize/submit', async (req, res) => {
    try {
      const body = req.body as { customer?: unknown; transaction?: string }
      const customer = parseCustomer(body.customer)
      const tx = getTransactionDecoder().decode(getBase64Encoder().encode(String(body.transaction))) as Transaction
      if (pending.get(customer) !== Buffer.from(tx.messageBytes).toString('base64')) {
        throw new Error('not the approval the issuer signed')
      }
      pending.delete(customer)
      const wire = getBase64EncodedWireTransaction(tx)
      const signature = await p.rpc.sendTransaction(wire, { encoding: 'base64', preflightCommitment: 'confirmed' }).send()
      await confirm(p.rpc, signature)
      res.json({ signature })
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : String(error) })
    }
  })

  // On-chain state for the UI: ledger fields and every balance the flow moves.
  app.get('/api/v1/credits/:customer/state', async (req, res) => {
    try {
      const customer = parseCustomer(req.params.customer)
      const ledger = await ledgerAddress(p.program, customer)
      const ledgerData = await rawAccount(rpcUrl, ledger)
      const channel = typeof req.query.channel === 'string' ? address(req.query.channel) : null
      res.json({
        balances: {
          customer: await tokenBalance(rpcUrl, await ata(customer)),
          escrow: channel ? await tokenBalance(rpcUrl, await ata(channel)) : null,
          merchant: await tokenBalance(rpcUrl, await ata(p.recipient)),
          vault: await tokenBalance(rpcUrl, await ata(ledger)),
        },
        ledger: ledgerData ? decodeLedger(ledgerData) : null,
        served: merchants.get(customer)?.served ?? 0,
      })
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : String(error) })
    }
  })

  // The merchant's paid route: 402 with the customer's hooks, then open,
  // voucher and close credentials through `@solana/mpp`'s session method.
  app.get('/api/v1/credits/:customer/quote', async (req, res) => {
    try {
      const customer = parseCustomer(req.params.customer)
      const merchant = await merchantFor(customer)
      const request = toFetchRequest(req)
      const result = await merchant.handler(request)
      if (result.status === 402 && result.challenge) {
        await sendFetchResponse(res, result.challenge)
        return
      }
      let action = 'unknown'
      try {
        action = (Credential.fromRequest(request).payload as { action?: string }).action ?? action
      } catch {
        /* the handler already verified the credential */
      }
      if (action === 'voucher') merchant.served += 1
      const body =
        action === 'voucher'
          ? { quote: { price: 100 + merchant.served, symbol: 'SOL' }, served: merchant.served }
          : { action, served: merchant.served }
      const response = new Response(JSON.stringify(body), { headers: { 'Content-Type': 'application/json' } })
      await sendFetchResponse(res, result.withReceipt ? result.withReceipt(response) : response)
    } catch (error) {
      res.status(400).json({ error: error instanceof Error ? error.message : String(error) })
    }
  })

  return true
}
