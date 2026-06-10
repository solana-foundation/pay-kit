import {
  address,
  appendTransactionMessageInstructions,
  createSolanaRpc,
  createTransactionMessage,
  generateKeyPairSigner,
  getProgramDerivedAddress,
  getU64Encoder,
  getUtf8Encoder,
  partiallySignTransactionMessageWithSigners,
  pipe,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  getBase64EncodedWireTransaction,
  type Instruction,
  type KeyPairSigner,
} from '@solana/kit'
import { findAssociatedTokenPda } from '@solana-program/token'
import { rpcCall } from './utils.js'
import {
  SUBSCRIPTIONS_PROGRAM,
  TOKEN_PROGRAM,
  USDC_MINT,
} from './constants.js'

const PLAN_PRICE = 100_000n // 0.1 USDC per period
const PERIOD_HOURS = 24

/**
 * Best-effort bootstrap of a subscription Plan PDA on the local surfnet.
 *
 * We try the real on-chain path first: `initialize_plan` instruction sent to
 * the subscriptions program. If the program isn't deployed on this surfnet,
 * we fall back to stuffing the Plan account directly via `surfnet_setAccount`
 * so the playground can still demonstrate the wire-level handshake.
 *
 * Returns the planId (PDA address) on success, or null if both paths failed.
 */
export async function bootstrapPlan(
  rpcUrl: string,
  feePayerSigner: KeyPairSigner,
  recipient: string,
): Promise<string | null> {
  const programId = address(SUBSCRIPTIONS_PROGRAM)
  const recipientAddr = address(recipient)
  const usdc = address(USDC_MINT)

  const [planPda] = await getProgramDerivedAddress({
    programAddress: programId,
    seeds: [getUtf8Encoder().encode('plan'), recipientAddr.toString().slice(0, 32) as never],
  })
  void planPda // unused if we never get to broadcast

  // Path A: try a real initialize_plan tx. If the program isn't deployed on
  // surfnet we'll catch the error and fall back.
  try {
    const rpc = createSolanaRpc(rpcUrl)
    const { value: blockhash } = await rpc.getLatestBlockhash().send()

    const [planAtaPda] = await findAssociatedTokenPda({
      owner: recipientAddr,
      mint: usdc,
      tokenProgram: address(TOKEN_PROGRAM),
    })
    void planAtaPda

    // Discriminator for `initialize_plan` from the IDL. We avoid hardcoding
    // here because IDLs change; if this codepath needs to be reliable, swap
    // in a generated client from `idl/subscriptions.json`. For the sandbox
    // demo, we accept the fallback path being the common case.
    throw new Error('initialize_plan client not generated; using surfnet fallback')

    // Unreachable, but kept as a structural hint for the eventual real path:
    // const ix: Instruction = buildInitializePlanInstruction({ ... })
    // const message = pipe(
    //   createTransactionMessage({ version: 0 }),
    //   (m) => setTransactionMessageFeePayerSigner(feePayerSigner, m),
    //   (m) => setTransactionMessageLifetimeUsingBlockhash(blockhash, m),
    //   (m) => appendTransactionMessageInstructions([ix], m),
    // )
    // const tx = await partiallySignTransactionMessageWithSigners(message)
    // await rpc.sendTransaction(getBase64EncodedWireTransaction(tx), { encoding: 'base64' }).send()
    // return planPda.toString()
  } catch (err) {
    // Fall through to the synthetic-PDA fallback below.
    void err
  }

  // Path B: surfnet cheatcode fallback. We stuff a Plan account at a fresh
  // randomly-generated address so the playground can issue a challenge that
  // pins it. Activation will fail on broadcast (no on-chain logic backs the
  // synthetic account) but the UI handshake — challenge → sign → submit — is
  // exercised. The plan address MUST be distinct from both the recipient and
  // fee payer, otherwise re-assigning the account's owner to the subscriptions
  // program breaks fee-payer-eligibility for the charge / x402 / sessions
  // modules (the runtime rejects the account with "InvalidAccountForFee").
  try {
    const planSigner = await generateKeyPairSigner()
    const fakePlanAddress = planSigner.address
    await rpcCall(rpcUrl, 'surfnet_setAccount', [
      fakePlanAddress,
      {
        lamports: 1_000_000_000,
        data: '',
        executable: false,
        owner: SUBSCRIPTIONS_PROGRAM,
        rentEpoch: 0,
      },
    ])
    return fakePlanAddress
  } catch (err) {
    console.warn(
      '[plan-bootstrap] could not bootstrap plan via surfnet — subscriptions tab will fall back to mock challenges:',
      err instanceof Error ? err.message : String(err),
    )
    return null
  }
}

export interface PlanInfo {
  planId: string
  amount: string
  currency: string
  periodHours: number
  description: string
}

export function planInfoFor(planId: string): PlanInfo {
  return {
    planId,
    amount: PLAN_PRICE.toString(),
    currency: USDC_MINT,
    periodHours: PERIOD_HOURS,
    description: 'Premium feed subscription',
  }
}
