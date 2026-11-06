/**
 * Musebook Unlimited — worked devnet subscription charge through the
 * Musebook credit provider (see `docs/musebook-subscription-plan.md`).
 *
 * Flow: deposit → authorize → open session → charge → close/settle →
 * refund. The subscriber's deposit backs a V2 payment channel whose
 * hooks are the provider's per-payer credit hooks; the monthly plan
 * amount ($19.99, in USDC or in $CLAWD priced at charge time) is
 * vouchered against the channel; at close, distribution runs the
 * `post_distribute` hook and any recovered refund returns to the
 * provider ledger vault — refunds restore credits **only** from that
 * actually recovered amount.
 *
 * Env-gated exactly like the Rust devnet test
 * (`rust/crates/kit/tests/musebook_devnet.rs`): without the payer and
 * issuer keypair files the example prints what it would do and exits
 * without touching the network. Nothing here runs on mainnet — the RPC
 * genesis hash must be devnet's or the example refuses to proceed.
 *
 *   MUSEBOOK_DEVNET_PAYER=/path/payer.json     (Solana keypair file)
 *   MUSEBOOK_DEVNET_ISSUER=/path/issuer.json   (Solana keypair file)
 *   MUSEBOOK_DEVNET_RPC_URL=https://api.devnet.solana.com   (default)
 *   MUSEBOOK_DEVNET_PROGRAM=<pubkey>           (optional devnet-only override)
 *   MUSEBOOK_SUBSCRIPTION_ASSET=usdc|clawd     (default usdc)
 *   MUSEBOOK_DEVNET_CLAWD_MINT=<pubkey>        (devnet mint for asset=clawd;
 *                                               the mainnet $CLAWD mint does
 *                                               not exist on devnet)
 *   MUSEBOOK_DEVNET_MERCHANT=/path/merchant.json (optional; ephemeral if unset)
 */
import { readFileSync } from 'node:fs';

import {
    AccountRole,
    address,
    appendTransactionMessageInstructions,
    createKeyPairSignerFromBytes,
    createSolanaRpc,
    createTransactionMessage,
    generateKeyPairSigner,
    getAddressEncoder,
    getBase64EncodedWireTransaction,
    getProgramDerivedAddress,
    getSignatureFromTransaction,
    getUtf8Encoder,
    type Instruction,
    type KeyPairSigner,
    pipe,
    setTransactionMessageFeePayerSigner,
    setTransactionMessageLifetimeUsingBlockhash,
    signTransactionMessageWithSigners,
} from '@solana/kit';
import { findAssociatedTokenPda } from '@solana-program/token';
import {
    ActiveSession,
    creditAuthorizationInstructions,
    DEFAULT_SESSION_EXPIRES_AT,
    derivePaymentChannelOpen,
    MAX_AUTHORIZATION_SLOTS,
    MUSEBOOK_COMPUTE_UNIT_LIMIT,
    PAYMENT_CHANNELS_V2_PROGRAM_ID,
    type SessionRequest,
    TOKEN_PROGRAM,
} from '@solana/mpp/client';
import { session as serverSession, verifyVoucherForChannel } from '@solana/mpp/server';

import { CLAWD_MINT, clawdBaseUnitsForPlan, clawdUsdPrice, PLAN_PRICE_USDC_BASE_UNITS } from './plan.js';
import { buildOpenWithHooks } from './v2-hooks.js';

const DEVNET_GENESIS_HASH = 'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG';
const DEVNET_USDC_MINT = '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU';
const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111';
const ASSOCIATED_TOKEN_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const SYSTEM_PROGRAM = '11111111111111111111111111111111';
const RENT_SYSVAR = 'SysvarRent111111111111111111111111111111111';

function loadKeypair(path: string): Promise<KeyPairSigner> {
    const bytes = new Uint8Array(JSON.parse(readFileSync(path, 'utf8')) as number[]);
    return createKeyPairSignerFromBytes(bytes);
}

function computeUnitLimit(units: number): Instruction {
    const data = new Uint8Array(5);
    data[0] = 2; // SetComputeUnitLimit
    new DataView(data.buffer).setUint32(1, units, true);
    return { accounts: [], data, programAddress: address(COMPUTE_BUDGET_PROGRAM) };
}

type Rpc = ReturnType<typeof createSolanaRpc>;

async function sendAndConfirm(
    rpc: Rpc,
    message: Parameters<typeof signTransactionMessageWithSigners>[0],
): Promise<string> {
    const signed = await signTransactionMessageWithSigners(message);
    const signature = getSignatureFromTransaction(signed);
    await rpc.sendTransaction(getBase64EncodedWireTransaction(signed), { encoding: 'base64' }).send();
    for (let attempt = 0; attempt < 30; attempt++) {
        const [status] = (await rpc.getSignatureStatuses([signature]).send()).value;
        if (status?.err) throw new Error(`transaction ${signature} failed: ${JSON.stringify(status.err)}`);
        if (status && (status.confirmationStatus === 'confirmed' || status.confirmationStatus === 'finalized')) {
            return signature;
        }
        await new Promise(resolve => setTimeout(resolve, 1_000));
    }
    throw new Error(`transaction ${signature} did not confirm in time`);
}

async function main(): Promise<void> {
    const payerPath = process.env.MUSEBOOK_DEVNET_PAYER;
    const issuerPath = process.env.MUSEBOOK_DEVNET_ISSUER;
    if (!payerPath || !issuerPath) {
        console.log(
            'SKIPPED: set MUSEBOOK_DEVNET_PAYER and MUSEBOOK_DEVNET_ISSUER to keypair files to run the devnet flow.',
        );
        return;
    }
    const rpcUrl = process.env.MUSEBOOK_DEVNET_RPC_URL ?? 'https://api.devnet.solana.com';
    const rpc = createSolanaRpc(rpcUrl);

    // Fail closed unless the RPC really is devnet (mirrors the Rust test).
    const genesis = await rpc.getGenesisHash().send();
    if (genesis !== DEVNET_GENESIS_HASH) {
        throw new Error(`refusing to run: RPC genesis ${genesis} is not devnet`);
    }

    const payer = await loadKeypair(payerPath);
    const issuer = await loadKeypair(issuerPath);
    const merchant = process.env.MUSEBOOK_DEVNET_MERCHANT
        ? await loadKeypair(process.env.MUSEBOOK_DEVNET_MERCHANT)
        : await generateKeyPairSigner();
    const sessionSigner = await generateKeyPairSigner();

    // --- Price the plan -------------------------------------------------
    const asset = (process.env.MUSEBOOK_SUBSCRIPTION_ASSET ?? 'usdc').toLowerCase();
    let mint: string;
    let monthlyAmount: bigint;
    if (asset === 'clawd') {
        mint = process.env.MUSEBOOK_DEVNET_CLAWD_MINT ?? '';
        if (!mint) {
            throw new Error(
                'asset=clawd needs MUSEBOOK_DEVNET_CLAWD_MINT: the mainnet $CLAWD mint ' +
                    `${CLAWD_MINT} does not exist on devnet`,
            );
        }
        const price = await clawdUsdPrice();
        // Decimals come from the mint account itself, never assumed.
        const info = await rpc
            .getAccountInfo(address(mint), { encoding: 'jsonParsed' })
            .send();
        const decimals = (info.value?.data as { parsed?: { info?: { decimals?: number } } })?.parsed?.info?.decimals;
        if (typeof decimals !== 'number') throw new Error('could not read mint decimals');
        monthlyAmount = clawdBaseUnitsForPlan(price, decimals);
        console.log(`plan: $19.99 in $CLAWD @ $${price} = ${monthlyAmount} base units`);
    } else if (asset === 'usdc') {
        mint = DEVNET_USDC_MINT;
        monthlyAmount = PLAN_PRICE_USDC_BASE_UNITS;
        console.log(`plan: $19.99 in USDC = ${monthlyAmount} base units`);
    } else {
        throw new Error(`unknown MUSEBOOK_SUBSCRIPTION_ASSET "${asset}" (usdc|clawd)`);
    }

    // --- Merchant challenge --------------------------------------------
    // One month per authorization: cap == deposit == the monthly amount;
    // renewals re-authorize (server-side `creditMaxCap` bounds the cap).
    const method = serverSession({
        amount: monthlyAmount,
        channelProgram: PAYMENT_CHANNELS_V2_PROGRAM_ID,
        creditIssuerSigner: issuer,
        creditMaxCap: monthlyAmount,
        creditProgram: process.env.MUSEBOOK_DEVNET_PROGRAM,
        creditProvider: 'musebook',
        currency: mint,
        decimals: 6,
        gracePeriodSeconds: 900,
        idleTimeoutSeconds: 0,
        minimumDeposit: monthlyAmount,
        network: 'devnet',
        recipient: merchant.address,
        rpc: rpc as never,
        signer: merchant,
        suggestedDeposit: monthlyAmount,
    } as never) as unknown as { request: (options: { request: Record<string, unknown> }) => Promise<SessionRequest> };
    const challenge = await method.request({ request: {} });
    if (
        challenge.methodDetails.creditProvider !== 'musebook' ||
        challenge.methodDetails.creditIssuer !== issuer.address ||
        challenge.methodDetails.channelVersion !== 2
    ) {
        throw new Error('challenge is not the expected musebook credit challenge');
    }
    console.log(`challenge: creditProvider=musebook issuer=${issuer.address} channelProgram=${PAYMENT_CHANNELS_V2_PROGRAM_ID}`);

    // --- Derive the credit open -----------------------------------------
    const open = await derivePaymentChannelOpen({
        authorizedSigner: sessionSigner.address,
        creditProgram: process.env.MUSEBOOK_DEVNET_PROGRAM,
        payer: payer.address,
        request: challenge,
    });
    if (!open.channelHooks) throw new Error('derived open is missing its credit hooks');
    console.log(`channel: ${open.channelId} deposit=${open.deposit}`);

    // --- Authorize -------------------------------------------------------
    // [Approve(cap), authorize] — the owner signs both; the issuer
    // co-signs `authorize` (the server's half of the flow).
    const authorization = await creditAuthorizationInstructions({
        authorizedSigner: sessionSigner.address,
        open,
        request: challenge,
        terms: {
            cap: monthlyAmount,
            expiresAtSlot: BigInt(open.openSlot) + MAX_AUTHORIZATION_SLOTS,
            nonce: 0n,
        },
    });
    const authorize = authorization[1]!;
    const authorizeWithSigners: Instruction = {
        ...authorize,
        accounts: authorize.accounts?.map((account, index) =>
            index === 0
                ? { ...account, signer: payer }
                : index === 1
                  ? { ...account, signer: issuer }
                  : account,
        ),
    };
    const latest = await rpc.getLatestBlockhash().send();
    const authorizationMessage = pipe(
        createTransactionMessage({ version: 0 }),
        message => setTransactionMessageFeePayerSigner(payer, message),
        message =>
            setTransactionMessageLifetimeUsingBlockhash(
                { blockhash: latest.value.blockhash, lastValidBlockHeight: latest.value.lastValidBlockHeight },
                message,
            ),
        message =>
            appendTransactionMessageInstructions(
                [computeUnitLimit(MUSEBOOK_COMPUTE_UNIT_LIMIT), authorization[0]!, authorizeWithSigners],
                message,
            ),
    );
    const authorizationSignature = await sendAndConfirm(rpc, authorizationMessage);
    console.log(`authorized: ${authorizationSignature}`);

    // --- Open the hooked channel ----------------------------------------
    // Base V1 open instruction, assembled exactly as the SDK's client
    // builder assembles it, then transformed to OpenWithHooks by the
    // local V2 port (the SDK has no V2 generated client yet).
    const mintAddress = address(mint);
    const tokenProgram = address(TOKEN_PROGRAM);
    const [payerTokenAccount] = await findAssociatedTokenPda({ mint: mintAddress, owner: payer.address, tokenProgram });
    const [channelTokenAccount] = await findAssociatedTokenPda({
        mint: mintAddress,
        owner: address(open.channelId),
        tokenProgram,
    });
    const [eventAuthority] = await getProgramDerivedAddress({
        programAddress: address(PAYMENT_CHANNELS_V2_PROGRAM_ID),
        seeds: [getUtf8Encoder().encode('event_authority')],
    });
    // Open args: [discriminator=1][salt u64][deposit u64][gracePeriod u32]
    // [openSlot u64][recipients: u32 count + (pubkey, bps u16) entries] —
    // one recipient here: the merchant at the full 10_000 bps share.
    const openData = new Uint8Array(1 + 8 + 8 + 4 + 8 + 4 + 34);
    {
        const view = new DataView(openData.buffer);
        openData[0] = 1;
        view.setBigUint64(1, BigInt(open.salt), true);
        view.setBigUint64(9, BigInt(open.deposit), true);
        view.setUint32(17, open.gracePeriod, true);
        view.setBigUint64(21, BigInt(open.openSlot), true);
        view.setUint32(29, 1, true);
        openData.set(new Uint8Array(getAddressEncoder().encode(merchant.address)), 33);
        view.setUint16(65, 10_000, true);
    }
    const baseOpen: Instruction = {
        accounts: [
            { address: payer.address, role: AccountRole.WRITABLE_SIGNER },
            { address: payer.address, role: AccountRole.WRITABLE_SIGNER }, // rentPayer == payer (unsponsored)
            { address: merchant.address, role: AccountRole.READONLY },
            { address: mintAddress, role: AccountRole.READONLY },
            { address: sessionSigner.address, role: AccountRole.READONLY },
            { address: address(open.channelId), role: AccountRole.WRITABLE },
            { address: payerTokenAccount, role: AccountRole.WRITABLE },
            { address: channelTokenAccount, role: AccountRole.WRITABLE },
            { address: tokenProgram, role: AccountRole.READONLY },
            { address: address(SYSTEM_PROGRAM), role: AccountRole.READONLY },
            { address: address(RENT_SYSVAR), role: AccountRole.READONLY },
            { address: address(ASSOCIATED_TOKEN_PROGRAM), role: AccountRole.READONLY },
            { address: eventAuthority, role: AccountRole.READONLY },
            { address: address(PAYMENT_CHANNELS_V2_PROGRAM_ID), role: AccountRole.READONLY },
        ],
        data: openData,
        programAddress: address(PAYMENT_CHANNELS_V2_PROGRAM_ID),
    };
    const hookedOpen = await buildOpenWithHooks(baseOpen, open.channelHooks, open.channelId);
    const openMessage = pipe(
        createTransactionMessage({ version: 0 }),
        message => setTransactionMessageFeePayerSigner(payer, message),
        message =>
            setTransactionMessageLifetimeUsingBlockhash(
                {
                    blockhash: challenge.methodDetails.recentBlockhash as never,
                    lastValidBlockHeight: latest.value.lastValidBlockHeight,
                },
                message,
            ),
        message => appendTransactionMessageInstructions([computeUnitLimit(MUSEBOOK_COMPUTE_UNIT_LIMIT), hookedOpen], message),
    );
    const openSignature = await sendAndConfirm(rpc, openMessage);
    console.log(`opened: ${openSignature}`);

    // --- Charge the month -------------------------------------------------
    // The deposit *is* the first month's backing (deposit-first credits):
    // the subscriber's session key vouchers the full monthly amount and
    // the merchant verifies it against the channel terms.
    const session = new ActiveSession({
        channelId: open.channelId,
        cumulative: 0n,
        expiresAt: DEFAULT_SESSION_EXPIRES_AT,
        signer: sessionSigner,
    });
    const voucher = await session.signVoucher(monthlyAmount);
    const verdict = await verifyVoucherForChannel({
        deposit: monthlyAmount,
        signed: voucher,
        state: {
            authorizedSigner: sessionSigner.address,
            channelId: open.channelId,
            committedDeliveries: [],
            cumulative: 0n,
            deposit: monthlyAmount,
            nextDeliverySequence: 0n,
            payer: payer.address,
            pendingDeliveries: [],
            processedUses: [],
            rentPayer: payer.address,
            sealed: false,
            settledOnChain: 0n,
            spentAmount: 0n,
        },
    });
    console.log(
        `charge: voucher for ${monthlyAmount} base units -> ${verdict.status}` +
            (verdict.status === 'rejected' ? ` (${verdict.reason}: ${verdict.detail})` : ''),
    );
    if (verdict.status === 'rejected') throw new Error('monthly voucher was rejected');

    // --- Close / settle / refund ------------------------------------------
    // Settlement must wait out the channel's grace period (900s here):
    // the payer requests close now; after the grace period the operator
    // runs settle_and_seal, then DistributeWithHooks (discriminator 12,
    // `v2-hooks.ts`) and WithdrawPayerWithHooks (discriminator 13). The
    // hooked distribution returns the unspent remainder toward the
    // provider ledger vault; **credits are restored only from that
    // actually recovered refund** — if distribution recovers zero, zero
    // credits are restored. See README.md for the operator sequence.
    console.log(
        'close: request close from the payer, wait out the 900s grace period, then settle with the hooked ' +
            'distribute/withdraw builders in v2-hooks.ts. Refund credits = the recovered refund amount only.',
    );
}

main().catch(error => {
    console.error(error instanceof Error ? error.message : error);
    process.exit(1);
});
