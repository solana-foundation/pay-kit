/**
 * Solana payment link content script.
 *
 * Renders a "Continue with Solana" button inside mppx's payment page.
 * mppx handles the outer chrome (amount, description, expiry, theming).
 * This script only provides the payment action button.
 */

import { findAssociatedTokenPda } from '@solana-program/token';
import { address } from '@solana/kit';
import { getWallets } from '@wallet-standard/app';
import type { Wallet, WalletAccount } from '@wallet-standard/base';

import {
  appendMemoInstruction,
  assertPageCanBuildVersion,
  bs58Decode,
  bs58Encode,
  compileMessage,
  computeBudgetInstructions,
  createAtaIdempotent,
  type Instruction,
  shouldCreateSplitAta,
  systemTransfer,
  tokenTransferChecked,
  unsignedTransaction,
} from './transaction.js';

// ── Read embedded data (supports both mppx and standalone templates) ──

const dataEl = document.getElementById('__MPPX_DATA__') ?? document.getElementById('__MPP_DATA__');
if (!dataEl?.textContent) throw new Error('Missing embedded data element');

const parsedData = JSON.parse(dataEl.textContent);

// Normalize: mppx <= 0.5.5 embeds { challenge: { request: {decoded} } };
// mppx >= 0.5.8 keys those entries by challenge id
// ({ <challengeId>: { label, challenge, ... }, ... }) — prefer the solana
// entry, fall back to the first. Standalone embeds
// { challenge: { request: "base64url" }, network, rpcUrl }.
const dataEntries = Object.values(parsedData).filter(
  (entry: any) => entry?.challenge !== undefined,
) as any[];
const rawData =
  parsedData.challenge !== undefined
    ? parsedData
    : (dataEntries.find(entry => entry.label === 'solana') ?? dataEntries[0] ?? parsedData);
const isMppx = typeof rawData.challenge?.request === 'object';
const challenge = rawData.challenge;
const request = isMppx
  ? challenge.request
  : JSON.parse(atob(challenge.request.replace(/-/g, '+').replace(/_/g, '/')));
const md = request.methodDetails ?? {};
const network = md.network ?? rawData.network ?? 'mainnet-beta';

// For credential building: get the request as base64url string.
// Standalone (__MPP_DATA__): challenge.request is already base64url — use as-is for HMAC integrity.
// mppx (__MPPX_DATA__): challenge.request is decoded — re-encode.
const requestB64ForCredential: string = isMppx
  ? base64UrlEncode(JSON.stringify(challenge.request))
  : challenge.request;
const testMode = network === 'devnet' || network === 'localnet';

// ── Render button ──

const root = document.getElementById('root');
if (!root) throw new Error('Missing #root');

// Solana logo SVG (monochrome, works in light/dark mode)
const SOLANA_LOGO = `<svg width="20" height="20" viewBox="0 0 397 312" xmlns="http://www.w3.org/2000/svg" style="display:inline-block;vertical-align:middle;margin-right:8px"><defs><linearGradient id="sg" x1="360" y1="11" x2="141" y2="310" gradientUnits="userSpaceOnUse"><stop stop-color="#00FFA3"/><stop offset="1" stop-color="#DC1FFF"/></linearGradient></defs><path d="M64.6 237.9c2.4-2.4 5.7-3.8 9.2-3.8h317.4c5.8 0 8.7 7 4.6 11.1l-62.7 62.7c-2.4 2.4-5.7 3.8-9.2 3.8H6.5c-5.8 0-8.7-7-4.6-11.1l62.7-62.7z" fill="url(#sg)"/><path d="M64.6 3.8C67.1 1.4 70.4 0 73.8 0h317.4c5.8 0 8.7 7 4.6 11.1l-62.7 62.7c-2.4 2.4-5.7 3.8-9.2 3.8H6.5c-5.8 0-8.7-7-4.6-11.1L64.6 3.8z" fill="url(#sg)"/><path d="M333.1 120.1c-2.4-2.4-5.7-3.8-9.2-3.8H6.5c-5.8 0-8.7 7-4.6 11.1l62.7 62.7c2.4 2.4 5.7 3.8 9.2 3.8h317.4c5.8 0 8.7-7 4.6-11.1l-62.7-62.7z" fill="url(#sg)"/></svg>`;

const btn = document.createElement('button');
btn.innerHTML = SOLANA_LOGO;
btn.append(' Continue with Solana');
if (testMode) {
  const testBadge = document.createElement('span');
  testBadge.setAttribute('style', 'font-size:10px;font-weight:500;background:var(--mppx-surface, #f5f5f5);color:var(--mppx-muted, #666);padding:2px 6px;border-radius:4px;margin-left:8px');
  testBadge.textContent = network;
  btn.appendChild(testBadge);
}
btn.setAttribute('style', [
  'display:flex', 'align-items:center', 'justify-content:center',
  'width:100%', 'padding:14px 24px',
  'border:none', 'border-radius:var(--mppx-radius, 8px)',
  'font-size:16px', 'font-weight:600', 'cursor:pointer',
  'font-family:inherit',
  'background:var(--mppx-accent, #000)', 'color:var(--mppx-background, #fff)',
  'transition:opacity 0.15s',
].join(';'));
btn.onmouseenter = () => { btn.style.opacity = '0.85'; };
btn.onmouseleave = () => { btn.style.opacity = '1'; };

const statusEl = document.createElement('div');
statusEl.setAttribute('style', 'text-align:center;font-size:13px;margin-top:8px;color:var(--mppx-muted, #666);min-height:20px');

root.appendChild(btn);
root.appendChild(statusEl);

// ── Payment flow ──

btn.onclick = async () => {
  btn.disabled = true;
  btn.style.opacity = '0.6';
  btn.style.cursor = 'wait';

  try {
    if (testMode) {
      await payTestMode();
    } else {
      await payWithWallet();
    }
  } catch (err: any) {
    console.error('[pay.sh] Payment error:', err);
    statusEl.textContent = err.message ?? 'Payment failed';
    statusEl.style.color = 'var(--mppx-negative, #e53e3e)';
    btn.disabled = false;
    btn.style.opacity = '1';
    btn.style.cursor = 'pointer';
  }
};

// ── Wallet payment (production) ──

async function payWithWallet() {
  statusEl.textContent = 'Looking for wallets...';

  // Discover Wallet Standard wallets
  const { get, on } = getWallets();
  let wallets = get();

  // If no wallets yet, wait briefly for late registrations
  if (wallets.length === 0) {
    await new Promise<void>(resolve => {
      const unsub = on('register', () => { wallets = get(); if (wallets.length > 0) { unsub(); resolve(); } });
      setTimeout(() => { unsub(); resolve(); }, 2000);
    });
  }

  // Filter to Solana-compatible wallets
  const solanaWallets = wallets.filter(w =>
    w.chains?.some((c: string) => c.startsWith('solana:'))
  );

  if (solanaWallets.length === 0) {
    throw new Error('No Solana wallet found. Install Phantom, Solflare, or another Solana wallet.');
  }

  // Show wallet picker if multiple, or auto-select if one
  let selectedWallet: Wallet;
  if (solanaWallets.length === 1) {
    selectedWallet = solanaWallets[0];
  } else {
    selectedWallet = await pickWallet(solanaWallets);
  }

  statusEl.textContent = `Connecting to ${selectedWallet.name}...`;

  // Connect
  const connectFeature = selectedWallet.features['standard:connect'] as any;
  if (!connectFeature) throw new Error(`${selectedWallet.name} doesn't support connect`);
  const { accounts } = await connectFeature.connect();
  if (!accounts || accounts.length === 0) throw new Error('No accounts returned');
  const account: WalletAccount = accounts[0];
  const walletPubkey = new Uint8Array(account.publicKey);
  const walletB58 = bs58Encode(walletPubkey);

  // Build transaction
  statusEl.textContent = 'Building transaction...';
  assertPageCanBuildVersion(md.transactionVersions);
  const rpcUrl = getRpcUrl(network);
  const mint = resolveMint(request.currency, network);
  const isNativeSOL = mint === null;
  const tokenProg = md.tokenProgram ?? defaultTokenProgram(request.currency, network);
  const blockhash = md.recentBlockhash ?? (await rpcCall(rpcUrl, 'getLatestBlockhash', [{ commitment: 'confirmed' }])).value.blockhash;
  const blockhashBytes = bs58Decode(blockhash);

  const amount = BigInt(request.amount);
  const splits = md.splits ?? [];
  let splitTotal = 0n;
  for (const s of splits) splitTotal += BigInt(s.amount);
  const primaryAmount = amount - splitTotal;
  const recipientPubkey = bs58Decode(request.recipient);

  const hasSeparateFeePayer = md.feePayer === true && !!md.feePayerKey;
  const feePayerPubkey = hasSeparateFeePayer ? bs58Decode(md.feePayerKey!) : walletPubkey;

  const ataPayer = hasSeparateFeePayer ? feePayerPubkey : walletPubkey;
  let instructions: Instruction[] = computeBudgetInstructions();
  if (isNativeSOL) {
    instructions.push(systemTransfer(walletPubkey, recipientPubkey, primaryAmount));
    appendMemoInstruction(instructions, request.externalId);
    for (const s of splits) {
      instructions.push(systemTransfer(walletPubkey, bs58Decode(s.recipient), BigInt(s.amount)));
      appendMemoInstruction(instructions, s.memo);
    }
  } else {
    const mintPubkey = bs58Decode(mint!);
    const decimals = md.decimals ?? 6;
    const sourceAta = bs58Decode(await findATA(walletB58, mint!, tokenProg));
    const destAta = bs58Decode(await findATA(request.recipient, mint!, tokenProg));
    instructions.push(tokenTransferChecked(sourceAta, mintPubkey, destAta, walletPubkey, primaryAmount, decimals, tokenProg));
    appendMemoInstruction(instructions, request.externalId);
    for (const s of splits) {
      const splitRecipient = bs58Decode(s.recipient);
      const splitAta = bs58Decode(await findATA(s.recipient, mint!, tokenProg));
      if (shouldCreateSplitAta(hasSeparateFeePayer, s)) {
        instructions.push(createAtaIdempotent(ataPayer, splitAta, splitRecipient, mintPubkey, tokenProg));
      }
      instructions.push(tokenTransferChecked(sourceAta, mintPubkey, splitAta, walletPubkey, BigInt(s.amount), decimals, tokenProg));
      appendMemoInstruction(instructions, s.memo);
    }
  }

  // Compile message
  const messageBytes = compileMessage(instructions, feePayerPubkey, walletPubkey, blockhashBytes);

  // Build full transaction with empty signature slots
  const txBytes = unsignedTransaction(messageBytes, hasSeparateFeePayer ? 2 : 1);

  // Sign with wallet
  statusEl.textContent = `Waiting for ${selectedWallet.name} to sign...`;
  const signFeature = selectedWallet.features['solana:signTransaction'] as any;
  if (!signFeature) throw new Error(`${selectedWallet.name} doesn't support signTransaction`);

  const [{ signedTransaction }] = await signFeature.signTransaction({
    account,
    transaction: txBytes,
    chain: `solana:${network}`,
  });

  // Submit via service worker
  statusEl.textContent = 'Submitting payment...';
  const txBase64 = btoa(String.fromCharCode(...new Uint8Array(signedTransaction)));
  const requestB64 = requestB64ForCredential;
  const credential = {
    challenge: { id: challenge.id, intent: challenge.intent, method: challenge.method, realm: challenge.realm, request: requestB64, ...(challenge.expires && { expires: challenge.expires }), ...(challenge.description && { description: challenge.description }) },
    payload: { transaction: txBase64, type: 'transaction' },
  };
  const credentialB64 = base64UrlEncode(JSON.stringify(credential));
  await submitViaServiceWorker(`Payment ${credentialB64}`);
}

// Wallet picker UI
function pickWallet(wallets: readonly Wallet[]): Promise<Wallet> {
  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.setAttribute('style', 'position:fixed;inset:0;background:rgba(0,0,0,0.5);display:flex;align-items:center;justify-content:center;z-index:9999');

    const modal = document.createElement('div');
    modal.setAttribute('style', 'background:var(--mppx-background, #fff);border-radius:var(--mppx-radius, 8px);padding:24px;max-width:320px;width:100%;font-family:inherit');
    modal.innerHTML = '<div style="font-size:16px;font-weight:600;margin-bottom:16px;color:var(--mppx-foreground, #000)">Select a wallet</div>';

    for (const wallet of wallets) {
      const item = document.createElement('button');
      if (wallet.icon) {
        const icon = document.createElement('img');
        icon.src = wallet.icon;
        icon.width = 24;
        icon.height = 24;
        icon.setAttribute('style', 'border-radius:4px;margin-right:10px');
        item.appendChild(icon);
      }
      item.append(wallet.name);
      item.setAttribute('style', 'display:flex;align-items:center;width:100%;padding:12px;margin-bottom:8px;border:1px solid var(--mppx-border, #e5e5e5);border-radius:var(--mppx-radius, 6px);background:var(--mppx-surface, #f5f5f5);color:var(--mppx-foreground, #000);font-size:15px;cursor:pointer;font-family:inherit');
      item.onclick = () => { overlay.remove(); resolve(wallet); };
      modal.appendChild(item);
    }

    overlay.appendChild(modal);
    overlay.onclick = (e) => { if (e.target === overlay) overlay.remove(); };
    document.body.appendChild(overlay);
  });
}

// ── Test mode payment ──

async function payTestMode() {
  assertPageCanBuildVersion(md.transactionVersions);
  statusEl.textContent = 'Generating keypair...';

  const rpcUrl = getRpcUrl(network);
  const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey));
  const publicKeyB58 = bs58Encode(publicKeyRaw);

  // Fund via surfpool cheatcodes
  statusEl.textContent = 'Funding test account...';
  await rpcCall(rpcUrl, 'surfnet_setAccount', [
    publicKeyB58,
    { lamports: 1_000_000_000, data: '', executable: false, owner: '11111111111111111111111111111111', rentEpoch: 0 },
  ]);

  const mint = resolveMint(request.currency, network);
  const isNativeSOL = mint === null;
  const tokenProg = md.tokenProgram ?? defaultTokenProgram(request.currency, network);

  if (!isNativeSOL) {
    await rpcCall(rpcUrl, 'surfnet_setTokenAccount', [publicKeyB58, mint, { amount: Number(BigInt(request.amount)), state: 'initialized' }, tokenProg]);
    await rpcCall(rpcUrl, 'surfnet_setTokenAccount', [request.recipient, mint, { amount: 0, state: 'initialized' }, tokenProg]);
  }

  // Build transaction
  statusEl.textContent = 'Building transaction...';
  const blockhash = md.recentBlockhash ?? (await rpcCall(rpcUrl, 'getLatestBlockhash', [{ commitment: 'confirmed' }])).value.blockhash;
  const blockhashBytes = bs58Decode(blockhash);

  const amount = BigInt(request.amount);
  const splits = md.splits ?? [];
  let splitTotal = 0n;
  for (const s of splits) splitTotal += BigInt(s.amount);
  const primaryAmount = amount - splitTotal;

  const recipientPubkey = bs58Decode(request.recipient);
  const hasSeparateFeePayer = md.feePayer === true && !!md.feePayerKey;
  const feePayerPubkey = hasSeparateFeePayer ? bs58Decode(md.feePayerKey!) : publicKeyRaw;

  const ataPayer = hasSeparateFeePayer ? feePayerPubkey : publicKeyRaw;
  let instructions: Instruction[] = computeBudgetInstructions();
  if (isNativeSOL) {
    instructions.push(systemTransfer(publicKeyRaw, recipientPubkey, primaryAmount));
    appendMemoInstruction(instructions, request.externalId);
    for (const s of splits) {
      instructions.push(systemTransfer(publicKeyRaw, bs58Decode(s.recipient), BigInt(s.amount)));
      appendMemoInstruction(instructions, s.memo);
    }
  } else {
    const mintPubkey = bs58Decode(mint!);
    const decimals = md.decimals ?? 6;
    const sourceAta = bs58Decode(await findATA(publicKeyB58, mint!, tokenProg));
    const destAta = bs58Decode(await findATA(request.recipient, mint!, tokenProg));
    instructions.push(tokenTransferChecked(sourceAta, mintPubkey, destAta, publicKeyRaw, primaryAmount, decimals, tokenProg));
    appendMemoInstruction(instructions, request.externalId);
    for (const s of splits) {
      const splitRecipient = bs58Decode(s.recipient);
      const splitAta = bs58Decode(await findATA(s.recipient, mint!, tokenProg));
      if (shouldCreateSplitAta(hasSeparateFeePayer, s)) {
        instructions.push(createAtaIdempotent(ataPayer, splitAta, splitRecipient, mintPubkey, tokenProg));
      }
      instructions.push(tokenTransferChecked(sourceAta, mintPubkey, splitAta, publicKeyRaw, BigInt(s.amount), decimals, tokenProg));
      appendMemoInstruction(instructions, s.memo);
    }
  }

  // Compile + sign
  statusEl.textContent = 'Signing transaction...';
  const messageBytes = compileMessage(instructions, feePayerPubkey, publicKeyRaw, blockhashBytes);
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', keyPair.privateKey, messageBytes));

  const txBytes = unsignedTransaction(messageBytes, hasSeparateFeePayer ? 2 : 1);
  if (hasSeparateFeePayer) {
    txBytes.set(signature, 1 + 64); // slot 1: client sig
  } else {
    txBytes.set(signature, 1); // slot 0: client sig
  }

  // Build credential
  statusEl.textContent = 'Submitting payment...';
  const txBase64 = btoa(String.fromCharCode(...txBytes));
  const requestB64 = requestB64ForCredential;
  const credential = {
    challenge: { id: challenge.id, intent: challenge.intent, method: challenge.method, realm: challenge.realm, request: requestB64, ...(challenge.expires && { expires: challenge.expires }), ...(challenge.description && { description: challenge.description }) },
    payload: { transaction: txBase64, type: 'transaction' },
  };
  const credentialB64 = base64UrlEncode(JSON.stringify(credential));

  // Submit via mppx service worker
  await submitViaServiceWorker(`Payment ${credentialB64}`);
}

// ── Service worker (mppx native) ──

async function submitViaServiceWorker(credentialHeader: string) {
  const url = new URL(window.location.href);
  // mppx uses __mppx_worker, standalone Rust/Go/Lua use __mpp_worker
  const swParam = isMppx ? '__mppx_worker' : '__mpp_worker';
  url.searchParams.set(swParam, '1');

  const reg = await navigator.serviceWorker.register(url.toString(), { scope: '/' });
  const worker = reg.installing ?? reg.waiting ?? reg.active;
  if (!worker) throw new Error('Service worker not available');

  await new Promise<void>(resolve => {
    if (worker.state === 'activated') return resolve();
    worker.addEventListener('statechange', () => { if (worker.state === 'activated') resolve(); });
  });

  const active = reg.active;
  if (!active) throw new Error('Service worker not active');

  await new Promise<void>((resolve, reject) => {
    const ch = new MessageChannel();
    ch.port1.onmessage = e => {
      // mppx SW acks with "ack", standalone SW acks with { received: true }
      if (e.data === 'ack' || e.data?.received) resolve();
      else reject(new Error('SW nack'));
    };
    // mppx SW expects { credential: "Payment <b64>" }, standalone expects { credential: "<b64>" }
    active.postMessage({ credential: credentialHeader }, [ch.port2]);
  });

  window.location.reload();
}

// ── Crypto helpers ──

function base64UrlEncode(data: string): string { return btoa(String.fromCharCode(...new TextEncoder().encode(data))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }

// ── RPC ──

async function rpcCall(url: string, method: string, params: unknown[]) {
  const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }) });
  const j = await r.json(); if (j.error) throw new Error(`${method}: ${j.error.message}`); return j.result;
}

function getRpcUrl(n: string) {
  // Prefer the RPC URL embedded in the challenge data (set by the server).
  if (rawData.rpcUrl) return rawData.rpcUrl;
  return n === 'devnet' ? 'https://api.devnet.solana.com' : n === 'localnet' ? 'http://localhost:8899' : 'https://api.mainnet-beta.solana.com';
}

const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const TOKEN_2022_PROGRAM = 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb';
const STABLECOIN_MINTS: Record<string, Record<string, string>> = {
  USDC: {
    devnet: '4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU',
    'mainnet-beta': 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v',
  },
  USDT: {
    'mainnet-beta': 'Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB',
  },
  USDG: {
    devnet: '4F6PM96JJxngmHnZLBh9n58RH4aTVNWvDs2nuwrT5BP7',
    'mainnet-beta': '2u1tszSeqZ3qBWF3uNGPFc8TzMk2tdiwknnRMWGWjGWH',
  },
  PYUSD: {
    devnet: 'CXk2AMBfi3TwaEL2468s6zP8xq9NxTXjp9gjMgzeUynM',
    'mainnet-beta': '2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo',
  },
  CASH: {
    'mainnet-beta': 'CASHx9KJUStyftLFWGvEVf59SGeG9sh5FfcnZMVPCASH',
  },
};
const TOKEN_2022_STABLECOIN_SYMBOLS = new Set(['PYUSD', 'USDG', 'CASH']);

function resolveMint(currency: string, network: string): string | null {
  if (currency.toLowerCase() === 'sol') return null;
  if (currency.length >= 32) return currency;
  const mints = STABLECOIN_MINTS[currency.toUpperCase()];
  return mints?.[network] ?? mints?.['mainnet-beta'] ?? currency;
}

function stablecoinSymbol(currency: string, network: string): string | undefined {
  const normalized = currency.toUpperCase();
  if (STABLECOIN_MINTS[normalized]) return normalized;
  const resolved = resolveMint(currency, network);
  if (!resolved) return undefined;
  for (const [symbol, mints] of Object.entries(STABLECOIN_MINTS)) {
    if (Object.values(mints).includes(resolved)) return symbol;
  }
}

function defaultTokenProgram(currency: string, network: string): string {
  const symbol = stablecoinSymbol(currency, network);
  return symbol && TOKEN_2022_STABLECOIN_SYMBOLS.has(symbol) ? TOKEN_2022_PROGRAM : TOKEN_PROGRAM;
}

async function findATA(owner: string, mint: string, tokenProg: string) {
  const [ata] = await findAssociatedTokenPda({ owner: address(owner), mint: address(mint), tokenProgram: address(tokenProg) });
  return ata;
}

