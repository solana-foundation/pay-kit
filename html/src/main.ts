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
const testBadge = testMode ? `<span style="font-size:10px;font-weight:500;background:var(--mppx-surface, #f5f5f5);color:var(--mppx-muted, #666);padding:2px 6px;border-radius:4px;margin-left:8px">${network}</span>` : '';
btn.innerHTML = `${SOLANA_LOGO} Continue with Solana${testBadge}`;
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
  const numSigs = hasSeparateFeePayer ? 2 : 1;
  const txBytes = new Uint8Array(1 + numSigs * 64 + messageBytes.length);
  txBytes[0] = numSigs;
  txBytes.set(messageBytes, 1 + numSigs * 64);

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
      const icon = wallet.icon ? `<img src="${wallet.icon}" width="24" height="24" style="border-radius:4px;margin-right:10px">` : '';
      item.innerHTML = `${icon}${wallet.name}`;
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

  const numSigs = hasSeparateFeePayer ? 2 : 1;
  const txBytes = new Uint8Array(1 + numSigs * 64 + messageBytes.length);
  txBytes[0] = numSigs;
  if (hasSeparateFeePayer) {
    txBytes.set(signature, 1 + 64); // slot 1: client sig
  } else {
    txBytes.set(signature, 1); // slot 0: client sig
  }
  txBytes.set(messageBytes, 1 + numSigs * 64);

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

const BS58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function bs58Decode(str: string): Uint8Array {
  const bytes: number[] = [];
  for (const ch of str) { let c = BS58.indexOf(ch); if (c < 0) throw new Error('bad b58'); for (let j = 0; j < bytes.length; j++) { c += bytes[j] * 58; bytes[j] = c & 0xff; c >>= 8; } while (c > 0) { bytes.push(c & 0xff); c >>= 8; } }
  for (const ch of str) { if (ch !== '1') break; bytes.push(0); }
  return new Uint8Array(bytes.reverse());
}

function bs58Encode(bytes: Uint8Array): string {
  const digits = [0];
  for (const b of bytes) { let c = b; for (let j = 0; j < digits.length; j++) { c += digits[j] << 8; digits[j] = c % 58; c = (c / 58) | 0; } while (c > 0) { digits.push(c % 58); c = (c / 58) | 0; } }
  let r = ''; for (const b of bytes) { if (b !== 0) break; r += '1'; }
  for (let i = digits.length - 1; i >= 0; i--) r += BS58[digits[i]];
  return r;
}

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

// ── Transaction building ──

type Instruction = { programId: string; accounts: { pubkey: Uint8Array; isSigner: boolean; isWritable: boolean }[]; data: Uint8Array };
type Split = { recipient: string; amount: string; ataCreationRequired?: boolean; memo?: string };

const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111';
const ATA_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
const SYSTEM_PROGRAM = '11111111111111111111111111111111';
const MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';

/** SetComputeUnitPrice(1) + SetComputeUnitLimit(200_000) */
function computeBudgetInstructions(): Instruction[] {
  const price = new Uint8Array(9); price[0] = 3; price[1] = 1;
  const limit = new Uint8Array(5); limit[0] = 2; new DataView(limit.buffer).setUint32(1, 200_000, true);
  return [
    { programId: COMPUTE_BUDGET_PROGRAM, accounts: [], data: price },
    { programId: COMPUTE_BUDGET_PROGRAM, accounts: [], data: limit },
  ];
}

/** Idempotent ATA creation (discriminator 1) */
function createAtaIdempotent(payer: Uint8Array, ata: Uint8Array, owner: Uint8Array, mint: Uint8Array, tokenProg: string): Instruction {
  return {
    programId: ATA_PROGRAM,
    data: new Uint8Array([1]),
    accounts: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: ata, isSigner: false, isWritable: true },
      { pubkey: owner, isSigner: false, isWritable: false },
      { pubkey: mint, isSigner: false, isWritable: false },
      { pubkey: bs58Decode(SYSTEM_PROGRAM), isSigner: false, isWritable: false },
      { pubkey: bs58Decode(tokenProg), isSigner: false, isWritable: false },
    ],
  };
}

function shouldCreateSplitAta(hasSeparateFeePayer: boolean, split: Split): boolean {
  return !hasSeparateFeePayer || split.ataCreationRequired === true;
}

function appendMemoInstruction(instructions: Instruction[], memo: string | undefined) {
  if (!memo) return;
  const data = new TextEncoder().encode(memo);
  if (data.byteLength > 566) throw new Error('memo cannot exceed 566 bytes');
  instructions.push({ programId: MEMO_PROGRAM, accounts: [], data });
}

function systemTransfer(from: Uint8Array, to: Uint8Array, lamports: bigint): Instruction {
  const d = new Uint8Array(12); new DataView(d.buffer).setUint32(0, 2, true); new DataView(d.buffer).setBigUint64(4, lamports, true);
  return { programId: '11111111111111111111111111111111', accounts: [{ pubkey: from, isSigner: true, isWritable: true }, { pubkey: to, isSigner: false, isWritable: true }], data: d };
}

function tokenTransferChecked(src: Uint8Array, mint: Uint8Array, dst: Uint8Array, auth: Uint8Array, amount: bigint, decimals: number, prog: string): Instruction {
  const d = new Uint8Array(10); d[0] = 12; new DataView(d.buffer).setBigUint64(1, amount, true); d[9] = decimals;
  return { programId: prog, accounts: [{ pubkey: src, isSigner: false, isWritable: true }, { pubkey: mint, isSigner: false, isWritable: false }, { pubkey: dst, isSigner: false, isWritable: true }, { pubkey: auth, isSigner: true, isWritable: false }], data: d };
}

function hex(k: Uint8Array) { return Array.from(k).map(b => b.toString(16).padStart(2, '0')).join(''); }
function compactU16(v: number): Uint8Array { if (v < 0x80) return new Uint8Array([v]); if (v < 0x4000) return new Uint8Array([v & 0x7f | 0x80, v >> 7]); return new Uint8Array([v & 0x7f | 0x80, (v >> 7) & 0x7f | 0x80, v >> 14]); }

function compileMessage(ixs: Instruction[], feePayer: Uint8Array, signer: Uint8Array, blockhash: Uint8Array): Uint8Array {
  const map = new Map<string, { pubkey: Uint8Array; isSigner: boolean; isWritable: boolean }>();
  const fpH = hex(feePayer); map.set(fpH, { pubkey: feePayer, isSigner: true, isWritable: true });
  const sH = hex(signer); if (sH !== fpH) map.set(sH, { pubkey: signer, isSigner: true, isWritable: true });
  const progs = new Set<string>();
  for (const ix of ixs) { progs.add(ix.programId); for (const a of ix.accounts) { const h = hex(a.pubkey); const e = map.get(h); if (e) { e.isSigner ||= a.isSigner; e.isWritable ||= a.isWritable; } else map.set(h, { ...a }); } }
  for (const p of progs) { const pk = bs58Decode(p); const h = hex(pk); if (!map.has(h)) map.set(h, { pubkey: pk, isSigner: false, isWritable: false }); }
  const all = [...map.values()]; const fp = all.find(a => hex(a.pubkey) === fpH)!; const rest = all.filter(a => hex(a.pubkey) !== fpH);
  const sw = rest.filter(a => a.isSigner && a.isWritable); const sr = rest.filter(a => a.isSigner && !a.isWritable);
  const uw = rest.filter(a => !a.isSigner && a.isWritable); const ur = rest.filter(a => !a.isSigner && !a.isWritable);
  const ordered = [fp, ...sw, ...sr, ...uw, ...ur];
  const idx = new Map<string, number>(); ordered.forEach((a, i) => idx.set(hex(a.pubkey), i));
  const cIxs = ixs.map(ix => ({ pi: idx.get(hex(bs58Decode(ix.programId)))!, ai: ix.accounts.map(a => idx.get(hex(a.pubkey))!), d: ix.data }));
  const parts: Uint8Array[] = [];
  parts.push(new Uint8Array([1 + sw.length + sr.length, sr.length, ur.length]));
  parts.push(compactU16(ordered.length)); for (const a of ordered) parts.push(a.pubkey);
  parts.push(blockhash);
  parts.push(compactU16(cIxs.length));
  for (const ix of cIxs) { parts.push(new Uint8Array([ix.pi])); parts.push(compactU16(ix.ai.length)); parts.push(new Uint8Array(ix.ai)); parts.push(compactU16(ix.d.length)); parts.push(ix.d); }
  const len = parts.reduce((s, p) => s + p.length, 0); const out = new Uint8Array(len); let off = 0; for (const p of parts) { out.set(p, off); off += p.length; } return out;
}
