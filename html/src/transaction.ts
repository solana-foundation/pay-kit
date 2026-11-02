/**
 * Pure transaction helpers for the Solana payment page: base58, instruction
 * builders and the version-0 message compiler. Kept free of DOM access so the
 * SDK test suites can build exactly what the page builds and run it through
 * their charge verifiers.
 */

/** Transaction message versions this page can build. */
export const PAGE_TRANSACTION_VERSION = 0;
const MESSAGE_VERSION_0_PREFIX = 0x80;

/**
 * Refuses a challenge whose `methodDetails.transactionVersions` does not
 * list version 0 (an absent field means `[0]`). The page builds version 0
 * only, so a version-1-only challenge cannot be paid from it.
 */
export function assertPageCanBuildVersion(transactionVersions: unknown): void {
  const accepted = transactionVersions === undefined ? [0] : transactionVersions;
  if (!Array.isArray(accepted) || !accepted.includes(PAGE_TRANSACTION_VERSION)) {
    throw new Error(
      `This payment page builds version-0 transactions, but the server accepts versions [${Array.isArray(accepted) ? accepted.join(', ') : String(accepted)}]. Pay with an MPP client instead.`,
    );
  }
}

/** Wire transaction with `numSigs` empty signature slots followed by the message. */
export function unsignedTransaction(message: Uint8Array, numSigs: number): Uint8Array {
  const tx = new Uint8Array(1 + numSigs * 64 + message.length);
  tx[0] = numSigs;
  tx.set(message, 1 + numSigs * 64);
  return tx;
}

const BS58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function bs58Decode(str: string): Uint8Array {
  const bytes: number[] = [];
  for (const ch of str) { let c = BS58.indexOf(ch); if (c < 0) throw new Error('bad b58'); for (let j = 0; j < bytes.length; j++) { c += bytes[j] * 58; bytes[j] = c & 0xff; c >>= 8; } while (c > 0) { bytes.push(c & 0xff); c >>= 8; } }
  for (const ch of str) { if (ch !== '1') break; bytes.push(0); }
  return new Uint8Array(bytes.reverse());
}

export function bs58Encode(bytes: Uint8Array): string {
  const digits = [0];
  for (const b of bytes) { let c = b; for (let j = 0; j < digits.length; j++) { c += digits[j] << 8; digits[j] = c % 58; c = (c / 58) | 0; } while (c > 0) { digits.push(c % 58); c = (c / 58) | 0; } }
  let r = ''; for (const b of bytes) { if (b !== 0) break; r += '1'; }
  for (let i = digits.length - 1; i >= 0; i--) r += BS58[digits[i]];
  return r;
}

export type Instruction = { programId: string; accounts: { pubkey: Uint8Array; isSigner: boolean; isWritable: boolean }[]; data: Uint8Array };
export type Split = { recipient: string; amount: string; ataCreationRequired?: boolean; memo?: string };

export const COMPUTE_BUDGET_PROGRAM = 'ComputeBudget111111111111111111111111111111';
export const ATA_PROGRAM = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL';
export const SYSTEM_PROGRAM = '11111111111111111111111111111111';
export const MEMO_PROGRAM = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';

/** SetComputeUnitPrice(1) + SetComputeUnitLimit(200_000) */
export function computeBudgetInstructions(): Instruction[] {
  const price = new Uint8Array(9); price[0] = 3; price[1] = 1;
  const limit = new Uint8Array(5); limit[0] = 2; new DataView(limit.buffer).setUint32(1, 200_000, true);
  return [
    { programId: COMPUTE_BUDGET_PROGRAM, accounts: [], data: price },
    { programId: COMPUTE_BUDGET_PROGRAM, accounts: [], data: limit },
  ];
}

/** Idempotent ATA creation (discriminator 1) */
export function createAtaIdempotent(payer: Uint8Array, ata: Uint8Array, owner: Uint8Array, mint: Uint8Array, tokenProg: string): Instruction {
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

export function shouldCreateSplitAta(hasSeparateFeePayer: boolean, split: Split): boolean {
  return !hasSeparateFeePayer || split.ataCreationRequired === true;
}

export function appendMemoInstruction(instructions: Instruction[], memo: string | undefined) {
  if (!memo) return;
  const data = new TextEncoder().encode(memo);
  if (data.byteLength > 566) throw new Error('memo cannot exceed 566 bytes');
  instructions.push({ programId: MEMO_PROGRAM, accounts: [], data });
}

export function systemTransfer(from: Uint8Array, to: Uint8Array, lamports: bigint): Instruction {
  const d = new Uint8Array(12); new DataView(d.buffer).setUint32(0, 2, true); new DataView(d.buffer).setBigUint64(4, lamports, true);
  return { programId: '11111111111111111111111111111111', accounts: [{ pubkey: from, isSigner: true, isWritable: true }, { pubkey: to, isSigner: false, isWritable: true }], data: d };
}

export function tokenTransferChecked(src: Uint8Array, mint: Uint8Array, dst: Uint8Array, auth: Uint8Array, amount: bigint, decimals: number, prog: string): Instruction {
  const d = new Uint8Array(10); d[0] = 12; new DataView(d.buffer).setBigUint64(1, amount, true); d[9] = decimals;
  return { programId: prog, accounts: [{ pubkey: src, isSigner: false, isWritable: true }, { pubkey: mint, isSigner: false, isWritable: false }, { pubkey: dst, isSigner: false, isWritable: true }, { pubkey: auth, isSigner: true, isWritable: false }], data: d };
}

function hex(k: Uint8Array) { return Array.from(k).map(b => b.toString(16).padStart(2, '0')).join(''); }
function compactU16(v: number): Uint8Array { if (v < 0x80) return new Uint8Array([v]); if (v < 0x4000) return new Uint8Array([v & 0x7f | 0x80, v >> 7]); return new Uint8Array([v & 0x7f | 0x80, (v >> 7) & 0x7f | 0x80, v >> 14]); }

/**
 * Compiles a version-0 message (SIMD-0385 / mpp-specs-txv1): a 0x80 version
 * prefix, the legacy header, keys, blockhash and instructions, then an empty
 * address-table-lookup section. MPP servers refuse legacy messages, so the
 * page never emits one.
 */
export function compileMessage(ixs: Instruction[], feePayer: Uint8Array, signer: Uint8Array, blockhash: Uint8Array): Uint8Array<ArrayBuffer> {
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
  // Version-0 prefix: the high bit set on the first byte, version number 0.
  parts.push(new Uint8Array([MESSAGE_VERSION_0_PREFIX]));
  parts.push(new Uint8Array([1 + sw.length + sr.length, sr.length, ur.length]));
  parts.push(compactU16(ordered.length)); for (const a of ordered) parts.push(a.pubkey);
  parts.push(blockhash);
  parts.push(compactU16(cIxs.length));
  for (const ix of cIxs) { parts.push(new Uint8Array([ix.pi])); parts.push(compactU16(ix.ai.length)); parts.push(new Uint8Array(ix.ai)); parts.push(compactU16(ix.d.length)); parts.push(ix.d); }
  // Version-0 address table lookups: none.
  parts.push(compactU16(0));
  const len = parts.reduce((s, p) => s + p.length, 0); const out = new Uint8Array(len); let off = 0; for (const p of parts) { out.set(p, off); off += p.length; } return out;
}
