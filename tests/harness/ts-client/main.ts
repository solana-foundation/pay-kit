/**
 * Canonical interop test client (TypeScript).
 *
 * Tests the full payment cycle against any MPP server:
 *   1. GET /health -> 200
 *   2. GET /fortune -> 402 + WWW-Authenticate
 *   3. Fund test keypair via surfpool
 *   4. Build credential with @solana/kit
 *   5. GET /fortune with Authorization -> 200 + fortune
 *
 * Usage: SERVER_URL=http://localhost:3001 npx tsx main.ts
 */

import {
  address,
  appendTransactionMessageInstruction,
  compileTransaction,
  createSolanaRpc,
  createTransactionMessage,
  generateKeyPairSigner,
  getBase64EncodedWireTransaction,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  type Address,
  type IInstruction,
  AccountRole,
} from '@solana/kit';
import { getTransferSolInstruction } from '@solana-program/system';
import {
  findAssociatedTokenPda,
  getTransferCheckedInstruction,
} from '@solana-program/token';

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

const SERVER_URL = process.env.SERVER_URL ?? 'http://localhost:3001';
const FORTUNE_PATH = process.env.FORTUNE_PATH ?? '/fortune';
const RPC_URL = process.env.RPC_URL ?? 'http://localhost:8899';

console.log(`Interop test: TypeScript client -> ${SERVER_URL}`);
console.log(`RPC: ${RPC_URL}`);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function base64UrlEncode(data: Uint8Array | string): string {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const b64 = Buffer.from(bytes).toString('base64');
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/');
  return new Uint8Array(Buffer.from(padded, 'base64'));
}

function assert(condition: boolean, message: string): asserts condition {
  if (!condition) throw new Error(`Assertion failed: ${message}`);
}

async function rpcCall(method: string, params: unknown): Promise<void> {
  const resp = await fetch(RPC_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const data = (await resp.json()) as { error?: { message: string } };
  if (data.error) throw new Error(`RPC ${method} error: ${data.error.message}`);
}

// ---------------------------------------------------------------------------
// Challenge parsing
// ---------------------------------------------------------------------------

interface Challenge {
  id: string;
  realm: string;
  method: string;
  intent: string;
  request: string; // base64url-encoded JSON
  expires?: string;
  description?: string;
}

function parseWwwAuthenticate(header: string): Challenge {
  assert(
    header.toLowerCase().startsWith('payment '),
    'should use Payment scheme',
  );
  const paramsStr = header.slice(8).trim();
  const params = new Map<string, string>();

  const chars = [...paramsStr];
  let i = 0;
  while (i < chars.length) {
    // skip whitespace and commas
    while (i < chars.length && (chars[i] === ' ' || chars[i] === ',' || chars[i] === '\t')) i++;
    if (i >= chars.length) break;

    // read key
    const keyStart = i;
    while (i < chars.length && chars[i] !== '=') i++;
    if (i >= chars.length) break;
    const key = chars.slice(keyStart, i).join('');
    i++; // skip '='

    // read value
    let value: string;
    if (chars[i] === '"') {
      i++; // skip opening quote
      const parts: string[] = [];
      while (i < chars.length && chars[i] !== '"') {
        if (chars[i] === '\\' && i + 1 < chars.length) {
          i++;
          parts.push(chars[i]);
        } else {
          parts.push(chars[i]);
        }
        i++;
      }
      if (i < chars.length) i++; // skip closing quote
      value = parts.join('');
    } else {
      const vs = i;
      while (i < chars.length && chars[i] !== ',' && chars[i] !== ' ') i++;
      value = chars.slice(vs, i).join('');
    }

    params.set(key, value);
  }

  const get = (k: string): string => {
    const v = params.get(k);
    if (v === undefined) throw new Error(`Missing '${k}' in challenge`);
    return v;
  };

  return {
    id: get('id'),
    realm: get('realm'),
    method: get('method'),
    intent: get('intent'),
    request: get('request'),
    expires: params.get('expires'),
    description: params.get('description'),
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  // -- Test 1: Health --
  process.stdout.write('  health ... ');
  {
    const resp = await fetch(`${SERVER_URL}/health`);
    assert(resp.status === 200, `health should return 200, got ${resp.status}`);
    console.log('OK');
  }

  // -- Test 2: Challenge --
  process.stdout.write('  challenge ... ');
  let challenge: Challenge;
  {
    const resp = await fetch(`${SERVER_URL}${FORTUNE_PATH}`);
    assert(resp.status === 402, `fortune without auth should return 402, got ${resp.status}`);
    const wwwAuth = resp.headers.get('www-authenticate');
    assert(wwwAuth !== null, 'missing WWW-Authenticate header');
    assert(wwwAuth!.startsWith('Payment '), 'should use Payment scheme');
    challenge = parseWwwAuthenticate(wwwAuth!);
    assert(challenge.method === 'solana', `method should be solana, got ${challenge.method}`);
    assert(challenge.intent === 'charge', `intent should be charge, got ${challenge.intent}`);
    console.log(`OK (id=${challenge.id.slice(0, 12)}...)`);
  }

  // -- Test 3: Fund test keypair via surfpool --
  process.stdout.write('  fund ... ');
  const signer = await generateKeyPairSigner();
  const pubkeyStr = signer.address;

  // Decode the challenge request
  const requestBytes = base64UrlDecode(challenge.request);
  const request = JSON.parse(new TextDecoder().decode(requestBytes)) as {
    amount: string;
    currency: string;
    recipient: string;
    methodDetails?: {
      network?: string;
      decimals?: number;
      tokenProgram?: string;
      feePayer?: boolean;
      feePayerKey?: string;
      recentBlockhash?: string;
      splits?: Array<{ recipient: string; amount: string }>;
    };
  };

  const currency = request.currency ?? 'sol';
  const isNativeSOL = currency.toLowerCase() === 'sol';
  const md = request.methodDetails ?? {};
  const tokenProgram = md.tokenProgram ?? 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
  const recipient = request.recipient;

  // Fund SOL account
  await rpcCall('surfnet_setAccount', [
    pubkeyStr,
    {
      lamports: 2_000_000_000,
      data: '',
      executable: false,
      owner: '11111111111111111111111111111111',
      rentEpoch: 0,
    },
  ]);

  if (!isNativeSOL) {
    const amount = Number(request.amount);
    // Fund sender token account
    await rpcCall('surfnet_setTokenAccount', [
      pubkeyStr,
      currency,
      { amount, state: 'initialized' },
      tokenProgram,
    ]);
    // Ensure recipient has token account
    await rpcCall('surfnet_setTokenAccount', [
      recipient,
      currency,
      { amount: 0, state: 'initialized' },
      tokenProgram,
    ]);
  }
  console.log(`OK (pubkey=${pubkeyStr.slice(0, 8)}...)`);

  // -- Test 4: Build credential --
  process.stdout.write('  credential ... ');

  const totalAmount = BigInt(request.amount);
  const splits = md.splits ?? [];
  let splitsTotal = 0n;
  for (const s of splits) splitsTotal += BigInt(s.amount);
  const primaryAmount = totalAmount - splitsTotal;

  const hasSeparateFeePayer = md.feePayer === true && !!md.feePayerKey;

  // Get blockhash
  let blockhash: string;
  let lastValidBlockHeight: bigint;
  if (md.recentBlockhash) {
    blockhash = md.recentBlockhash;
    // Use a generous default when the server provides the blockhash
    lastValidBlockHeight = BigInt(Number.MAX_SAFE_INTEGER);
  } else {
    const rpc = createSolanaRpc(RPC_URL);
    const { value } = await rpc.getLatestBlockhash({ commitment: 'confirmed' }).send();
    blockhash = value.blockhash;
    lastValidBlockHeight = value.lastValidBlockHeight;
  }

  // Build instructions — matching the SDK flow:
  // 1. Compute budget (always)
  // 2. Primary transfer
  // 3. Split ATA creation + transfer when the challenge allows it
  const instructions: IInstruction[] = [];

  // ── Compute budget ──
  const COMPUTE_BUDGET = address('ComputeBudget111111111111111111111111111111');
  // SetComputeUnitPrice: discriminator 3, value 1 micro-lamport
  const priceData = new Uint8Array(9);
  priceData[0] = 3;
  priceData[1] = 1;
  instructions.push({ programAddress: COMPUTE_BUDGET, data: priceData, accounts: [] });
  // SetComputeUnitLimit: discriminator 2, value 200_000
  const limitData = new Uint8Array(5);
  limitData[0] = 2;
  new DataView(limitData.buffer).setUint32(1, 200_000, true);
  instructions.push({ programAddress: COMPUTE_BUDGET, data: limitData, accounts: [] });

  // ── ATA helper ──
  const ATA_PROGRAM = address('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
  const SYSTEM_PROGRAM = address('11111111111111111111111111111111');
  const ataPayer: Address = hasSeparateFeePayer ? address(md.feePayerKey!) : signer.address;

  function createAtaIdempotent(payer: Address, ata: Address, owner: Address, mint: Address, tokenProg: Address): IInstruction {
    return {
      programAddress: ATA_PROGRAM,
      data: new Uint8Array([1]),
      accounts: [
        { address: payer, role: AccountRole.WRITABLE_SIGNER },
        { address: ata, role: AccountRole.WRITABLE },
        { address: owner, role: AccountRole.READONLY },
        { address: mint, role: AccountRole.READONLY },
        { address: SYSTEM_PROGRAM, role: AccountRole.READONLY },
        { address: tokenProg, role: AccountRole.READONLY },
      ],
    };
  }

  if (isNativeSOL) {
    instructions.push(
      getTransferSolInstruction({
        source: signer,
        destination: address(recipient),
        amount: primaryAmount,
      }),
    );
    for (const s of splits) {
      instructions.push(
        getTransferSolInstruction({
          source: signer,
          destination: address(s.recipient),
          amount: BigInt(s.amount),
        }),
      );
    }
  } else {
    const mintAddress = address(currency);
    const decimals = md.decimals ?? 6;
    const tokenProgramAddress = address(tokenProgram);

    const [sourceAta] = await findAssociatedTokenPda({
      owner: signer.address,
      mint: mintAddress,
      tokenProgram: tokenProgramAddress,
    });

    // Primary recipient ATA creation is intentionally out of scope.
    const [destAta] = await findAssociatedTokenPda({
      owner: address(recipient),
      mint: mintAddress,
      tokenProgram: tokenProgramAddress,
    });
    instructions.push(
      getTransferCheckedInstruction({
        source: sourceAta,
        mint: mintAddress,
        destination: destAta,
        authority: signer,
        amount: primaryAmount,
        decimals,
      }),
    );

    // Splits: ATA creation + transfer each
    for (const s of splits) {
      const [splitAta] = await findAssociatedTokenPda({
        owner: address(s.recipient),
        mint: mintAddress,
        tokenProgram: tokenProgramAddress,
      });
      instructions.push(createAtaIdempotent(ataPayer, splitAta, address(s.recipient), mintAddress, tokenProgramAddress));
      instructions.push(
        getTransferCheckedInstruction({
          source: sourceAta,
          mint: mintAddress,
          destination: splitAta,
          authority: signer,
          amount: BigInt(s.amount),
          decimals,
        }),
      );
    }
  }

  // Build transaction message.
  // Always pass fee payer as an address string. The signer is tracked via instructions.
  const feePayerAddress: Address = hasSeparateFeePayer
    ? address(md.feePayerKey!)
    : signer.address;

  let txMessage = pipe(
    createTransactionMessage({ version: 'legacy' }),
    (m) => setTransactionMessageFeePayer(feePayerAddress, m),
    (m) =>
      setTransactionMessageLifetimeUsingBlockhash(
        {
          blockhash: blockhash as Parameters<typeof setTransactionMessageLifetimeUsingBlockhash>[0]['blockhash'],
          lastValidBlockHeight,
        },
        m,
      ),
  );

  for (const ix of instructions) {
    txMessage = appendTransactionMessageInstruction(ix, txMessage);
  }

  // Compile and sign (the client signs its part)
  const compiledTx = compileTransaction(
    txMessage as Parameters<typeof compileTransaction>[0],
  );

  // Sign the compiled message bytes with our keypair
  const sigBytes = new Uint8Array(
    await crypto.subtle.sign('Ed25519', signer.keyPair.privateKey, compiledTx.messageBytes),
  );

  // Create a signed transaction with our signature applied
  const signedTx = {
    ...compiledTx,
    signatures: {
      ...compiledTx.signatures,
      [signer.address]: sigBytes,
    },
  };

  // Encode the wire transaction as base64 (standard, not base64url)
  const txBase64 = getBase64EncodedWireTransaction(
    signedTx as Parameters<typeof getBase64EncodedWireTransaction>[0],
  );

  // Build credential JSON (ChallengeEcho: id, realm, method, intent, request, expires?, digest?, opaque?)
  // Note: description is NOT part of the ChallengeEcho, only the challenge itself.
  const credential = {
    challenge: {
      id: challenge.id,
      intent: challenge.intent,
      method: challenge.method,
      realm: challenge.realm,
      request: challenge.request,
      ...(challenge.expires ? { expires: challenge.expires } : {}),
    },
    payload: {
      transaction: txBase64,
      type: 'transaction',
    },
  };

  const credentialB64 = base64UrlEncode(JSON.stringify(credential));
  const authHeader = `Payment ${credentialB64}`;
  assert(authHeader.startsWith('Payment '), 'credential should start with Payment');
  console.log('OK');

  // -- Test 5: Submit and get fortune --
  process.stdout.write('  payment ... ');
  {
    const resp = await fetch(`${SERVER_URL}${FORTUNE_PATH}`, {
      headers: { Authorization: authHeader },
    });
    const status = resp.status;
    const body = await resp.text();
    assert(status === 200, `payment should return 200, got ${status}: ${body}`);
    const data = JSON.parse(body) as { fortune?: string };
    assert(data.fortune !== undefined, 'response should contain fortune');
    console.log(`OK -> ${data.fortune}`);
  }

  console.log('\n  All interop tests passed');
}

main().catch((err) => {
  console.error(`\n  FAILED: ${err.message ?? err}`);
  process.exit(1);
});
