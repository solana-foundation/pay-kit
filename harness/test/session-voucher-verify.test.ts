import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  getBase58Decoder,
  getBase58Encoder,
  getI64Encoder,
  getU64Encoder,
} from "@solana/kit";
import {
  type ChannelState,
  type VoucherRejectReason,
  verifyVoucherForChannel,
} from "@solana/mpp/server";
import { beforeAll, describe, expect, it } from "vitest";

// Executed adversarial coverage for the session-voucher trust logic.
//
// `session-voucher/session-voucher-reject.json` enumerated the voucher reject
// classes but nothing executed them — it was a reason catalog that guarded
// nothing (see vector-accounting.test.ts). This suite drives the REAL pure
// verifier (`verifyVoucherForChannel`, the same one the session server calls)
// with a hand-built voucher per class and asserts the exact reject reason, so
// a regression that relaxes monotonicity / deposit-cap / expiry / settlement-
// window / signature enforcement turns a test red instead of escaping. Every
// reason in the catalog must have a case here (asserted at the end), so the
// catalog and the executed coverage can no longer drift apart.
//
// The verifier is pure and clock-injectable, so this is deterministic and
// RPC-free. Reject reasons 1-7 (steps before the signature check) need no valid
// signature; `invalid-signature` uses a wrong-signer signature; `expired` and
// `expires-within-settlement-window` need a valid signature and a fixed clock.

const CHANNEL_ID = "cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN";
const NOW = 1_000_000n;

// Rebuild the 48-byte Ed25519 preimage: channelId(32, base58) ||
// cumulativeAmount LE u64 || expiresAt LE i64. Self-checked against the frozen
// canonical-bytes vector in beforeAll so a layout drift fails loudly here.
function encodeVoucherPreimage(
  channelId: string,
  cumulative: bigint,
  expiresAt: bigint,
): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(new ArrayBuffer(48));
  out.set(new Uint8Array(getBase58Encoder().encode(channelId)), 0);
  out.set(new Uint8Array(getU64Encoder().encode(cumulative)), 32);
  out.set(new Uint8Array(getI64Encoder().encode(expiresAt)), 40);
  return out;
}

type Signer = { pubkeyBase58: string; keyPair: CryptoKeyPair };

async function makeSigner(): Promise<Signer> {
  const keyPair = (await crypto.subtle.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const raw = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey),
  );
  return { pubkeyBase58: getBase58Decoder().decode(raw), keyPair };
}

async function signVoucher(
  signer: Signer,
  cumulative: bigint,
  expiresAt: bigint,
) {
  const message = encodeVoucherPreimage(CHANNEL_ID, cumulative, expiresAt);
  const sig = new Uint8Array(
    await crypto.subtle.sign("Ed25519", signer.keyPair.privateKey, message),
  );
  return {
    data: {
      channelId: CHANNEL_ID,
      cumulativeAmount: cumulative.toString(),
      expiresAt: Number(expiresAt),
    },
    signature: getBase58Decoder().decode(sig),
  };
}

function baseState(signer: Signer, overrides: Partial<ChannelState> = {}): ChannelState {
  return {
    authorizedSigner: signer.pubkeyBase58,
    channelId: CHANNEL_ID,
    committedDeliveries: [],
    cumulative: 0n,
    deposit: 1000n,
    finalized: false,
    nextDeliverySequence: 0n,
    pendingDeliveries: [],
    ...overrides,
  };
}

const seen = new Set<VoucherRejectReason>();
async function expectReject(
  args: Parameters<typeof verifyVoucherForChannel>[0],
  reason: VoucherRejectReason,
) {
  const result = await verifyVoucherForChannel(args);
  expect(result.status, `expected reject ${reason}, got ${JSON.stringify(result)}`).toBe(
    "rejected",
  );
  if (result.status === "rejected") {
    expect(result.reason).toBe(reason);
    seen.add(result.reason);
  }
}

describe("session voucher verifier — adversarial", () => {
  let signer: Signer;
  beforeAll(async () => {
    signer = await makeSigner();
  });

  it("byte layout matches the frozen canonical voucher vector", () => {
    // cumulative 42, expiresAt 1234 → the pinned session-voucher-preimage-frozen bytes.
    const bytes = Array.from(encodeVoucherPreimage(CHANNEL_ID, 42n, 1234n));
    const frozen = [
      9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9,
      9, 9, 9, 9, 9, 9, 9, 42, 0, 0, 0, 0, 0, 0, 0, 210, 4, 0, 0, 0, 0, 0, 0,
    ];
    expect(bytes).toEqual(frozen);
  });

  it("accepts a valid, in-window, monotonic voucher", async () => {
    const signed = await signVoucher(signer, 100n, 0n); // expiresAt 0 = never expires
    const result = await verifyVoucherForChannel({
      deposit: 1000n,
      nowSeconds: NOW,
      signed,
      state: baseState(signer),
    });
    expect(result.status).toBe("accepted");
  });

  it("reports an exact re-submission as replayed (re-verifies the signature)", async () => {
    const signed = await signVoucher(signer, 42n, 0n);
    const result = await verifyVoucherForChannel({
      deposit: 1000n,
      nowSeconds: NOW,
      signed,
      state: baseState(signer, {
        cumulative: 42n,
        highestVoucherSignature: signed.signature,
      }),
    });
    expect(result.status).toBe("replayed");
  });

  it("rejects a non-canonical cumulative", async () => {
    const signed = await signVoucher(signer, 100n, 0n);
    await expectReject(
      {
        deposit: 1000n,
        nowSeconds: NOW,
        signed: { ...signed, data: { ...signed.data, cumulativeAmount: "not-a-u64" } },
        state: baseState(signer),
      },
      "invalid-cumulative",
    );
  });

  it("rejects vouchers on a finalized channel", async () => {
    const signed = await signVoucher(signer, 100n, 0n);
    await expectReject(
      { deposit: 1000n, nowSeconds: NOW, signed, state: baseState(signer, { finalized: true }) },
      "channel-finalized",
    );
  });

  it("rejects vouchers once a cooperative close is pending", async () => {
    const signed = await signVoucher(signer, 100n, 0n);
    await expectReject(
      {
        deposit: 1000n,
        nowSeconds: NOW,
        signed,
        state: baseState(signer, { closeRequestedAt: NOW }),
      },
      "channel-close-pending",
    );
  });

  it("rejects a non-monotonic cumulative (<= watermark)", async () => {
    const signed = await signVoucher(signer, 50n, 0n);
    await expectReject(
      { deposit: 1000n, nowSeconds: NOW, signed, state: baseState(signer, { cumulative: 50n }) },
      "cumulative-not-monotonic",
    );
  });

  it("rejects a cumulative above the deposit cap", async () => {
    const signed = await signVoucher(signer, 2000n, 0n);
    await expectReject(
      { deposit: 1000n, nowSeconds: NOW, signed, state: baseState(signer) },
      "exceeds-deposit",
    );
  });

  it("rejects a delta below the configured minimum", async () => {
    const signed = await signVoucher(signer, 105n, 0n);
    await expectReject(
      {
        deposit: 1000n,
        minVoucherDelta: 50n,
        nowSeconds: NOW,
        signed,
        state: baseState(signer, { cumulative: 100n }),
      },
      "below-min-delta",
    );
  });

  it("rejects a voucher signed by the wrong key", async () => {
    const other = await makeSigner();
    // Valid-shaped signature (64 bytes) from a different key over the same
    // message: passes steps 1-7, fails the Ed25519 check.
    const forged = await signVoucher(other, 100n, 0n);
    await expectReject(
      { deposit: 1000n, nowSeconds: NOW, signed: forged, state: baseState(signer) },
      "invalid-signature",
    );
  });

  it("rejects an expired voucher", async () => {
    const signed = await signVoucher(signer, 100n, NOW - 1n); // expiry in the past
    await expectReject(
      { deposit: 1000n, nowSeconds: NOW, signed, state: baseState(signer) },
      "expired",
    );
  });

  it("rejects a voucher whose expiry does not outlast the settlement window", async () => {
    const signed = await signVoucher(signer, 100n, NOW + 50n); // in future but < window
    await expectReject(
      {
        deposit: 1000n,
        nowSeconds: NOW,
        settlementWindow: 100n,
        signed,
        state: baseState(signer),
      },
      "expires-within-settlement-window",
    );
  });

  it("covers every reason listed in the session-voucher reject catalog", () => {
    const here = dirname(fileURLToPath(import.meta.url));
    const catalog = JSON.parse(
      readFileSync(
        join(here, "..", "vectors", "session-voucher", "session-voucher-reject.json"),
        "utf8",
      ),
    ) as Array<{ reason: string }>;
    const catalogReasons = new Set(catalog.map((entry) => entry.reason));
    for (const reason of catalogReasons) {
      expect(seen.has(reason as VoucherRejectReason), `catalog reason ${reason} is not executed here`).toBe(
        true,
      );
    }
  });
});
