// Package paymentchannels_parity guards the Codama-generated payment-channels
// Go client against the Rust spine byte-for-byte.
//
// It lives in a separate directory from the generated package because the Go
// codegen (`pnpm run payment-channels:go`) renders with
// deleteFolderBeforeRendering, which wipes everything under
// protocols/programs/paymentchannels/. Keeping the guard out-of-tree means
// regeneration never clobbers it.
//
// The frozen hex vectors are produced by `borsh::to_vec` over the identical
// OpenArgs, DistributionEntry, and VoucherArgs struct layouts, plus the u8=1
// open discriminator the on-chain program declares
// (OPEN_DISCRIMINATOR: u8 = 1). If the upstream IDL changes the layout, both
// the regenerated client and these vectors must move together, and this test
// makes that break loud.
package paymentchannels_parity

import (
	"bytes"
	"encoding/hex"
	"testing"

	bin "github.com/gagliardetto/binary"
	"github.com/gagliardetto/solana-go"

	pc "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

// borshEncode serializes v with the gagliardetto Borsh encoder, matching the
// little-endian, length-prefixed-Vec layout that borsh::to_vec emits in Rust.
func borshEncode(t *testing.T, v any) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := bin.NewBorshEncoder(&buf).Encode(v); err != nil {
		t.Fatalf("borsh encode: %v", err)
	}
	return buf.Bytes()
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("decode frozen vector %q: %v", s, err)
	}
	return b
}

// TestOpenDiscriminator pins the single-byte Anchor-numeric discriminator. This
// program does NOT use the 8-byte sha256("global:open")[:8] convention; the
// on-chain program declares OPEN_DISCRIMINATOR: u8 = 1 and the IDL encodes it
// as a fieldDiscriminatorNode u8 at offset 0. Guard against a silent switch
// to the wide form.
func TestOpenDiscriminator(t *testing.T) {
	if pc.OpenDiscriminator != 1 {
		t.Fatalf("OpenDiscriminator = %d, want 1 (rust OPEN_DISCRIMINATOR: u8 = 1)", pc.OpenDiscriminator)
	}
}

// TestOpenArgsBorshParity asserts the OpenArgs Borsh layout
// {salt u64, deposit u64, grace_period u32, recipients Vec<{recipient pubkey, bps u16}>}
// matches the Rust spine for a frozen input.
func TestOpenArgsBorshParity(t *testing.T) {
	// salt=1, deposit=1_000_000, grace_period=900,
	// recipients=[{recipient=<all-zero pubkey>, bps=10000}]
	args := pc.OpenArgs{
		Salt:        1,
		Deposit:     1_000_000,
		GracePeriod: 900,
		Recipients: []pc.DistributionEntry{
			{Recipient: solana.PublicKey{}, Bps: 10000},
		},
	}

	// Frozen from `borsh::to_vec(&OpenArgs{...})` against the Rust spine layout.
	const wantOpenArgs = "010000000000000040420f0000000000840300000100000000000000000000000000000000000000000000000000000000000000000000001027"
	got := borshEncode(t, args)
	if want := mustHex(t, wantOpenArgs); !bytes.Equal(got, want) {
		t.Fatalf("OpenArgs borsh mismatch\n got: %s\nwant: %s", hex.EncodeToString(got), wantOpenArgs)
	}
}

// TestOpenInstructionDataParity asserts the full Open instruction data wire
// bytes (1-byte discriminator || Borsh OpenArgs) match the Rust spine, going
// through the generated Open.MarshalWithEncoder path the client actually uses.
func TestOpenInstructionDataParity(t *testing.T) {
	open := pc.NewOpenInstructionBuilder().SetOpenArgs(pc.OpenArgs{
		Salt:        1,
		Deposit:     1_000_000,
		GracePeriod: 900,
		Recipients: []pc.DistributionEntry{
			{Recipient: solana.PublicKey{}, Bps: 10000},
		},
	})

	var buf bytes.Buffer
	if err := open.MarshalWithEncoder(bin.NewBorshEncoder(&buf)); err != nil {
		t.Fatalf("Open.MarshalWithEncoder: %v", err)
	}

	// Frozen from `[1u8] ++ borsh::to_vec(&OpenArgs{...})` against the Rust spine.
	const wantOpenIx = "01010000000000000040420f0000000000840300000100000000000000000000000000000000000000000000000000000000000000000000001027"
	if want := mustHex(t, wantOpenIx); !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("Open instruction data mismatch\n got: %s\nwant: %s", hex.EncodeToString(buf.Bytes()), wantOpenIx)
	}
	if buf.Bytes()[0] != 0x01 {
		t.Fatalf("first byte = %#02x, want 0x01 discriminator", buf.Bytes()[0])
	}
}

// TestVoucherPreimageParity asserts the 48-byte voucher preimage exposed by the
// generated VoucherArgs type matches the Rust spine layout
// channel_id(32) || cumulative_amount_le(8) || expires_at_le(8). This is the
// load-bearing off-chain Ed25519 signing preimage for the session phase.
func TestVoucherPreimageParity(t *testing.T) {
	voucher := pc.VoucherArgs{
		ChannelId:        solana.PublicKey{}, // all-zero channel id
		CumulativeAmount: 1234567,
		ExpiresAt:        4102444800, // DEFAULT_SESSION_EXPIRES_AT (2100-01-01)
	}

	// Frozen from `borsh::to_vec(&VoucherArgs{...})` against the Rust spine.
	const wantVoucher = "000000000000000000000000000000000000000000000000000000000000000087d6120000000000005786f400000000"
	got := borshEncode(t, voucher)
	if len(got) != 48 {
		t.Fatalf("voucher preimage = %d bytes, want 48", len(got))
	}
	if want := mustHex(t, wantVoucher); !bytes.Equal(got, want) {
		t.Fatalf("voucher preimage mismatch\n got: %s\nwant: %s", hex.EncodeToString(got), wantVoucher)
	}

	// Pin the field offsets: cumulative_amount little-endian at byte 32,
	// expires_at little-endian at byte 40.
	if v := bin.LE.Uint64(got[32:40]); v != 1234567 {
		t.Fatalf("cumulative_amount@32 = %d, want 1234567", v)
	}
	if v := int64(bin.LE.Uint64(got[40:48])); v != 4102444800 {
		t.Fatalf("expires_at@40 = %d, want 4102444800", v)
	}
}
