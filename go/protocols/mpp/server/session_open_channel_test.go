package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	bin "github.com/gagliardetto/binary"
	solana "github.com/gagliardetto/solana-go"
	"github.com/gagliardetto/solana-go/rpc"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
	pcgen "github.com/solana-foundation/pay-kit/go/protocols/programs/paymentchannels"
)

// A real Borsh channel account served independently of signature status. A
// confirmed signature alone must never stand in for proof of session funding.
type sessionChannelRPC struct {
	*testutil.FakeRPC
	address        solana.PublicKey
	account        *rpc.Account
	err            error
	reads          int
	opts           *rpc.GetAccountInfoOpts
	blockhashCalls atomic.Int64
}

func (r *sessionChannelRPC) GetLatestBlockhash(ctx context.Context, commitment rpc.CommitmentType) (*rpc.GetLatestBlockhashResult, error) {
	r.blockhashCalls.Add(1)
	return r.FakeRPC.GetLatestBlockhash(ctx, commitment)
}

func (r *sessionChannelRPC) calls() int64 { return r.blockhashCalls.Load() }

func (r *sessionChannelRPC) GetAccountInfoWithOpts(ctx context.Context, address solana.PublicKey, opts *rpc.GetAccountInfoOpts) (*rpc.GetAccountInfoResult, error) {
	r.reads++
	r.opts = opts
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !address.Equals(r.address) {
		return nil, errors.New("unexpected channel address")
	}
	if r.err != nil {
		return nil, r.err
	}
	return &rpc.GetAccountInfoResult{Value: r.account}, nil
}

func openChannelAccount(t *testing.T, fixture openTxFixture) *pcgen.Channel {
	t.Helper()
	_, bump, err := paymentchannels.FindChannelPDA(fixture.payer.PublicKey(), fixture.payee, fixture.mint, fixture.authorized, openFixtureSalt, openFixtureOpenSlot)
	if err != nil {
		t.Fatal(err)
	}
	return &pcgen.Channel{
		// Explicit on-chain value from the IDL, not the generated zero-based enum.
		Discriminator: 1, Version: 1, Bump: bump,
		Status: uint8(pcgen.ChannelStatus_Open), Salt: openFixtureSalt, Deposit: openFixtureDeposit,
		GracePeriod: openFixtureGrace, DistributionHash: sha256.Sum256([]byte{0, 0, 0, 0}),
		Payer: fixture.payer.PublicKey(), Payee: fixture.payee, Mint: fixture.mint,
		AuthorizedSigner: fixture.authorized, RentPayer: fixture.payer.PublicKey(), OpenSlot: openFixtureOpenSlot,
	}
}

func newSessionChannelRPC(t *testing.T, fixture openTxFixture, mutate func(*pcgen.Channel)) *sessionChannelRPC {
	t.Helper()
	channel := openChannelAccount(t, fixture)
	if mutate != nil {
		mutate(channel)
	}
	var data bytes.Buffer
	if err := channel.MarshalWithEncoder(bin.NewBorshEncoder(&data)); err != nil {
		t.Fatal(err)
	}
	return &sessionChannelRPC{
		FakeRPC: testutil.NewFakeRPC(), address: fixture.channel,
		account: &rpc.Account{Owner: paymentchannels.ProgramPubkey(), Data: rpc.DataBytesOrJSONFromBytes(data.Bytes())},
	}
}

func TestOpenRejectsInflatedClaimedDeposit(t *testing.T) {
	fixture := buildOpenTxFixture(t)
	rpcClient := newSessionChannelRPC(t, fixture, nil)
	claimed := "4000000"
	fixture.payload.Deposit = &claimed
	config := openSessionConfig(fixture)
	config.VerifyOpenTx = NewOpenTxVerifier(config, rpcClient)
	srv := newSessionTestServer(config)
	if state, err := srv.ProcessOpen(context.Background(), &fixture.payload); err == nil {
		t.Fatalf("accepted claimed deposit %d for transaction funding %d", state.Deposit, openFixtureDeposit)
	}
	if state, err := srv.Store().GetChannel(context.Background(), fixture.channel.String()); err != nil || state != nil {
		t.Fatalf("rejected open persisted state: %+v, %v", state, err)
	}
}

func TestOpenRequiresConfirmedMatchingChannel(t *testing.T) {
	cases := []struct {
		name      string
		mutate    func(*pcgen.Channel)
		changeRPC func(*sessionChannelRPC)
	}{
		{name: "missing account", changeRPC: func(r *sessionChannelRPC) { r.account = nil }},
		{name: "missing data", changeRPC: func(r *sessionChannelRPC) { r.account.Data = nil }},
		{name: "truncated data", changeRPC: func(r *sessionChannelRPC) { r.account.Data = rpc.DataBytesOrJSONFromBytes([]byte{1, 1}) }},
		{name: "wrong owner", changeRPC: func(r *sessionChannelRPC) { r.account.Owner = solana.SystemProgramID }},
		{name: "executable account", changeRPC: func(r *sessionChannelRPC) { r.account.Executable = true }},
		{name: "RPC error", changeRPC: func(r *sessionChannelRPC) { r.err = errors.New("RPC unavailable") }},
		{name: "wrong discriminator", mutate: func(c *pcgen.Channel) { c.Discriminator++ }},
		{name: "zero discriminator", mutate: func(c *pcgen.Channel) { c.Discriminator = 0 }},
		{name: "unsupported version", mutate: func(c *pcgen.Channel) { c.Version++ }},
		{name: "closed channel", mutate: func(c *pcgen.Channel) { c.Status++ }},
		{name: "wrong bump", mutate: func(c *pcgen.Channel) { c.Bump-- }},
		{name: "wrong payer", mutate: func(c *pcgen.Channel) { c.Payer = testutil.NewPrivateKey().PublicKey() }},
		{name: "wrong payee", mutate: func(c *pcgen.Channel) { c.Payee = testutil.NewPrivateKey().PublicKey() }},
		{name: "wrong mint", mutate: func(c *pcgen.Channel) { c.Mint = testutil.NewPrivateKey().PublicKey() }},
		{name: "wrong signer", mutate: func(c *pcgen.Channel) { c.AuthorizedSigner = testutil.NewPrivateKey().PublicKey() }},
		{name: "wrong rent payer", mutate: func(c *pcgen.Channel) { c.RentPayer = testutil.NewPrivateKey().PublicKey() }},
		{name: "wrong deposit", mutate: func(c *pcgen.Channel) { c.Deposit-- }},
		{name: "wrong salt", mutate: func(c *pcgen.Channel) { c.Salt++ }},
		{name: "wrong open slot", mutate: func(c *pcgen.Channel) { c.OpenSlot++ }},
		{name: "wrong grace", mutate: func(c *pcgen.Channel) { c.GracePeriod++ }},
		{name: "wrong distribution", mutate: func(c *pcgen.Channel) { c.DistributionHash[0]++ }},
		{name: "already settled", mutate: func(c *pcgen.Channel) { c.Settlement.Settled = 1 }},
		{name: "already paid out", mutate: func(c *pcgen.Channel) { c.Settlement.PayoutWatermark = 1 }},
		{name: "close started", mutate: func(c *pcgen.Channel) { c.ClosureStartedAt = 1 }},
		{name: "payer withdrawn", mutate: func(c *pcgen.Channel) { c.PayerWithdrawnAt = 1 }},
		{name: "processed status"},
	}
	for _, tc := range cases {
		for _, attached := range []bool{true, false} {
			name := tc.name + "/signature-only"
			if attached {
				name = tc.name + "/attached-transaction"
			}
			t.Run(name, func(t *testing.T) {
				fixture := buildOpenTxFixture(t)
				r := newSessionChannelRPC(t, fixture, tc.mutate)
				if tc.name == "processed status" {
					r.Statuses[fixture.signature] = &rpc.SignatureStatusesResult{ConfirmationStatus: rpc.ConfirmationStatusProcessed}
				} else if tc.changeRPC != nil {
					tc.changeRPC(r)
				}
				if !attached {
					fixture.payload.Transaction = nil
				}
				config := openSessionConfig(fixture)
				config.VerifyOpenTx = NewOpenTxVerifier(config, r)
				srv := newSessionTestServer(config)
				if _, err := srv.ProcessOpen(context.Background(), &fixture.payload); err == nil {
					t.Fatal("invalid channel accepted")
				}
				if state, err := srv.Store().GetChannel(context.Background(), fixture.channel.String()); err != nil || state != nil {
					t.Fatalf("invalid channel persisted: %+v, %v", state, err)
				}
			})
		}
	}
}

func TestOpenPersistsConfirmedChannelFacts(t *testing.T) {
	for _, attached := range []bool{true, false} {
		t.Run(map[bool]string{true: "attached-transaction", false: "signature-only"}[attached], func(t *testing.T) {
			fixture := buildOpenTxFixture(t)
			r := newSessionChannelRPC(t, fixture, nil)
			if !attached {
				fixture.payload.Transaction = nil
				fixture.payload.Payer = nil
				fixture.payload.RecentSlot = nil
			}
			config := openSessionConfig(fixture)
			config.VerifyOpenTx = NewOpenTxVerifier(config, r)
			srv := newSessionTestServer(config)
			state, err := srv.ProcessOpen(context.Background(), &fixture.payload)
			if err != nil {
				t.Fatal(err)
			}
			if r.reads != 1 || r.opts.Commitment != rpc.CommitmentConfirmed || r.opts.Encoding != solana.EncodingBase64 {
				t.Fatalf("expected one confirmed base64 account read, got %d %+v", r.reads, r.opts)
			}
			if state.Deposit != openFixtureDeposit || (state.Operator == nil || *state.Operator != fixture.payer.PublicKey().String()) || state.OpenSlot != openFixtureOpenSlot {
				t.Fatalf("wrong persisted funding facts: %+v", state)
			}
		})
	}
}

func TestSessionMiddlewareRequiresFundedChannelAndAcceptsValidVoucher(t *testing.T) {
	for _, name := range []string{"valid channel", "missing account", "inflated deposit", "zero discriminator"} {
		t.Run(name, func(t *testing.T) {
			fixture := buildOpenTxFixture(t)
			signer := newTestVoucherSigner(t)
			fixture.authorized = solana.MustPublicKeyFromBase58(signer.Address())
			channel, _, err := paymentchannels.FindChannelPDA(fixture.payer.PublicKey(), fixture.payee, fixture.mint, fixture.authorized, openFixtureSalt, openFixtureOpenSlot)
			if err != nil {
				t.Fatal(err)
			}
			fixture.channel = channel
			// Signature-only opens may omit these metadata fields. Funding facts
			// must come from the account, not from trusted state seeded by a test.
			fixture.payload = intents.OpenPayloadPush(channel.String(), "1000000", signer.Address(), fixture.signature)
			r := newSessionChannelRPC(t, fixture, nil)
			switch name {
			case "missing account":
				r.account = nil
			case "inflated deposit":
				claim := "4000000"
				fixture.payload.Deposit = &claim
			case "zero discriminator":
				data := r.account.Data.GetBinary()
				data[0] = 0
				r.account.Data = rpc.DataBytesOrJSONFromBytes(data)
			}
			session := newTestSession(t, func(o *SessionOptions) {
				o.Operator = fixture.payer.PublicKey().String()
				o.Recipient = fixture.payee.String()
				o.RPC = r
			})
			calls := 0
			handler := SessionMiddleware(session, nil)(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				calls++
				if _, ok := ReceiptFromContext(req.Context()); !ok {
					t.Error("verified resource request has no receipt")
				}
				w.WriteHeader(http.StatusOK)
			}))
			challengeResponse := httptest.NewRecorder()
			handler.ServeHTTP(challengeResponse, httptest.NewRequest(http.MethodGet, "/resource", nil))
			if challengeResponse.Code != http.StatusPaymentRequired {
				t.Fatalf("initial status = %d", challengeResponse.Code)
			}
			challenge, err := core.ParseWWWAuthenticate(challengeResponse.Header().Get(core.WWWAuthenticateHeader))
			if err != nil {
				t.Fatal(err)
			}
			submit := func(action intents.SessionAction) *httptest.ResponseRecorder {
				t.Helper()
				credential, err := core.NewPaymentCredential(challenge.ToEcho(), action)
				if err != nil {
					t.Fatal(err)
				}
				auth, err := core.FormatAuthorization(credential)
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest(http.MethodGet, "/resource", nil)
				req.Header.Set(core.AuthorizationHeader, auth)
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, req)
				return response
			}
			opened := submit(intents.NewOpenAction(fixture.payload))
			voucherAmount := uint64(1000)
			if name != "valid channel" {
				voucherAmount = 2 * openFixtureDeposit
			}
			vouchered := submit(intents.NewVoucherAction(intents.VoucherPayload{Voucher: signer.SignVoucher(t, channel.String(), voucherAmount, farFuture())}))
			state := mustGetChannel(t, session, channel.String())
			if name != "valid channel" {
				if opened.Code != http.StatusPaymentRequired || vouchered.Code != http.StatusPaymentRequired || calls != 0 || state != nil {
					t.Fatalf("invalid funding reached resource: open=%d voucher=%d calls=%d state=%+v", opened.Code, vouchered.Code, calls, state)
				}
				return
			}
			if opened.Code != http.StatusOK || vouchered.Code != http.StatusOK || calls != 2 {
				t.Fatalf("valid channel rejected: open=%d %s voucher=%d %s calls=%d", opened.Code, opened.Body, vouchered.Code, vouchered.Body, calls)
			}
			receipt, err := core.ParseReceipt(opened.Header().Get(core.PaymentReceiptHeader))
			if err != nil || receipt.Reference != fixture.signature {
				t.Fatalf("open receipt = %+v, %v", receipt, err)
			}
			if state == nil || state.Deposit != openFixtureDeposit || state.OpenSlot != openFixtureOpenSlot || state.Cumulative != voucherAmount || state.Operator == nil || *state.Operator != fixture.payer.PublicKey().String() {
				t.Fatalf("valid channel funding/voucher facts were not persisted: %+v", state)
			}
			if r.reads != 1 || len(r.Sent) != 0 {
				t.Fatalf("signature-only open: account reads=%d broadcasts=%d", r.reads, len(r.Sent))
			}
		})
	}
}

func TestConfirmedOpenAcceptsRecordedChannelWireAccount(t *testing.T) {
	// Captured getAccountInfo bytes from Devnet channel 2R7au9... on 2026-10-20,
	// opened by transaction 53nAyvJeEBzYCeawXpT2S5E9SReamZKiGpBknTz9DWrXQQxAPSuguEyVmqeUkad3P6ji3Ng7szuAq394cSXF8oEf.
	// Keeping the wire bytes independent of the generated encoder catches its
	// zero-based discriminator enum and guards against layout/offset drift.
	const encoded = "AQH/AIgI2LCYGOAYECcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIQDAADfP2GYBKkv20BXGS3EPddI6neK3FK8SYzoBSTAFLgRGYuiNtUZH68me24WyHjHcXJRperVD5kXFoUzQlb6VuafmB6cwuNlAdNDkImyVYuESav1xTruHKXeoYjj7qhtX3SLojbVGR+vJntuFsh4x3FyUaXq1Q+ZFxaFM0JW+lbmn9+v4vz4XgJMl5IJiBxLTQMaE+NTGYIxQnawcCQub4m3mB6cwuNlAdNDkImyVYuESav1xTruHKXeoYjj7qhtX3TEq5MeAAAAAA=="
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	const channelID = "2R7au9cmvZATTuExQswgEzWdUYG2e5wqZK8vCkDaNNpd"
	const payer = "AQ58iYhav6paopnGhGpoZW1pUyp4Mwr1TTy8rdSN9EhC"
	const operator = "BEp3YGFVFEAMJ1PeHBPNFoYfeP65aqosHxhsgmHmDoSs"
	payload := intents.OpenPayloadPush(channelID, "10000", payer, confirmedSignature(0x73))
	r := &sessionChannelRPC{FakeRPC: testutil.NewFakeRPC(), address: solana.MustPublicKeyFromBase58(channelID), account: &rpc.Account{Owner: paymentchannels.ProgramPubkey(), Data: rpc.DataBytesOrJSONFromBytes(data)}}
	verified, err := readConfirmedOpenChannel(context.Background(), VerifyOpenTxExpected{
		AuthorizedSigner: payer, Currency: "G4BUMgcYFzGb4c23Uuph634wNe5DzNGNRvLPAgTqKjsk", Network: "devnet", Operator: operator, Recipient: operator, MaxCap: 100000,
	}, &payload, nil, r)
	want := VerifyOpenTxResult{ChannelID: channelID, Deposit: 10000, GracePeriod: 900, OpenSlot: 512994244, Payer: payer, Salt: 1792459695774501000}
	if err != nil || verified != want {
		t.Fatalf("recorded valid account: got %+v, %v; want %+v", verified, err, want)
	}
}

func TestSessionPublicOpenRejectsMissingConfirmedChannel(t *testing.T) {
	for _, attached := range []bool{true, false} {
		fixture := buildOpenTxFixture(t)
		r := newSessionChannelRPC(t, fixture, nil)
		r.account = nil
		if !attached {
			fixture.payload.Transaction = nil
		}
		session := newTestSession(t, func(o *SessionOptions) {
			o.Operator = fixture.payer.PublicKey().String()
			o.Recipient = fixture.payee.String()
			o.RPC = r
		})
		if _, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload)); err == nil {
			t.Fatalf("public open accepted absent channel (attached=%v)", attached)
		}
		if state := mustGetChannel(t, session, fixture.channel.String()); state != nil {
			t.Fatal("invalid open persisted")
		}
	}
}

func TestSubmitOpenTxRequiresMatchingConfirmedChannel(t *testing.T) {
	for _, valid := range []bool{true, false} {
		fixture := buildOpenTxFixture(t)
		r := newSessionChannelRPC(t, fixture, nil)
		if !valid {
			r.account = nil
		}
		result, err := SubmitOpenTx(context.Background(), fixture.expected, &fixture.payload, nil, r)
		if !valid {
			if err == nil {
				t.Fatal("broadcast success accepted without a channel")
			}
		} else if err != nil || result.Deposit != openFixtureDeposit {
			t.Fatalf("valid funded open: %+v, %v", result, err)
		}
	}
}

func TestOpenContextCancellationDoesNotPersist(t *testing.T) {
	fixture := buildOpenTxFixture(t)
	r := newSessionChannelRPC(t, fixture, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	config := openSessionConfig(fixture)
	config.VerifyOpenTx = NewOpenTxVerifier(config, r)
	if _, err := newSessionTestServer(config).ProcessOpen(ctx, &fixture.payload); err == nil || !strings.Contains(err.Error(), "canceled") {
		t.Fatalf("expected cancellation, got %v", err)
	}
}

func TestOpenPayloadMetadataMustMatchBeforeBroadcast(t *testing.T) {
	for _, field := range []string{"deposit", "payer", "payee", "mint", "salt", "grace", "slot"} {
		t.Run(field, func(t *testing.T) {
			fixture := buildOpenTxFixture(t)
			other := testutil.NewPrivateKey().PublicKey().String()
			switch field {
			case "deposit":
				other = "4000000"
				fixture.payload.Deposit = &other
			case "payer":
				fixture.payload.Payer = &other
			case "payee":
				fixture.payload.Payee = &other
			case "mint":
				fixture.payload.Mint = &other
			case "salt":
				*fixture.payload.Salt++
			case "grace":
				*fixture.payload.GracePeriod++
			case "slot":
				*fixture.payload.RecentSlot++
			}
			r := newSessionChannelRPC(t, fixture, nil)
			if _, err := SubmitOpenTx(context.Background(), fixture.expected, &fixture.payload, nil, r); err == nil {
				t.Fatal("mismatched metadata accepted")
			}
			if len(r.Sent) != 0 {
				t.Fatal("invalid open was broadcast")
			}
		})
	}
}

func TestPullPaymentChannelOpenRequiresConfirmedFunding(t *testing.T) {
	for _, strategy := range []intents.SessionPullVoucherStrategy{intents.SessionPullVoucherStrategyClientVoucher, intents.SessionPullVoucherStrategyOperatedVoucher} {
		for _, valid := range []bool{false, true} {
			fixture := buildOpenTxFixture(t)
			fixture.payload.Mode = intents.SessionModePull
			fixture.payload.Transaction = nil
			r := newSessionChannelRPC(t, fixture, nil)
			if !valid {
				r.account = nil
			}
			session := newTestSession(t, func(o *SessionOptions) {
				o.Operator = fixture.payer.PublicKey().String()
				o.Recipient = fixture.payee.String()
				o.RPC = r
				o.Modes = []intents.SessionMode{intents.SessionModePull}
				o.PullVoucherStrategy = &strategy
			})
			_, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload))
			if (err == nil) != valid {
				t.Fatalf("pull %s valid=%v: %v", strategy, valid, err)
			}
			if (mustGetChannel(t, session, fixture.channel.String()) != nil) != valid {
				t.Fatal("invalid pull funding persisted")
			}
			config := openSessionConfig(fixture)
			config.Modes = []intents.SessionMode{intents.SessionModePull}
			config.PullVoucherStrategy = &strategy
			config.VerifyOpenTx = NewOpenTxVerifier(config, r)
			_, err = newSessionTestServer(config).ProcessOpen(context.Background(), &fixture.payload)
			if (err == nil) != valid {
				t.Fatalf("core pull %s valid=%v: %v", strategy, valid, err)
			}
		}
	}
}

func TestOpenConfirmedStatusAndContextSlot(t *testing.T) {
	for _, status := range []rpc.ConfirmationStatusType{rpc.ConfirmationStatusProcessed, "", rpc.ConfirmationStatusConfirmed, rpc.ConfirmationStatusFinalized} {
		t.Run(string(status), func(t *testing.T) {
			fixture := buildOpenTxFixture(t)
			r := newSessionChannelRPC(t, fixture, nil)
			r.Statuses[fixture.signature] = &rpc.SignatureStatusesResult{Slot: 987, ConfirmationStatus: status}
			_, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, r)
			valid := status == rpc.ConfirmationStatusConfirmed || status == rpc.ConfirmationStatusFinalized
			if (err == nil) != valid {
				t.Fatalf("status %s: %v", status, err)
			}
			if valid && (r.opts.MinContextSlot == nil || *r.opts.MinContextSlot != 987) {
				t.Fatal("account read is not pinned after confirmation slot")
			}
			if !valid && r.reads != 0 {
				t.Fatal("read channel before confirmed status")
			}
		})
	}
}

func TestSessionDistributionHashMatchesProgramGolden(t *testing.T) {
	var a, b solana.PublicKey
	for i := range a {
		a[i] = 1
		b[i] = 2
	}
	want := [32]byte{0x54, 0xc8, 0x97, 0x55, 0x87, 0x75, 0x0e, 0x88, 0x21, 0xe9, 0x3f, 0x5d, 0x4a, 0xf6, 0x07, 0xd2, 0x0d, 0x55, 0xa5, 0x8b, 0xa1, 0xb9, 0xa4, 0xb4, 0x9f, 0x72, 0xa5, 0x42, 0xed, 0x87, 0x4a, 0x3f}
	if got := sessionDistributionHash([]Split{{Recipient: a, BPS: 7500}, {Recipient: b, BPS: 2500}}); got != want {
		t.Fatalf("distribution hash %x, want %x", got, want)
	}
}

func TestPullPaymentChannelCannotDowngradeToAmountAlias(t *testing.T) {
	for _, tokenAccount := range []bool{false, true} {
		fixture := buildOpenTxFixture(t)
		fixture.payload.Mode = intents.SessionModePull
		fixture.payload.Transaction = nil
		fixture.payload.ApprovedAmount = fixture.payload.Deposit
		fixture.payload.Deposit = nil
		if tokenAccount {
			key := testutil.NewPrivateKey().PublicKey().String()
			fixture.payload.TokenAccount = &key
		}
		strategy := intents.SessionPullVoucherStrategyClientVoucher
		r := newSessionChannelRPC(t, fixture, nil)
		r.account = nil
		session := newTestSession(t, func(o *SessionOptions) {
			o.RPC = r
			o.Operator = fixture.payer.PublicKey().String()
			o.Recipient = fixture.payee.String()
			o.Modes = []intents.SessionMode{intents.SessionModePull}
			o.PullVoucherStrategy = &strategy
		})
		if _, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload)); err == nil {
			t.Fatal("amount alias bypassed channel verification")
		}
		if r.reads != 1 {
			t.Fatal("amount alias was not checked against the account")
		}
	}
}

func TestSessionTransactionDerivesOmittedChannelID(t *testing.T) {
	for _, submitter := range []OpenTxSubmitter{OpenTxSubmitterClient, OpenTxSubmitterServer} {
		fixture := buildOpenTxFixture(t)
		r := newSessionChannelRPC(t, fixture, nil)
		fixture.payload.ChannelID = nil
		session := newTestSession(t, func(o *SessionOptions) {
			o.RPC = r
			o.Operator = fixture.payer.PublicKey().String()
			o.Recipient = fixture.payee.String()
			o.OpenTxSubmitter = submitter
		})
		if _, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload)); err != nil {
			t.Fatalf("tx-only %s open: %v", submitter, err)
		}
		if state := mustGetChannel(t, session, fixture.channel.String()); state == nil || state.OpenSlot != openFixtureOpenSlot {
			t.Fatal("derived channel not persisted")
		}
	}
}

func TestSubmitOpenTxRecoversFundedOpenAfterAccountReadFailure(t *testing.T) {
	operator := testutil.NewPrivateKey()
	fixture := buildServerCompletedOpenFixture(t, operator)
	r := newSessionChannelRPC(t, fixture, func(c *pcgen.Channel) { c.RentPayer = operator.PublicKey() })
	r.err = errors.New("account replica unavailable")
	if _, err := SubmitOpenTx(context.Background(), fixture.expected, &fixture.payload, operator, r); err == nil {
		t.Fatal("missing account proof accepted")
	}
	if len(r.Sent) != 1 {
		t.Fatal("first open not broadcast")
	}
	actualSignature := r.Sent[0].Signatures[0].String()
	r.err = nil
	r.SendErr = errors.New("already been processed")
	result, err := SubmitOpenTx(context.Background(), fixture.expected, &fixture.payload, operator, r)
	if err != nil || result.Signature != actualSignature {
		t.Fatalf("confirmed funded retry: %+v, %v", result, err)
	}
	if fixture.payload.Signature == actualSignature {
		t.Fatal("test must retain original placeholder to exercise canonical signed identity")
	}
}

func TestSubmitOpenTxBroadcastErrorRequiresBothProofs(t *testing.T) {
	for _, accountPresent := range []bool{true, false} {
		fixture := buildOpenTxFixture(t)
		r := newSessionChannelRPC(t, fixture, nil)
		broadcastErr := errors.New("broadcast response lost")
		r.SendErr = broadcastErr
		if accountPresent {
			r.Statuses[fixture.signature] = nil
		} else {
			r.account = nil
		}
		if _, err := SubmitOpenTx(context.Background(), fixture.expected, &fixture.payload, nil, r); !errors.Is(err, broadcastErr) {
			t.Fatalf("broadcast error without both proofs: %v", err)
		}
	}
}

func TestSessionConfirmedOpenReplayPreservesWatermark(t *testing.T) {
	fixture := buildOpenTxFixture(t)
	r := newSessionChannelRPC(t, fixture, nil)
	session := newTestSession(t, func(o *SessionOptions) {
		o.RPC = r
		o.Operator = fixture.payer.PublicKey().String()
		o.Recipient = fixture.payee.String()
	})
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload)); err != nil {
		t.Fatal(err)
	}
	_, err := session.Core().Store().UpdateChannel(context.Background(), fixture.channel.String(), func(current *ChannelState) (ChannelState, error) {
		current.Cumulative = 250_000
		current.NextDeliverySequence = 7
		return *current, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload)); err != nil {
		t.Fatal(err)
	}
	state := mustGetChannel(t, session, fixture.channel.String())
	if state.Cumulative != 250_000 || state.NextDeliverySequence != 7 {
		t.Fatalf("replayed open erased state: %+v", state)
	}
}

// Simulate deletion between the replay lookup and the atomic state update.
type deletingOpenReplayStore struct{ ChannelStore }

func (s deletingOpenReplayStore) GetChannel(ctx context.Context, id string) (*ChannelState, error) {
	state, err := s.ChannelStore.GetChannel(ctx, id)
	if err == nil && state != nil {
		err = s.ChannelStore.DeleteChannel(ctx, id)
	}
	return state, err
}

func TestConfirmedOpenReplayAfterTopUp(t *testing.T) {
	for _, path := range []string{"core/signature-only", "core/attached", "public/signature-only", "public/attached", "public/server-submitted"} {
		t.Run(path, func(t *testing.T) {
			fixture := buildOpenTxFixture(t)
			if strings.HasSuffix(path, "signature-only") {
				fixture.payload.Transaction = nil
			}
			r := newSessionChannelRPC(t, fixture, nil)
			var server *SessionServer
			var open func(*intents.OpenPayload) error
			if strings.HasPrefix(path, "core/") {
				config := openSessionConfig(fixture)
				config.VerifyOpenTx = NewOpenTxVerifier(config, r)
				server = newSessionTestServer(config)
				open = func(payload *intents.OpenPayload) error {
					_, err := server.ProcessOpen(context.Background(), payload)
					return err
				}
			} else {
				session := newTestSession(t, func(o *SessionOptions) {
					o.RPC = r
					o.Operator = fixture.payer.PublicKey().String()
					o.Recipient = fixture.payee.String()
					if strings.HasSuffix(path, "server-submitted") {
						o.OpenTxSubmitter = OpenTxSubmitterServer
					}
				})
				server = session.Core()
				open = func(payload *intents.OpenPayload) error {
					_, err := verifySessionAction(t, session, intents.NewOpenAction(*payload))
					return err
				}
			}
			if err := open(&fixture.payload); err != nil {
				t.Fatal(err)
			}
			if _, err := server.ProcessTopUp(context.Background(), &intents.TopUpPayload{
				ChannelID: fixture.channel.String(), NewDeposit: "1500000", Signature: fixture.signature,
			}); err != nil {
				t.Fatal(err)
			}
			r.account = newSessionChannelRPC(t, fixture, func(c *pcgen.Channel) { c.Deposit = 1_500_000 }).account
			before, err := server.Store().UpdateChannel(context.Background(), fixture.channel.String(), func(current *ChannelState) (ChannelState, error) {
				current.Cumulative = 250_000
				current.NextDeliverySequence = 7
				return *current, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			reads, sends := r.reads, len(r.Sent)
			if err := open(&fixture.payload); err != nil {
				t.Fatalf("original open rejected after top-up: %v", err)
			}
			after, err := server.Store().GetChannel(context.Background(), fixture.channel.String())
			if err != nil || !reflect.DeepEqual(&before, after) {
				t.Fatalf("replay changed topped-up state: before=%+v after=%+v err=%v", before, after, err)
			}
			intruder := fixture.payload
			intruder.AuthorizedSigner = testutil.NewPrivateKey().PublicKey().String()
			if err := open(&intruder); err == nil {
				t.Fatal("different signer replay accepted")
			}
			if _, err := server.Store().MarkSealed(context.Background(), fixture.channel.String()); err != nil {
				t.Fatal(err)
			}
			if err := open(&fixture.payload); err == nil {
				t.Fatal("sealed channel replay accepted")
			}
			if r.reads != reads || len(r.Sent) != sends {
				t.Fatal("existing channel replay read chain funding or rebroadcast")
			}
			if _, err := server.Store().UpdateChannel(context.Background(), fixture.channel.String(), func(*ChannelState) (ChannelState, error) {
				return before, nil
			}); err != nil {
				t.Fatal(err)
			}
			server.store = deletingOpenReplayStore{server.store}
			if err := open(&fixture.payload); err == nil || !strings.Contains(err.Error(), "disappeared") {
				t.Fatalf("deleted replay recreated unverified state: %v", err)
			}
			if state, err := server.Store().GetChannel(context.Background(), fixture.channel.String()); err != nil || state != nil {
				t.Fatalf("deleted channel recreated: %+v, %v", state, err)
			}
		})
	}
}

func TestPullChannelKeyAliasStillVerifiesFunding(t *testing.T) {
	for _, strategy := range []intents.SessionPullVoucherStrategy{intents.SessionPullVoucherStrategyClientVoucher, intents.SessionPullVoucherStrategyOperatedVoucher} {
		fixture := buildOpenTxFixture(t)
		fixture.payload.Mode = intents.SessionModePull
		fixture.payload.Transaction = nil
		fixture.payload.TokenAccount = fixture.payload.ChannelID
		fixture.payload.ChannelID = nil
		if strategy == intents.SessionPullVoucherStrategyClientVoucher {
			fixture.payload.ApprovedAmount = fixture.payload.Deposit
			fixture.payload.Deposit = nil
		}
		r := newSessionChannelRPC(t, fixture, nil)
		r.account = nil
		session := newTestSession(t, func(o *SessionOptions) {
			o.RPC = r
			o.Operator = fixture.payer.PublicKey().String()
			o.Recipient = fixture.payee.String()
			o.Modes = []intents.SessionMode{intents.SessionModePull}
			o.PullVoucherStrategy = &strategy
		})
		if _, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload)); err == nil {
			t.Fatal("channel key alias bypassed funding check")
		}
		if r.reads != 1 {
			t.Fatal("aliased channel account not read")
		}
	}
}

func TestTokenDelegationRetainsHostVerificationPath(t *testing.T) {
	for _, strategy := range []intents.SessionPullVoucherStrategy{intents.SessionPullVoucherStrategyClientVoucher, intents.SessionPullVoucherStrategyOperatedVoucher} {
		for _, alias := range []bool{false, true} {
			fixture := buildOpenTxFixture(t)
			r := newSessionChannelRPC(t, fixture, nil)
			r.account = nil
			session := newTestSession(t, func(o *SessionOptions) {
				o.RPC = r
				o.Modes = []intents.SessionMode{intents.SessionModePull}
				o.PullVoucherStrategy = &strategy
			})
			payload := intents.OpenPayloadPull(fixture.channel.String(), "1000", fixture.payer.PublicKey().String(), fixture.authorized.String(), fixture.signature)
			if alias {
				delegation := testutil.NewPrivateKey().PublicKey().String()
				payload.ChannelID = &delegation
			}
			if _, err := verifySessionAction(t, session, intents.NewOpenAction(payload)); err != nil {
				t.Fatalf("host-managed delegation path changed: %v", err)
			}
			if r.reads != 0 {
				t.Fatal("token delegation read as payment-channel account")
			}
		}
	}
}

func TestConfirmedOpenSupportsConfiguredSplitsAndProgram(t *testing.T) {
	fixture := buildOpenTxFixture(t)
	program := testutil.NewPrivateKey().PublicKey()
	fixture.expected.ProgramID = &program
	fixture.expected.Splits = []Split{{Recipient: testutil.NewPrivateKey().PublicKey(), BPS: 250}}
	channel, bump, err := paymentchannels.FindChannelPDAForProgram(fixture.payer.PublicKey(), fixture.payee, fixture.mint, fixture.authorized, openFixtureSalt, openFixtureOpenSlot, program)
	if err != nil {
		t.Fatal(err)
	}
	fixture.channel = channel
	ix, err := paymentchannels.BuildOpenInstruction(paymentchannels.OpenChannelParams{
		ProgramID: program, Payer: fixture.payer.PublicKey(), RentPayer: fixture.payer.PublicKey(),
		Payee: fixture.payee, Mint: fixture.mint, AuthorizedSigner: fixture.authorized,
		Salt: openFixtureSalt, Deposit: openFixtureDeposit, GracePeriod: openFixtureGrace, OpenSlot: openFixtureOpenSlot,
		TokenProgram: solana.TokenProgramID,
		Recipients:   []paymentchannels.Distribution{{Recipient: fixture.expected.Splits[0].Recipient, Bps: 250}},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, fixture.payload = signAndAttachOpenTx(t, &fixture, ix)
	r := newSessionChannelRPC(t, fixture, func(c *pcgen.Channel) {
		c.Bump = bump
		c.DistributionHash = sessionDistributionHash(fixture.expected.Splits)
	})
	r.account.Owner = program
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, r); err != nil {
		t.Fatalf("custom program and split: %v", err)
	}
	fixture.expected.Splits[0].BPS++
	if _, err := VerifyOpenTx(context.Background(), fixture.expected, &fixture.payload, r); err == nil {
		t.Fatal("changed configured split accepted")
	}
}
