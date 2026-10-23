package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	solana "github.com/gagliardetto/solana-go"
	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore/paymentchannels"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

func TestOpenReplayRequiresSameFundingPolicy(t *testing.T) {
	changes := map[string]func(*SessionConfig){
		"operator":  func(c *SessionConfig) { c.Operator = testutil.NewPrivateKey().PublicKey().String() },
		"recipient": func(c *SessionConfig) { c.Recipient = testutil.NewPrivateKey().PublicKey().String() },
		"mint":      func(c *SessionConfig) { c.Currency = testutil.NewPrivateKey().PublicKey().String() },
		"network":   func(c *SessionConfig) { c.Network = "devnet" },
		"program":   func(c *SessionConfig) { p := testutil.NewPrivateKey().PublicKey(); c.ProgramID = &p },
		"splits": func(c *SessionConfig) {
			c.Splits = []Split{{Recipient: testutil.NewPrivateKey().PublicKey(), BPS: 100}}
		},
		"cap":                 func(c *SessionConfig) { c.MaxCap++ },
		"verification policy": func(c *SessionConfig) { c.VerifyOpenTx = nil },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			fixture := buildOpenTxFixture(t)
			fixture.payload.Transaction = nil
			r := newSessionChannelRPC(t, fixture, nil)
			config := openSessionConfig(fixture)
			config.VerifyOpenTx = NewOpenTxVerifier(config, r)
			store := NewMemoryChannelStore()
			first := NewSessionServer(config, store)
			before, err := first.ProcessOpen(context.Background(), &fixture.payload)
			if err != nil {
				t.Fatal(err)
			}
			change(&config)
			second := NewSessionServer(config, store)
			if _, err := second.ProcessOpen(context.Background(), &fixture.payload); err == nil || !strings.Contains(err.Error(), "funding context") {
				t.Fatalf("different funding policy accepted: %v", err)
			}
			after, err := store.GetChannel(context.Background(), fixture.channel.String())
			if err != nil || !reflect.DeepEqual(&before, after) {
				t.Fatalf("rejected replay changed state: %+v, %v", after, err)
			}
		})
	}
}

type fundingContextChangingStore struct {
	ChannelStore
	hideLookup bool
	context    string
}

func (s fundingContextChangingStore) GetChannel(ctx context.Context, id string) (*ChannelState, error) {
	state, err := s.ChannelStore.GetChannel(ctx, id)
	if err == nil && state != nil {
		_, err = s.ChannelStore.UpdateChannel(ctx, id, func(current *ChannelState) (ChannelState, error) {
			current.OpenFundingContext = s.context
			return *current, nil
		})
	}
	if s.hideLookup {
		state = nil
	}
	return state, err
}

func TestOpenReplayContextSurvivesStorageAndFailsClosed(t *testing.T) {
	for _, public := range []bool{false, true} {
		for _, hideLookup := range []bool{false, true} {
			for _, binding := range []string{"", "v2:unsupported", "v1:other-policy"} {
				fixture := buildOpenTxFixture(t)
				fixture.payload.Transaction = nil
				r := newSessionChannelRPC(t, fixture, nil)
				var server *SessionServer
				var open func() error
				if public {
					session := newTestSession(t, func(o *SessionOptions) {
						o.RPC = r
						o.Operator = fixture.payer.PublicKey().String()
						o.Recipient = fixture.payee.String()
					})
					server = session.Core()
					open = func() error {
						_, err := verifySessionAction(t, session, intents.NewOpenAction(fixture.payload))
						return err
					}
				} else {
					config := openSessionConfig(fixture)
					config.VerifyOpenTx = NewOpenTxVerifier(config, r)
					server = newSessionTestServer(config)
					open = func() error { _, err := server.ProcessOpen(context.Background(), &fixture.payload); return err }
				}
				if err := open(); err != nil {
					t.Fatal(err)
				}
				store := server.Store()
				before, err := store.GetChannel(context.Background(), fixture.channel.String())
				if err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(before)
				if err != nil {
					t.Fatal(err)
				}
				var restored ChannelState
				if err := json.Unmarshal(data, &restored); err != nil {
					t.Fatal(err)
				}
				if restored.OpenFundingContext == "" {
					t.Fatal("funding binding lost during storage")
				}
				if _, err := store.UpdateChannel(context.Background(), fixture.channel.String(), func(*ChannelState) (ChannelState, error) { return restored, nil }); err != nil {
					t.Fatal(err)
				}
				if err := open(); err != nil {
					t.Fatalf("same-context stored replay: %v", err)
				}
				server.store = fundingContextChangingStore{ChannelStore: store, hideLookup: hideLookup, context: binding}
				if err := open(); err == nil || !strings.Contains(err.Error(), "funding context") {
					t.Fatalf("public=%v hideLookup=%v binding=%q accepted: %v", public, hideLookup, binding, err)
				}
				after, err := store.GetChannel(context.Background(), fixture.channel.String())
				if err != nil {
					t.Fatal(err)
				}
				before.OpenFundingContext = binding
				if !reflect.DeepEqual(before, after) {
					t.Fatal("rejected replay reset or adopted stored state")
				}
			}
		}
	}
}

func TestOpenReplayDoesNotUpgradeTrustedCredit(t *testing.T) {
	for _, structuralOnly := range []bool{false, true} {
		fixture := buildOpenTxFixture(t)
		store := NewMemoryChannelStore()
		configure := func(o *SessionOptions) {
			o.Store = store
			o.Operator = fixture.payer.PublicKey().String()
			o.Recipient = fixture.payee.String()
		}
		if structuralOnly {
			config := openSessionConfig(fixture)
			config.VerifyOpenTx = NewOpenTxVerifier(config, nil)
			if _, err := NewSessionServer(config, store).ProcessOpen(context.Background(), &fixture.payload); err != nil {
				t.Fatal(err)
			}
		} else {
			fixture.payload.Transaction = nil
			trusted := newTestSession(t, configure)
			if _, err := verifySessionAction(t, trusted, intents.NewOpenAction(fixture.payload)); err != nil {
				t.Fatal(err)
			}
		}
		fixture.payload.Transaction = nil
		r := newSessionChannelRPC(t, fixture, nil)
		r.account = nil
		verified := newTestSession(t, func(o *SessionOptions) { configure(o); o.RPC = r })
		if _, err := verifySessionAction(t, verified, intents.NewOpenAction(fixture.payload)); err == nil {
			t.Fatalf("structuralOnly=%v: unverified stored credit reused as RPC-confirmed funding", structuralOnly)
		}
	}
}

func TestOpenFundingContextCanonicalIdentity(t *testing.T) {
	config := sessionTestConfig()
	config.Network = "mainnet-beta"
	payload := sessionOpenPayload("channel", 1000, "signer")
	want := NewSessionServer(config, nil).openFundingContext(payload, openAdmissionRPC)
	config.Network = "mainnet"
	config.Currency = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
	program := paymentchannels.ProgramPubkey()
	config.ProgramID = &program
	config.SettlementAuthority = intents.SessionSettlementAuthorityClientVoucher
	deposit := "2000"
	payload.Deposit = &deposit
	if got := NewSessionServer(config, nil).openFundingContext(payload, openAdmissionRPC); got != want {
		t.Fatal("equivalent funding identity or changed amount broke replay binding")
	}
}

func TestPullReplayCannotChangeFundingOrVoucherPolicy(t *testing.T) {
	for _, change := range []string{"mode", "strategy", "authority", "funding kind"} {
		t.Run(change, func(t *testing.T) {
			fixture := buildOpenTxFixture(t)
			fixture.authorized = fixture.payer.PublicKey()
			channel, _, err := paymentchannels.FindChannelPDA(fixture.payer.PublicKey(), fixture.payee, fixture.mint, fixture.authorized, openFixtureSalt, openFixtureOpenSlot)
			if err != nil {
				t.Fatal(err)
			}
			fixture.channel = channel
			fixture.payload = intents.OpenPayloadPush(channel.String(), "1000000", fixture.authorized.String(), fixture.signature)
			fixture.payload.Mode = intents.SessionModePull
			r := newSessionChannelRPC(t, fixture, nil)
			config := openSessionConfig(fixture)
			config.Modes = []intents.SessionMode{intents.SessionModePush, intents.SessionModePull}
			strategy := intents.SessionPullVoucherStrategyClientVoucher
			config.PullVoucherStrategy = &strategy
			config.VerifyOpenTx = NewOpenTxVerifier(config, r)
			store := NewMemoryChannelStore()
			before, err := NewSessionServer(config, store).ProcessOpen(context.Background(), &fixture.payload)
			if err != nil {
				t.Fatal(err)
			}
			switch change {
			case "mode":
				fixture.payload.Mode = intents.SessionModePush
			case "strategy":
				operated := intents.SessionPullVoucherStrategyOperatedVoucher
				config.PullVoucherStrategy = &operated
			case "authority":
				config.SettlementAuthority = intents.SessionSettlementAuthorityDelegated
			case "funding kind":
				fixture.payload = intents.OpenPayloadPull(channel.String(), "1000000", fixture.payer.PublicKey().String(), fixture.authorized.String(), fixture.signature)
			}
			if _, err := NewSessionServer(config, store).ProcessOpen(context.Background(), &fixture.payload); err == nil || !strings.Contains(err.Error(), "funding context") {
				t.Fatalf("changed %s reused credit: %v", change, err)
			}
			after, err := store.GetChannel(context.Background(), channel.String())
			if err != nil || !reflect.DeepEqual(&before, after) {
				t.Fatalf("changed %s modified state", change)
			}
		})
	}
}

// A shared store does not make funding for one recipient valid for another.
func TestOpenReplayRejectsAnotherRecipient(t *testing.T) {
	for _, path := range []string{"core/signature-only", "core/attached", "public/signature-only", "public/attached"} {
		t.Run(path, func(t *testing.T) {
			fixture := buildOpenTxFixture(t)
			if strings.HasSuffix(path, "signature-only") {
				fixture.payload.Transaction = nil
			}
			r := newSessionChannelRPC(t, fixture, nil)
			store := NewMemoryChannelStore()
			otherRecipient := testutil.NewPrivateKey().PublicKey().String()
			if strings.HasPrefix(path, "core/") {
				configA := openSessionConfig(fixture)
				configA.VerifyOpenTx = NewOpenTxVerifier(configA, r)
				first := NewSessionServer(configA, store)
				if _, err := first.ProcessOpen(context.Background(), &fixture.payload); err != nil {
					t.Fatal(err)
				}
				configB := openSessionConfig(fixture)
				configB.Recipient = otherRecipient
				configB.VerifyOpenTx = NewOpenTxVerifier(configB, r)
				second := NewSessionServer(configB, store)
				if _, err := second.ProcessOpen(context.Background(), &fixture.payload); err == nil {
					t.Fatal("accepted open funded for another recipient through a shared store")
				}
			} else {
				first := newTestSession(t, func(o *SessionOptions) {
					o.RPC = r
					o.Store = store
					o.Operator = fixture.payer.PublicKey().String()
					o.Recipient = fixture.payee.String()
				})
				if _, err := verifySessionAction(t, first, intents.NewOpenAction(fixture.payload)); err != nil {
					t.Fatal(err)
				}
				second := newTestSession(t, func(o *SessionOptions) {
					o.RPC = r
					o.Store = store
					o.Operator = fixture.payer.PublicKey().String()
					o.Recipient = otherRecipient
				})
				if _, err := verifySessionAction(t, second, intents.NewOpenAction(fixture.payload)); err == nil {
					t.Fatal("accepted open funded for another recipient through a shared store")
				}
			}
		})
	}
}

func TestSessionMiddlewareRejectsAnotherRecipientOpen(t *testing.T) {
	fixture := buildOpenTxFixture(t)
	signer := newTestVoucherSigner(t)
	fixture.authorized = solana.MustPublicKeyFromBase58(signer.Address())
	channel, _, err := paymentchannels.FindChannelPDA(fixture.payer.PublicKey(), fixture.payee, fixture.mint, fixture.authorized, openFixtureSalt, openFixtureOpenSlot)
	if err != nil {
		t.Fatal(err)
	}
	fixture.channel = channel
	fixture.payload = intents.OpenPayloadPush(channel.String(), "1000000", signer.Address(), fixture.signature)
	r := newSessionChannelRPC(t, fixture, nil)
	store := NewMemoryChannelStore()
	first := newTestSession(t, func(o *SessionOptions) {
		o.RPC = r
		o.Store = store
		o.Operator = fixture.payer.PublicKey().String()
		o.Recipient = fixture.payee.String()
	})
	if _, err := verifySessionAction(t, first, intents.NewOpenAction(fixture.payload)); err != nil {
		t.Fatal(err)
	}
	otherRecipient := testutil.NewPrivateKey().PublicKey().String()
	second := newTestSession(t, func(o *SessionOptions) {
		o.RPC = r
		o.Store = store
		o.Operator = fixture.payer.PublicKey().String()
		o.Recipient = otherRecipient
	})
	calls := 0
	handler := SessionMiddleware(second, nil)(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { calls++; w.WriteHeader(http.StatusOK) }))
	submit := func(action intents.SessionAction) int {
		credential := sessionActionCredential(t, second, action)
		auth, err := core.FormatAuthorization(credential)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, "/resource", nil)
		req.Header.Set(core.AuthorizationHeader, auth)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		return res.Code
	}
	// The replayed open contains no proof of possession of the authorized key.
	status := submit(intents.NewOpenAction(fixture.payload))
	t.Logf("public-data-only open for other recipient: HTTP=%d handler_calls=%d", status, calls)
	if status != http.StatusPaymentRequired || calls != 0 {
		t.Error("cross-recipient open reached resource")
	}
}
