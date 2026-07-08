package client

import (
	"strings"
	"testing"

	"github.com/solana-foundation/pay-kit/go/internal/testutil"
	"github.com/solana-foundation/pay-kit/go/paycore"
	core "github.com/solana-foundation/pay-kit/go/protocols/mpp/core"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

func sessionChallenge(t *testing.T, request intents.SessionRequest) core.PaymentChallenge {
	t.Helper()
	encoded, err := core.NewBase64URLJSONValue(request)
	if err != nil {
		t.Fatalf("encode session request: %v", err)
	}
	return core.PaymentChallenge{
		ID:      "challenge-id",
		Realm:   "example",
		Method:  core.NewMethodName("solana"),
		Intent:  core.NewIntentName("session"),
		Request: encoded,
	}
}

func chargeIntentChallenge(t *testing.T) core.PaymentChallenge {
	t.Helper()
	challenge := sessionChallenge(t, testSessionRequest(
		testutil.NewPrivateKey().PublicKey(), testutil.NewPrivateKey().PublicKey()))
	challenge.Intent = core.NewIntentName("charge")
	return challenge
}

func TestSessionRequestModesDefaultsToPushOnly(t *testing.T) {
	cases := []struct {
		name  string
		modes []intents.SessionMode
		want  []intents.SessionMode
	}{
		{"omitted", nil, []intents.SessionMode{intents.SessionModePush}},
		{"explicit empty", []intents.SessionMode{}, []intents.SessionMode{intents.SessionModePush}},
		{"advertised", []intents.SessionMode{intents.SessionModePull},
			[]intents.SessionMode{intents.SessionModePull}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := intents.SessionRequest{Modes: tc.modes}
			got := SessionRequestModes(request)
			if len(got) != len(tc.want) {
				t.Fatalf("modes = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("modes = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestSelectSessionChallengeSkipsNonSessionChallenges(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	session := sessionChallenge(t, testSessionRequest(operator, recipient))

	selected, err := SelectSessionChallenge(
		[]core.PaymentChallenge{chargeIntentChallenge(t), session},
		SelectSessionChallengeOptions{},
	)
	if err != nil {
		t.Fatalf("SelectSessionChallenge: %v", err)
	}
	if selected == nil {
		t.Fatal("no challenge selected")
	}
	if !selected.Challenge.Intent.IsSession() {
		t.Fatalf("selected intent = %s, want session", selected.Challenge.Intent)
	}
	if selected.Request.Operator != operator.String() {
		t.Fatalf("decoded operator = %s", selected.Request.Operator)
	}
}

func TestSelectSessionChallengeFiltersByNetwork(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	devnet := testSessionRequest(operator, recipient)
	devnetName := "devnet"
	devnet.Network = &devnetName
	mainnet := testSessionRequest(operator, recipient)
	mainnetName := "mainnet"
	mainnet.Network = &mainnetName

	challenges := []core.PaymentChallenge{sessionChallenge(t, devnet), sessionChallenge(t, mainnet)}

	selected, err := SelectSessionChallenge(challenges, SelectSessionChallengeOptions{Network: "mainnet-beta"})
	if err != nil {
		t.Fatalf("SelectSessionChallenge: %v", err)
	}
	if selected == nil || selected.Request.Network == nil || *selected.Request.Network != "mainnet" {
		t.Fatalf("selected = %+v, want the mainnet challenge for mainnet-beta", selected)
	}

	selected, err = SelectSessionChallenge(challenges, SelectSessionChallengeOptions{Network: paycore.NetworkLocalnet})
	if err != nil {
		t.Fatalf("SelectSessionChallenge: %v", err)
	}
	if selected != nil {
		t.Fatalf("selected = %+v, want none for localnet", selected)
	}
}

func TestSelectSessionChallengeFiltersByCurrencyMint(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	usdc := testSessionRequest(operator, recipient)
	pyusd := testSessionRequest(operator, recipient)
	pyusd.Currency = "PYUSD"

	challenges := []core.PaymentChallenge{sessionChallenge(t, usdc), sessionChallenge(t, pyusd)}

	selected, err := SelectSessionChallenge(challenges, SelectSessionChallengeOptions{
		Currencies: []string{"PYUSD"},
	})
	if err != nil {
		t.Fatalf("SelectSessionChallenge: %v", err)
	}
	if selected == nil || selected.Request.Currency != "PYUSD" {
		t.Fatalf("selected = %+v, want PYUSD challenge", selected)
	}

	// A mint address matches its symbol through mint resolution.
	mintMatched, err := SelectSessionChallenge(challenges, SelectSessionChallengeOptions{
		Currencies: []string{selectedMintForUSDC()},
	})
	if err != nil {
		t.Fatalf("SelectSessionChallenge: %v", err)
	}
	if mintMatched == nil || mintMatched.Request.Currency != "USDC" {
		t.Fatalf("selected = %+v, want USDC challenge via mint address", mintMatched)
	}
}

// selectedMintForUSDC returns the mainnet USDC mint (localnet resolves to it).
func selectedMintForUSDC() string {
	return "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
}

func TestSelectSessionChallengePrefersAdvertisedMode(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()

	pushOnly := testSessionRequest(operator, recipient)
	pushOnly.Modes = nil
	pushOnly.PullVoucherStrategy = nil
	pull := testSessionRequest(operator, recipient)

	challenges := []core.PaymentChallenge{sessionChallenge(t, pushOnly), sessionChallenge(t, pull)}

	selected, err := SelectSessionChallenge(challenges, SelectSessionChallengeOptions{
		Modes: []intents.SessionMode{intents.SessionModePull},
	})
	if err != nil {
		t.Fatalf("SelectSessionChallenge: %v", err)
	}
	if selected == nil || len(selected.Request.Modes) == 0 ||
		selected.Request.Modes[0] != intents.SessionModePull {
		t.Fatalf("selected = %+v, want the pull challenge", selected)
	}

	// An omitted modes list advertises push, so a push client matches it first.
	selected, err = SelectSessionChallenge(challenges, SelectSessionChallengeOptions{
		Modes: []intents.SessionMode{intents.SessionModePush},
	})
	if err != nil {
		t.Fatalf("SelectSessionChallenge: %v", err)
	}
	if selected == nil || len(selected.Request.Modes) != 0 {
		t.Fatalf("selected = %+v, want the omitted-modes push-only challenge", selected)
	}

	// No advertised mode matches: nothing selected.
	selected, err = SelectSessionChallenge(
		[]core.PaymentChallenge{sessionChallenge(t, pushOnly)},
		SelectSessionChallengeOptions{Modes: []intents.SessionMode{intents.SessionModePull}},
	)
	if err != nil {
		t.Fatalf("SelectSessionChallenge: %v", err)
	}
	if selected != nil {
		t.Fatalf("selected = %+v, want none (push-only challenge, pull-only client)", selected)
	}
}

func TestSelectSessionChallengeRejectsUndecodableSessionRequest(t *testing.T) {
	challenge := core.PaymentChallenge{
		ID:      "challenge-id",
		Realm:   "example",
		Method:  core.NewMethodName("solana"),
		Intent:  core.NewIntentName("session"),
		Request: core.NewBase64URLJSONRaw("!!!not-base64url!!!"),
	}
	_, err := SelectSessionChallenge([]core.PaymentChallenge{challenge}, SelectSessionChallengeOptions{})
	if err == nil || !strings.Contains(err.Error(), "invalid Solana session challenge request") {
		t.Fatalf("error = %v, want invalid request", err)
	}
}

func TestSelectSessionChallengeFromHeaders(t *testing.T) {
	operator := testutil.NewPrivateKey().PublicKey()
	recipient := testutil.NewPrivateKey().PublicKey()
	challenge := sessionChallenge(t, testSessionRequest(operator, recipient))
	header, err := core.FormatWWWAuthenticate(challenge)
	if err != nil {
		t.Fatalf("FormatWWWAuthenticate: %v", err)
	}

	selected, err := SelectSessionChallengeFromHeaders([]string{header}, SelectSessionChallengeOptions{})
	if err != nil {
		t.Fatalf("SelectSessionChallengeFromHeaders: %v", err)
	}
	if selected == nil || selected.Request.Operator != operator.String() {
		t.Fatalf("selected = %+v, want parsed session challenge", selected)
	}

	none, err := SelectSessionChallengeFromHeaders([]string{"Basic realm=x"}, SelectSessionChallengeOptions{})
	if err != nil {
		t.Fatalf("SelectSessionChallengeFromHeaders: %v", err)
	}
	if none != nil {
		t.Fatalf("selected = %+v, want none for non-Payment header", none)
	}
}
