package intents

import (
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mr-tron/base58"
)

func ptrStr(s string) *string { return &s }
func ptrU8(v uint8) *uint8    { return &v }

// ── SessionMode / strategy / status serde ──

func TestSessionModeSerialization(t *testing.T) {
	tests := []struct {
		mode SessionMode
		want string
	}{
		{SessionModePush, `"push"`},
		{SessionModePull, `"pull"`},
	}
	for _, tc := range tests {
		t.Run(string(tc.mode), func(t *testing.T) {
			got, err := json.Marshal(tc.mode)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
			var back SessionMode
			if err := json.Unmarshal(got, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if back != tc.mode {
				t.Fatalf("roundtrip got %q want %q", back, tc.mode)
			}
		})
	}
}

func TestSessionPullVoucherStrategySerialization(t *testing.T) {
	tests := []struct {
		strategy SessionPullVoucherStrategy
		want     string
	}{
		{SessionPullVoucherStrategyClientVoucher, `"clientVoucher"`},
		{SessionPullVoucherStrategyOperatedVoucher, `"operatedVoucher"`},
	}
	for _, tc := range tests {
		t.Run(string(tc.strategy), func(t *testing.T) {
			got, err := json.Marshal(tc.strategy)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
			var back SessionPullVoucherStrategy
			if err := json.Unmarshal(got, &back); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if back != tc.strategy {
				t.Fatalf("roundtrip got %q want %q", back, tc.strategy)
			}
		})
	}
}

func TestCommitStatusSerialization(t *testing.T) {
	tests := []struct {
		status CommitStatus
		want   string
	}{
		{CommitStatusCommitted, `"committed"`},
		{CommitStatusReplayed, `"replayed"`},
	}
	for _, tc := range tests {
		t.Run(string(tc.status), func(t *testing.T) {
			got, err := json.Marshal(tc.status)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if string(got) != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestDefaultSessionExpiresAt(t *testing.T) {
	if DefaultSessionExpiresAt != 4_102_444_800 {
		t.Fatalf("got %d", DefaultSessionExpiresAt)
	}
}

// ── SessionRequest ──

func TestSessionRequestRoundtrip(t *testing.T) {
	decimals := uint8(6)
	req := SessionRequest{
		Cap:         "10000000",
		Currency:    "USDC",
		Decimals:    &decimals,
		Network:     ptrStr("mainnet"),
		Operator:    "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
		Recipient:   "CXhrFZJLKqjzmP3sjYLcF4dTeXWKCy9e2SXXZ2Yo6MPY",
		Description: ptrStr("API session"),
		Modes:       []SessionMode{SessionModePush},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back SessionRequest
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Cap != "10000000" || back.Currency != "USDC" {
		t.Fatalf("unexpected back: %#v", back)
	}
	if back.Description == nil || *back.Description != "API session" {
		t.Fatalf("description: %v", back.Description)
	}
	if len(back.Modes) != 1 || back.Modes[0] != SessionModePush {
		t.Fatalf("modes: %v", back.Modes)
	}
}

func TestSessionRequestOmitsEmptyFields(t *testing.T) {
	req := SessionRequest{
		Cap:       "1000",
		Currency:  "USDC",
		Operator:  "op",
		Recipient: "rec",
		Splits:    nil,
		Modes:     nil,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(data)
	for _, key := range []string{"splits", "modes", "decimals", "network", "description", "externalId", "programId", "minVoucherDelta", "pullVoucherStrategy", "recentBlockhash"} {
		if strings.Contains(js, key) {
			t.Fatalf("expected %q omitted, got %s", key, js)
		}
	}
	for _, key := range []string{"cap", "currency", "operator", "recipient"} {
		if !strings.Contains(js, key) {
			t.Fatalf("expected %q present, got %s", key, js)
		}
	}
}

func TestSessionRequestEmptySplitsOmitted(t *testing.T) {
	req := SessionRequest{Cap: "1", Currency: "USDC", Operator: "op", Recipient: "rec", Splits: []SessionSplit{}}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(data), "splits") {
		t.Fatalf("empty splits should be omitted: %s", data)
	}
}

func TestSessionRequestWithModesPushAndPull(t *testing.T) {
	strategy := SessionPullVoucherStrategyClientVoucher
	req := SessionRequest{
		Cap:                 "1000",
		Currency:            "USDC",
		Operator:            "op",
		Recipient:           "rec",
		Modes:               []SessionMode{SessionModePush, SessionModePull},
		PullVoucherStrategy: &strategy,
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(data)
	if !strings.Contains(js, `"push"`) || !strings.Contains(js, `"pull"`) {
		t.Fatalf("modes missing: %s", js)
	}
	if !strings.Contains(js, `"pullVoucherStrategy":"clientVoucher"`) {
		t.Fatalf("strategy missing: %s", js)
	}
	var back SessionRequest
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Modes) != 2 || back.Modes[0] != SessionModePush || back.Modes[1] != SessionModePull {
		t.Fatalf("modes: %v", back.Modes)
	}
	if back.PullVoucherStrategy == nil || *back.PullVoucherStrategy != SessionPullVoucherStrategyClientVoucher {
		t.Fatalf("strategy: %v", back.PullVoucherStrategy)
	}
}

func TestSessionRequestWithSplits(t *testing.T) {
	req := SessionRequest{
		Cap:        "1000",
		Currency:   "USDC",
		Operator:   "op",
		Recipient:  "rec",
		Splits:     []SessionSplit{{Recipient: "s1", BPS: 100}, {Recipient: "s2", BPS: 200}},
		ProgramID:  ptrStr("prog123"),
		ExternalID: ptrStr("ref-1"),
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back SessionRequest
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Splits) != 2 || back.Splits[0].BPS != 100 {
		t.Fatalf("splits: %v", back.Splits)
	}
	if back.ProgramID == nil || *back.ProgramID != "prog123" {
		t.Fatalf("programId: %v", back.ProgramID)
	}
	if back.ExternalID == nil || *back.ExternalID != "ref-1" {
		t.Fatalf("externalId: %v", back.ExternalID)
	}
}

func TestSessionRequestWithMinVoucherDelta(t *testing.T) {
	req := SessionRequest{
		Cap:             "10000000",
		Currency:        "USDC",
		Decimals:        ptrU8(6),
		Network:         ptrStr("mainnet"),
		Operator:        "op",
		Recipient:       "rec",
		MinVoucherDelta: ptrStr("500"),
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"minVoucherDelta"`) {
		t.Fatalf("minVoucherDelta missing: %s", data)
	}
	var back SessionRequest
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.MinVoucherDelta == nil || *back.MinVoucherDelta != "500" {
		t.Fatalf("minVoucherDelta: %v", back.MinVoucherDelta)
	}
}

func TestSessionRequestRecentBlockhashRoundtrip(t *testing.T) {
	req := SessionRequest{Cap: "1", Currency: "USDC", Operator: "op", Recipient: "rec", RecentBlockhash: ptrStr("bh1")}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"recentBlockhash":"bh1"`) {
		t.Fatalf("recentBlockhash missing: %s", data)
	}
	var back SessionRequest
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.RecentBlockhash == nil || *back.RecentBlockhash != "bh1" {
		t.Fatalf("recentBlockhash: %v", back.RecentBlockhash)
	}
}

// ── OpenPayload constructors ──

func TestOpenPayloadPushFields(t *testing.T) {
	p := OpenPayloadPush("chan1", "1000000", "signer1", "txsig")
	if p.Mode != SessionModePush {
		t.Fatalf("mode: %q", p.Mode)
	}
	if p.ChannelID == nil || *p.ChannelID != "chan1" {
		t.Fatalf("channelId: %v", p.ChannelID)
	}
	if p.Deposit == nil || *p.Deposit != "1000000" {
		t.Fatalf("deposit: %v", p.Deposit)
	}
	if p.TokenAccount != nil || p.ApprovedAmount != nil {
		t.Fatal("pull fields should be nil")
	}
	if p.AuthorizedSigner != "signer1" || p.Signature != "txsig" {
		t.Fatalf("shared fields: %#v", p)
	}
}

func TestOpenPayloadPullFields(t *testing.T) {
	p := OpenPayloadPull("tokacct", "5000000", "wallet1", "signer1", "approvesig")
	if p.Mode != SessionModePull {
		t.Fatalf("mode: %q", p.Mode)
	}
	if p.ChannelID != nil || p.Deposit != nil {
		t.Fatal("push fields should be nil")
	}
	if p.TokenAccount == nil || *p.TokenAccount != "tokacct" {
		t.Fatalf("tokenAccount: %v", p.TokenAccount)
	}
	if p.ApprovedAmount == nil || *p.ApprovedAmount != "5000000" {
		t.Fatalf("approvedAmount: %v", p.ApprovedAmount)
	}
	if p.Owner == nil || *p.Owner != "wallet1" {
		t.Fatalf("owner: %v", p.Owner)
	}
}

func TestOpenPayloadPaymentChannelAndTxHelpers(t *testing.T) {
	p := OpenPayloadPaymentChannel("chan1", "1000000", "payer1", "payee1", "mint1", 99, 45, "signer1", "txsig").
		WithTransaction("open-tx").
		WithInitTx("init-tx").
		WithUpdateTx("update-tx")

	if p.Mode != SessionModePush {
		t.Fatalf("mode: %q", p.Mode)
	}
	id, err := p.SessionID()
	if err != nil || id != "chan1" {
		t.Fatalf("sessionID: %q %v", id, err)
	}
	dep, err := p.DepositAmount()
	if err != nil || dep != 1_000_000 {
		t.Fatalf("depositAmount: %d %v", dep, err)
	}
	if p.Payer == nil || *p.Payer != "payer1" {
		t.Fatalf("payer: %v", p.Payer)
	}
	if p.Payee == nil || *p.Payee != "payee1" {
		t.Fatalf("payee: %v", p.Payee)
	}
	if p.Mint == nil || *p.Mint != "mint1" {
		t.Fatalf("mint: %v", p.Mint)
	}
	if p.Salt == nil || *p.Salt != 99 {
		t.Fatalf("salt: %v", p.Salt)
	}
	if p.GracePeriod == nil || *p.GracePeriod != 45 {
		t.Fatalf("gracePeriod: %v", p.GracePeriod)
	}
	if p.Transaction == nil || *p.Transaction != "open-tx" {
		t.Fatalf("transaction: %v", p.Transaction)
	}
	if p.InitMultiDelegateTx == nil || *p.InitMultiDelegateTx != "init-tx" {
		t.Fatalf("init: %v", p.InitMultiDelegateTx)
	}
	if p.UpdateDelegationTx == nil || *p.UpdateDelegationTx != "update-tx" {
		t.Fatalf("update: %v", p.UpdateDelegationTx)
	}
}

func TestOpenPayloadPullPaymentChannelUsesChannelIDAndDeposit(t *testing.T) {
	p := OpenPayloadPaymentChannelWithMode(SessionModePull, "chan1", "1000000", "payer1", "payee1", "mint1", 99, 45, "signer1", "pending").
		WithTransaction("open-tx")
	if p.Mode != SessionModePull {
		t.Fatalf("mode: %q", p.Mode)
	}
	id, err := p.SessionID()
	if err != nil || id != "chan1" {
		t.Fatalf("sessionID: %q %v", id, err)
	}
	dep, err := p.DepositAmount()
	if err != nil || dep != 1_000_000 {
		t.Fatalf("depositAmount: %d %v", dep, err)
	}
	if p.TokenAccount != nil || p.ApprovedAmount != nil {
		t.Fatal("token fields should be nil")
	}
	if p.Transaction == nil || *p.Transaction != "open-tx" {
		t.Fatalf("transaction: %v", p.Transaction)
	}
}

func TestOpenPayloadPushSessionIDAndDeposit(t *testing.T) {
	p := OpenPayloadPush("chan1", "2000000", "s", "sig")
	id, err := p.SessionID()
	if err != nil || id != "chan1" {
		t.Fatalf("sessionID: %q %v", id, err)
	}
	dep, err := p.DepositAmount()
	if err != nil || dep != 2_000_000 {
		t.Fatalf("depositAmount: %d %v", dep, err)
	}
}

func TestOpenPayloadPullSessionIDAndDeposit(t *testing.T) {
	p := OpenPayloadPull("tokacct", "3000000", "wallet1", "s", "sig")
	id, err := p.SessionID()
	if err != nil || id != "tokacct" {
		t.Fatalf("sessionID: %q %v", id, err)
	}
	dep, err := p.DepositAmount()
	if err != nil || dep != 3_000_000 {
		t.Fatalf("depositAmount: %d %v", dep, err)
	}
}

func TestOpenPayloadMissingRequiredFieldsAndInvalidDeposit(t *testing.T) {
	push := OpenPayloadPush("chan1", "bad", "s", "sig")
	if _, err := push.DepositAmount(); err == nil {
		t.Fatal("expected invalid deposit error")
	}
	push.Deposit = nil
	if _, err := push.DepositAmount(); err == nil {
		t.Fatal("expected missing deposit error")
	}
	push.ChannelID = nil
	if _, err := push.SessionID(); err == nil {
		t.Fatal("expected missing channelId error")
	}

	pull := OpenPayloadPull("tokacct", "bad", "wallet", "s", "sig")
	if _, err := pull.DepositAmount(); err == nil {
		t.Fatal("expected invalid pull deposit error")
	}
	pull.ApprovedAmount = nil
	if _, err := pull.DepositAmount(); err == nil {
		t.Fatal("expected missing approvedAmount error")
	}
	pull.TokenAccount = nil
	if _, err := pull.SessionID(); err == nil {
		t.Fatal("expected missing tokenAccount error")
	}
}

func TestOpenPayloadPushRoundtripJSON(t *testing.T) {
	p := OpenPayloadPush("chan1", "1000000", "signer1", "txsig")
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(data)
	if !strings.Contains(js, `"mode":"push"`) {
		t.Fatalf("mode missing: %s", js)
	}
	if !strings.Contains(js, `"channelId":"chan1"`) {
		t.Fatalf("channelId missing: %s", js)
	}
	if strings.Contains(js, "tokenAccount") {
		t.Fatalf("tokenAccount should be omitted: %s", js)
	}
	var back OpenPayload
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Mode != SessionModePush || back.ChannelID == nil || *back.ChannelID != "chan1" {
		t.Fatalf("back: %#v", back)
	}
}

func TestOpenPayloadPullRoundtripJSON(t *testing.T) {
	p := OpenPayloadPull("tokacct", "5000000", "wallet1", "signer1", "approvesig")
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(data)
	if !strings.Contains(js, `"mode":"pull"`) {
		t.Fatalf("mode missing: %s", js)
	}
	if !strings.Contains(js, `"tokenAccount":"tokacct"`) {
		t.Fatalf("tokenAccount missing: %s", js)
	}
	if !strings.Contains(js, `"owner":"wallet1"`) {
		t.Fatalf("owner missing: %s", js)
	}
	if strings.Contains(js, "channelId") {
		t.Fatalf("channelId should be omitted: %s", js)
	}
	var back OpenPayload
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Mode != SessionModePull || back.TokenAccount == nil || *back.TokenAccount != "tokacct" {
		t.Fatalf("back: %#v", back)
	}
	if back.Owner == nil || *back.Owner != "wallet1" {
		t.Fatalf("owner: %v", back.Owner)
	}
}

func TestOpenPayloadSaltSerializesAsStringAndAcceptsNumber(t *testing.T) {
	const salt = ^uint64(0) - 7 // u64::MAX - 7
	p := OpenPayloadPaymentChannel("chan1", "1000000", "payer1", "payee1", "mint1", salt, 900, "signer1", "txsig")
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `"salt":"18446744073709551608"`
	if !strings.Contains(string(data), want) {
		t.Fatalf("salt not a decimal string: %s", data)
	}
	var back OpenPayload
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Salt == nil || *back.Salt != salt {
		t.Fatalf("salt roundtrip: %v", back.Salt)
	}

	legacy := `{"mode":"push","channelId":"chan1","deposit":"1000000","payer":"payer1","payee":"payee1","mint":"mint1","salt":42,"gracePeriod":900,"authorizedSigner":"signer1","signature":"txsig"}`
	var legacyBack OpenPayload
	if err := json.Unmarshal([]byte(legacy), &legacyBack); err != nil {
		t.Fatalf("legacy unmarshal: %v", err)
	}
	if legacyBack.Salt == nil || *legacyBack.Salt != 42 {
		t.Fatalf("legacy salt: %v", legacyBack.Salt)
	}
}

func TestOpenPayloadSaltBigNumberDecodesWithoutPrecisionLoss(t *testing.T) {
	// A u64 number larger than 2^53 must survive number-form decode.
	legacy := `{"mode":"push","channelId":"c","deposit":"1","salt":18446744073709551608,"authorizedSigner":"s","signature":"sig"}`
	var p OpenPayload
	if err := json.Unmarshal([]byte(legacy), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.Salt == nil || *p.Salt != ^uint64(0)-7 {
		t.Fatalf("big number salt: %v", p.Salt)
	}
}

func TestOpenPayloadSaltInvalid(t *testing.T) {
	cases := []string{
		`{"mode":"push","channelId":"c","deposit":"1","salt":"notanumber","authorizedSigner":"s","signature":"sig"}`,
		`{"mode":"push","channelId":"c","deposit":"1","salt":-1,"authorizedSigner":"s","signature":"sig"}`,
		`{"mode":"push","channelId":"c","deposit":"1","salt":true,"authorizedSigner":"s","signature":"sig"}`,
	}
	for _, c := range cases {
		var p OpenPayload
		if err := json.Unmarshal([]byte(c), &p); err == nil {
			t.Fatalf("expected error decoding %s", c)
		}
	}
}

func TestOpenPayloadSaltNullAndAbsent(t *testing.T) {
	null := `{"mode":"push","channelId":"c","deposit":"1","salt":null,"authorizedSigner":"s","signature":"sig"}`
	var p OpenPayload
	if err := json.Unmarshal([]byte(null), &p); err != nil {
		t.Fatalf("unmarshal null: %v", err)
	}
	if p.Salt != nil {
		t.Fatalf("salt should be nil for null, got %v", p.Salt)
	}
	absent := `{"mode":"push","channelId":"c","deposit":"1","authorizedSigner":"s","signature":"sig"}`
	var q OpenPayload
	if err := json.Unmarshal([]byte(absent), &q); err != nil {
		t.Fatalf("unmarshal absent: %v", err)
	}
	if q.Salt != nil {
		t.Fatalf("salt should be nil when absent, got %v", q.Salt)
	}
}

func TestOpenPayloadMissingModeFailsDecode(t *testing.T) {
	js := `{"channelId":"chan1","deposit":"1000","authorizedSigner":"s","signature":"sig"}`
	var p OpenPayload
	if err := json.Unmarshal([]byte(js), &p); err == nil {
		t.Fatal("expected missing mode error")
	}
}

func TestOpenPayloadUnknownModeSessionIDAndDeposit(t *testing.T) {
	p := OpenPayload{Mode: SessionMode("weird"), AuthorizedSigner: "s", Signature: "sig"}
	if _, err := p.SessionID(); err == nil {
		t.Fatal("expected unknown mode sessionID error")
	}
	if _, err := p.DepositAmount(); err == nil {
		t.Fatal("expected unknown mode deposit error")
	}
}

// ── Metering ──

func TestMeteringAmountParsersAndUsageRoundtrip(t *testing.T) {
	directive := MeteringDirective{
		DeliveryID: "d1",
		SessionID:  "chan1",
		Amount:     "not-a-number",
		Currency:   "USDC",
		Sequence:   1,
		ExpiresAt:  DefaultSessionExpiresAt,
		Proof:      ptrStr("proof"),
	}
	if _, err := directive.AmountBaseUnits(); err == nil {
		t.Fatal("expected invalid metering amount error")
	}

	usage := MeteringUsage{DeliveryID: "d1", Amount: "42"}
	data, err := json.Marshal(usage)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"deliveryId":"d1"`) {
		t.Fatalf("deliveryId missing: %s", data)
	}
	var back MeteringUsage
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	v, err := back.AmountBaseUnits()
	if err != nil || v != 42 {
		t.Fatalf("amount: %d %v", v, err)
	}

	bad := MeteringUsage{DeliveryID: "d1", Amount: "bad"}
	if _, err := bad.AmountBaseUnits(); err == nil {
		t.Fatal("expected bad usage amount error")
	}
}

func TestMeteringDirectiveAndEnvelopeRoundtrip(t *testing.T) {
	directive := MeteringDirective{
		DeliveryID: "d1",
		SessionID:  "chan1",
		Amount:     "125",
		Currency:   "USDC",
		Sequence:   7,
		ExpiresAt:  4_102_444_800,
		CommitURL:  ptrStr("https://example.test/commit"),
	}
	v, err := directive.AmountBaseUnits()
	if err != nil || v != 125 {
		t.Fatalf("amount: %d %v", v, err)
	}

	envelope := MeteredEnvelope[map[string]any]{
		Payload:  map[string]any{"ok": true},
		Metering: directive,
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(data)
	if !strings.Contains(js, `"deliveryId":"d1"`) {
		t.Fatalf("deliveryId missing: %s", js)
	}
	if !strings.Contains(js, `"commitUrl":"https://example.test/commit"`) {
		t.Fatalf("commitUrl missing: %s", js)
	}
	var back MeteredEnvelope[map[string]any]
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Metering.Sequence != 7 {
		t.Fatalf("sequence: %d", back.Metering.Sequence)
	}
	if back.Payload["ok"] != true {
		t.Fatalf("payload: %v", back.Payload)
	}
}

func TestMeteringDirectiveOmitsOptionalFields(t *testing.T) {
	directive := MeteringDirective{DeliveryID: "d1", SessionID: "c", Amount: "1", Currency: "USDC", Sequence: 1, ExpiresAt: 1}
	data, err := json.Marshal(directive)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(data)
	if strings.Contains(js, "commitUrl") || strings.Contains(js, "proof") {
		t.Fatalf("optional fields should be omitted: %s", js)
	}
}

func TestCommitReceiptRoundtrip(t *testing.T) {
	receipt := CommitReceipt{
		DeliveryID: "d1",
		SessionID:  "chan1",
		Amount:     "100",
		Cumulative: "500",
		Status:     CommitStatusCommitted,
	}
	data, err := json.Marshal(receipt)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(data), `"status":"committed"`) {
		t.Fatalf("status: %s", data)
	}
	var back CommitReceipt
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Status != CommitStatusCommitted || back.Cumulative != "500" {
		t.Fatalf("back: %#v", back)
	}
}

// ── SessionAction variants ──

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(data)
}

func TestSessionActionOpenPushRoundtrip(t *testing.T) {
	action := NewOpenAction(OpenPayloadPush("chan123", "5000000", "signer123", "sig456"))
	js := mustMarshal(t, action)
	if !strings.Contains(js, `"action":"open"`) {
		t.Fatalf("action tag missing: %s", js)
	}
	if !strings.Contains(js, `"mode":"push"`) {
		t.Fatalf("mode missing: %s", js)
	}
	var back SessionAction
	if err := json.Unmarshal([]byte(js), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Open == nil {
		t.Fatal("expected Open variant")
	}
	if back.Open.Mode != SessionModePush {
		t.Fatalf("mode: %q", back.Open.Mode)
	}
	id, err := back.Open.SessionID()
	if err != nil || id != "chan123" {
		t.Fatalf("sessionID: %q %v", id, err)
	}
	dep, err := back.Open.DepositAmount()
	if err != nil || dep != 5_000_000 {
		t.Fatalf("deposit: %d %v", dep, err)
	}
	if back.Open.AuthorizedSigner != "signer123" {
		t.Fatalf("signer: %q", back.Open.AuthorizedSigner)
	}
}

func TestSessionActionOpenPullRoundtrip(t *testing.T) {
	action := NewOpenAction(OpenPayloadPull("tokacct", "3000000", "wallet1", "signer1", "approvesig"))
	js := mustMarshal(t, action)
	if !strings.Contains(js, `"action":"open"`) {
		t.Fatalf("action tag missing: %s", js)
	}
	if !strings.Contains(js, `"mode":"pull"`) || !strings.Contains(js, "tokenAccount") {
		t.Fatalf("pull fields missing: %s", js)
	}
	var back SessionAction
	if err := json.Unmarshal([]byte(js), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Open == nil || back.Open.Mode != SessionModePull {
		t.Fatalf("back: %#v", back.Open)
	}
	id, _ := back.Open.SessionID()
	if id != "tokacct" {
		t.Fatalf("sessionID: %q", id)
	}
}

func TestSessionActionVoucherRoundtrip(t *testing.T) {
	nonce := uint64(3)
	action := NewVoucherAction(VoucherPayload{
		Voucher: SignedVoucher{
			Data:      VoucherData{ChannelID: "chan1", Cumulative: "500000", ExpiresAt: 1 << 62, Nonce: &nonce},
			Signature: "sig_here",
		},
	})
	js := mustMarshal(t, action)
	if !strings.Contains(js, `"action":"voucher"`) {
		t.Fatalf("action tag missing: %s", js)
	}
	if !strings.Contains(js, `"cumulativeAmount":"500000"`) {
		t.Fatalf("cumulativeAmount missing: %s", js)
	}
	var back SessionAction
	if err := json.Unmarshal([]byte(js), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Voucher == nil {
		t.Fatal("expected Voucher variant")
	}
	if back.Voucher.Voucher.Data.Cumulative != "500000" {
		t.Fatalf("cumulative: %q", back.Voucher.Voucher.Data.Cumulative)
	}
	if back.Voucher.Voucher.Data.Nonce == nil || *back.Voucher.Voucher.Data.Nonce != 3 {
		t.Fatalf("nonce: %v", back.Voucher.Voucher.Data.Nonce)
	}
}

func TestSessionActionCommitRoundtrip(t *testing.T) {
	nonce := uint64(3)
	action := NewCommitAction(CommitPayload{
		DeliveryID: "delivery-1",
		Voucher: SignedVoucher{
			Data:      VoucherData{ChannelID: "chan1", Cumulative: "500000", ExpiresAt: 1 << 62, Nonce: &nonce},
			Signature: "sig_here",
		},
	})
	js := mustMarshal(t, action)
	if !strings.Contains(js, `"action":"commit"`) {
		t.Fatalf("action tag missing: %s", js)
	}
	if !strings.Contains(js, `"deliveryId":"delivery-1"`) {
		t.Fatalf("deliveryId missing: %s", js)
	}
	var back SessionAction
	if err := json.Unmarshal([]byte(js), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Commit == nil || back.Commit.DeliveryID != "delivery-1" {
		t.Fatalf("back: %#v", back.Commit)
	}
	if back.Commit.Voucher.Data.Cumulative != "500000" {
		t.Fatalf("cumulative: %q", back.Commit.Voucher.Data.Cumulative)
	}
}

func TestSessionActionTopUpRoundtrip(t *testing.T) {
	action := NewTopUpAction(TopUpPayload{ChannelID: "chan1", NewDeposit: "9000000", Signature: "txsig"})
	js := mustMarshal(t, action)
	if !strings.Contains(js, `"action":"topUp"`) {
		t.Fatalf("expected topUp camelCase tag: %s", js)
	}
	var back SessionAction
	if err := json.Unmarshal([]byte(js), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.TopUp == nil || back.TopUp.NewDeposit != "9000000" || back.TopUp.Signature != "txsig" {
		t.Fatalf("back: %#v", back.TopUp)
	}
}

func TestSessionActionCloseNoVoucherRoundtrip(t *testing.T) {
	action := NewCloseAction(ClosePayload{ChannelID: "chan1"})
	js := mustMarshal(t, action)
	if !strings.Contains(js, `"action":"close"`) {
		t.Fatalf("action tag missing: %s", js)
	}
	if strings.Contains(js, "voucher") {
		t.Fatalf("voucher should be omitted: %s", js)
	}
	var back SessionAction
	if err := json.Unmarshal([]byte(js), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Close == nil || back.Close.Voucher != nil {
		t.Fatalf("back: %#v", back.Close)
	}
}

func TestSessionActionCloseWithVoucherRoundtrip(t *testing.T) {
	nonce := uint64(7)
	action := NewCloseAction(ClosePayload{
		ChannelID: "chan1",
		Voucher: &SignedVoucher{
			Data:      VoucherData{ChannelID: "chan1", Cumulative: "700000", ExpiresAt: 1 << 62, Nonce: &nonce},
			Signature: "final_sig",
		},
	})
	js := mustMarshal(t, action)
	var back SessionAction
	if err := json.Unmarshal([]byte(js), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Close == nil || back.Close.Voucher == nil {
		t.Fatalf("back: %#v", back.Close)
	}
	if back.Close.Voucher.Data.Cumulative != "700000" {
		t.Fatalf("cumulative: %q", back.Close.Voucher.Data.Cumulative)
	}
}

func TestSessionActionMarshalErrors(t *testing.T) {
	var empty SessionAction
	if _, err := json.Marshal(empty); err == nil {
		t.Fatal("expected error marshaling empty action")
	}
	multi := SessionAction{Open: &OpenPayload{Mode: SessionModePush}, Close: &ClosePayload{ChannelID: "c"}}
	if _, err := json.Marshal(multi); err == nil {
		t.Fatal("expected error marshaling multi-variant action")
	}
}

func TestSessionActionUnmarshalErrors(t *testing.T) {
	cases := []string{
		`{"channelId":"c"}`,                  // missing action
		`{"action":"bogus","channelId":"c"}`, // unknown action
		`not json`,                           // malformed
		`{"action":"open"}`,                  // open missing mode
	}
	for _, c := range cases {
		var a SessionAction
		if err := json.Unmarshal([]byte(c), &a); err == nil {
			t.Fatalf("expected error decoding %q", c)
		}
	}
}

// ── VoucherData ──

func TestVoucherDataCumulativeAlias(t *testing.T) {
	js := `{"channelId":"chan1","cumulative":"123","expiresAt":42}`
	var v VoucherData
	if err := json.Unmarshal([]byte(js), &v); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if v.Cumulative != "123" {
		t.Fatalf("alias not honored: %q", v.Cumulative)
	}
	// Canonical key still works and takes precedence when both present.
	both := `{"channelId":"chan1","cumulativeAmount":"999","cumulative":"123","expiresAt":42}`
	var v2 VoucherData
	if err := json.Unmarshal([]byte(both), &v2); err != nil {
		t.Fatalf("unmarshal both: %v", err)
	}
	if v2.Cumulative != "999" {
		t.Fatalf("canonical should win: %q", v2.Cumulative)
	}
}

func TestVoucherDataMarshalUsesCumulativeAmount(t *testing.T) {
	v := VoucherData{ChannelID: "c", Cumulative: "100", ExpiresAt: 42}
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	js := string(data)
	if !strings.Contains(js, `"cumulativeAmount":"100"`) {
		t.Fatalf("expected cumulativeAmount: %s", js)
	}
	if strings.Contains(js, `"cumulative":`) {
		t.Fatalf("should not emit cumulative alias: %s", js)
	}
}

func TestVoucherDataMessageBytesWithNonce(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = 3
	}
	channelID := base58.Encode(raw)
	nonce := uint64(1)
	data := VoucherData{ChannelID: channelID, Cumulative: "1000", ExpiresAt: 42, Nonce: &nonce}
	bytes, err := data.MessageBytes()
	if err != nil {
		t.Fatalf("messageBytes: %v", err)
	}
	if len(bytes) != 48 {
		t.Fatalf("len: %d", len(bytes))
	}
	decoded, _ := base58.Decode(channelID)
	if string(bytes[:32]) != string(decoded) {
		t.Fatal("channelId prefix mismatch")
	}
	var cumWant [8]byte
	binary.LittleEndian.PutUint64(cumWant[:], 1000)
	if string(bytes[32:40]) != string(cumWant[:]) {
		t.Fatal("cumulative LE mismatch")
	}
	var expWant [8]byte
	binary.LittleEndian.PutUint64(expWant[:], 42)
	if string(bytes[40:48]) != string(expWant[:]) {
		t.Fatal("expiresAt LE mismatch")
	}
}

func TestVoucherDataMessageBytesWithoutNonce(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = 4
	}
	data := VoucherData{ChannelID: base58.Encode(raw), Cumulative: "1000", ExpiresAt: 42}
	bytes, err := data.MessageBytes()
	if err != nil {
		t.Fatalf("messageBytes: %v", err)
	}
	if len(bytes) != 48 {
		t.Fatalf("len: %d", len(bytes))
	}
}

func TestVoucherDataMessageBytesDeterministicAndDiffersByCumulative(t *testing.T) {
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = 6
	}
	channelID := base58.Encode(raw)
	a := VoucherData{ChannelID: channelID, Cumulative: "100", ExpiresAt: 42}
	a2 := VoucherData{ChannelID: channelID, Cumulative: "100", ExpiresAt: 42}
	b := VoucherData{ChannelID: channelID, Cumulative: "200", ExpiresAt: 42}
	ab, _ := a.MessageBytes()
	a2b, _ := a2.MessageBytes()
	bb, _ := b.MessageBytes()
	if string(ab) != string(a2b) {
		t.Fatal("expected deterministic bytes")
	}
	if string(ab) == string(bb) {
		t.Fatal("expected different bytes for different cumulative")
	}
}

func TestVoucherDataMessageBytesErrors(t *testing.T) {
	// Non-base58 channelId.
	bad := VoucherData{ChannelID: "0OIl", Cumulative: "1", ExpiresAt: 1}
	if _, err := bad.MessageBytes(); err == nil {
		t.Fatal("expected invalid channelId error")
	}
	// Channel id not 32 bytes.
	short := VoucherData{ChannelID: base58.Encode([]byte{1, 2, 3}), Cumulative: "1", ExpiresAt: 1}
	if _, err := short.MessageBytes(); err == nil {
		t.Fatal("expected 32-byte length error")
	}
	// Invalid cumulative.
	rawb := make([]byte, 32)
	good := VoucherData{ChannelID: base58.Encode(rawb), Cumulative: "notnum", ExpiresAt: 1}
	if _, err := good.MessageBytes(); err == nil {
		t.Fatal("expected invalid cumulative error")
	}
}

func TestSignedVoucherFields(t *testing.T) {
	v := SignedVoucher{
		Data:      VoucherData{ChannelID: "c", Cumulative: "100", ExpiresAt: 1 << 62},
		Signature: "abc123",
	}
	if v.Data.Cumulative != "100" || v.Signature != "abc123" {
		t.Fatalf("fields: %#v", v)
	}
}
