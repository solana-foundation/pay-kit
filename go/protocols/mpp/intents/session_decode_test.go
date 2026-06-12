package intents

// Decode-failure coverage for the session wire types: each SessionAction
// variant rejects a malformed flattened payload with a variant-specific
// error, and the OpenPayload/VoucherData deserializers reject non-object
// shapes outright.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSessionActionVariantDecodeFailures(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"open", `{"action":"open","mode":"push","salt":[]}`, "decode open action"},
		{"voucher", `{"action":"voucher","voucher":"not-an-object"}`, "decode voucher action"},
		{"commit", `{"action":"commit","deliveryId":5}`, "decode commit action"},
		{"topUp", `{"action":"topUp","channelId":5}`, "decode topUp action"},
		{"close", `{"action":"close","channelId":5}`, "decode close action"},
		{"tag", `{"action":5}`, "read session action tag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var action SessionAction
			err := json.Unmarshal([]byte(tc.raw), &action)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("decode %s = %v, want %q", tc.raw, err, tc.want)
			}
		})
	}
}

func TestOpenPayloadDecodeRejectsNonObject(t *testing.T) {
	var payload OpenPayload
	if err := json.Unmarshal([]byte(`"push"`), &payload); err == nil ||
		!strings.Contains(err.Error(), "decode open payload") {
		t.Fatalf("non-object open payload = %v", err)
	}
}

func TestVoucherDataDecodeRejectsNonObject(t *testing.T) {
	var data VoucherData
	if err := json.Unmarshal([]byte(`5`), &data); err == nil ||
		!strings.Contains(err.Error(), "decode voucher data") {
		t.Fatalf("non-object voucher data = %v", err)
	}
}

func TestSessionActionMarshalRejectsInvalidVariantCounts(t *testing.T) {
	var empty SessionAction
	if _, err := json.Marshal(empty); err == nil || !strings.Contains(err.Error(), "no variant set") {
		t.Fatalf("empty action marshal = %v", err)
	}
	open := OpenPayloadPush("c", "1", "signer", "sig")
	double := SessionAction{Open: &open, Close: &ClosePayload{ChannelID: "c"}}
	if _, err := json.Marshal(double); err == nil || !strings.Contains(err.Error(), "multiple variants set") {
		t.Fatalf("double action marshal = %v", err)
	}
}
