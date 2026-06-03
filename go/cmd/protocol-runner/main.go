// Command protocol-runner is the Go MPP protocol-primitive conformance runner.
//
// It speaks the canonical mpp-tools protocol adapter ABI (the same contract
// the TypeScript reference runner at harness/src/protocol/runners/typescript.ts
// implements): read one request envelope as JSON on stdin
//
//	{ "op": "<operation>", "input": <value> }
//
// drive the real Go pay_kit protocol layer (protocols/mpp/wire) for that
// operation, and write one response envelope as JSON on stdout
//
//	{ "success": true,  "result": <value> }
//	{ "success": false, "error": "<msg>", "error_type": "<type>" }
//
// The harness spawn driver (harness/src/protocol/runners/spawn.ts) wires this
// runner identically to every other language runner via the manifest at
// harness/protocol-runners/go.json, then validates it against the vendored
// canonical vectors under harness/vectors/mpp-protocol/.
//
// Operations are dispatched straight to the production wire functions:
//   - challenge.parse  -> wire.ParseWWWAuthenticate
//   - challenge.format -> wire.FormatWWWAuthenticate
//   - credential.parse -> wire.ParseAuthorization
//   - credential.format-> wire.FormatAuthorization
//   - receipt.parse    -> wire.ParseReceipt
//   - receipt.format   -> wire.FormatReceipt
//   - base64url.encode -> wire.Base64URLEncode
//   - base64url.decode -> wire.Base64URLDecode
//   - challenge.id     -> wire.NewBase64URLJSONValue + wire.ComputeChallengeID
//
// No operation result is faked: each handler returns exactly what the SDK
// produces. Operations the Go SDK does not implement return the
// unsupported_operation error_type.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/wire"
)

// request is the canonical adapter-ABI input envelope.
type request struct {
	Op    string          `json:"op"`
	Input json.RawMessage `json:"input"`
}

// response is the canonical adapter-ABI output envelope.
type response struct {
	Success   bool        `json:"success"`
	Result    interface{} `json:"result,omitempty"`
	Error     string      `json:"error,omitempty"`
	ErrorType string      `json:"error_type,omitempty"`
}

func ok(result interface{}) response {
	return response{Success: true, Result: result}
}

func fail(err error, errorType string) response {
	return response{Success: false, Error: err.Error(), ErrorType: errorType}
}

// headerInput is the `{ "header": "..." }` envelope shared by every parse op.
type headerInput struct {
	Header string `json:"header"`
}

// textInput is the `{ "text": "..." }` envelope shared by the base64url ops.
type textInput struct {
	Text string `json:"text"`
}

// challengeIDInput mirrors the canonical challenge.id ABI input. `request` is
// the structured payment request object (canonicalized by the SDK before it
// enters the HMAC), and `opaque` is the already-serialized pipe-slot string.
type challengeIDInput struct {
	SecretKey string          `json:"secretKey"`
	Realm     string          `json:"realm"`
	Method    string          `json:"method"`
	Intent    string          `json:"intent"`
	Request   json.RawMessage `json:"request"`
	Expires   string          `json:"expires"`
	Digest    string          `json:"digest"`
	Opaque    string          `json:"opaque"`
}

// challengeObject is the canonical golden shape for a parsed challenge: the
// request (and opaque) are decoded JSON values, not base64url strings, and
// the method/intent are plain strings. Optional fields are omitted when empty
// to match the vendored golden objects byte-for-byte under deep-equal.
type challengeObject struct {
	ID          string      `json:"id"`
	Realm       string      `json:"realm"`
	Method      string      `json:"method"`
	Intent      string      `json:"intent"`
	Request     interface{} `json:"request"`
	Expires     string      `json:"expires,omitempty"`
	Description string      `json:"description,omitempty"`
	Digest      string      `json:"digest,omitempty"`
	Opaque      interface{} `json:"opaque,omitempty"`
}

// decodeJSONValue decodes a base64url-encoded JSON blob into a generic value,
// preserving integers via json.Number so re-serialization is byte-stable.
func decodeJSONValue(b wire.Base64URLJSON) (interface{}, error) {
	payload, err := wire.Base64URLDecode(b.Raw())
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	var value interface{}
	if err := dec.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

// challengeToObject maps a parsed wire.PaymentChallenge into the canonical
// golden object shape, decoding the embedded base64url request/opaque blobs.
func challengeToObject(c wire.PaymentChallenge) (challengeObject, error) {
	reqValue, err := decodeJSONValue(c.Request)
	if err != nil {
		return challengeObject{}, err
	}
	obj := challengeObject{
		ID:          c.ID,
		Realm:       c.Realm,
		Method:      string(c.Method),
		Intent:      string(c.Intent),
		Request:     reqValue,
		Expires:     c.Expires,
		Description: c.Description,
		Digest:      c.Digest,
	}
	if c.Opaque != nil {
		opaqueValue, err := decodeJSONValue(*c.Opaque)
		if err != nil {
			return challengeObject{}, err
		}
		obj.Opaque = opaqueValue
	}
	return obj, nil
}

// unmarshalNumber decodes raw JSON into a generic value preserving integers.
func unmarshalNumber(raw json.RawMessage, out *interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(out)
}

func dispatch(req request) response {
	switch req.Op {
	case "challenge.parse":
		var in headerInput
		if err := json.Unmarshal(req.Input, &in); err != nil {
			return fail(err, "parse_error")
		}
		challenge, err := wire.ParseWWWAuthenticate(in.Header)
		if err != nil {
			return fail(err, "parse_error")
		}
		obj, err := challengeToObject(challenge)
		if err != nil {
			return fail(err, "parse_error")
		}
		return ok(obj)

	case "challenge.format":
		header, err := formatChallenge(req.Input)
		if err != nil {
			return fail(err, "format_error")
		}
		return ok(headerInput{Header: header})

	case "credential.parse":
		var in headerInput
		if err := json.Unmarshal(req.Input, &in); err != nil {
			return fail(err, "parse_error")
		}
		credential, err := wire.ParseAuthorization(in.Header)
		if err != nil {
			return fail(err, "parse_error")
		}
		// Emit the credential in its native wire JSON form; the harness
		// driver's normalizeCredential decodes challenge.request back into an
		// object before comparing, so no re-shaping is needed here.
		return ok(credential)

	case "credential.format":
		credential, err := credentialFromInput(req.Input)
		if err != nil {
			return fail(err, "format_error")
		}
		header, err := wire.FormatAuthorization(credential)
		if err != nil {
			return fail(err, "format_error")
		}
		return ok(headerInput{Header: header})

	case "receipt.parse":
		var in headerInput
		if err := json.Unmarshal(req.Input, &in); err != nil {
			return fail(err, "parse_error")
		}
		receipt, err := wire.ParseReceipt(in.Header)
		if err != nil {
			return fail(err, "parse_error")
		}
		return ok(receipt)

	case "receipt.format":
		var receipt wire.Receipt
		if err := json.Unmarshal(req.Input, &receipt); err != nil {
			return fail(err, "format_error")
		}
		header, err := wire.FormatReceipt(receipt)
		if err != nil {
			return fail(err, "format_error")
		}
		return ok(headerInput{Header: header})

	case "base64url.encode":
		var in textInput
		if err := json.Unmarshal(req.Input, &in); err != nil {
			return fail(err, "encoding_error")
		}
		return ok(textInput{Text: wire.Base64URLEncode([]byte(in.Text))})

	case "base64url.decode":
		var in textInput
		if err := json.Unmarshal(req.Input, &in); err != nil {
			return fail(err, "encoding_error")
		}
		decoded, err := wire.Base64URLDecode(in.Text)
		if err != nil {
			return fail(err, "encoding_error")
		}
		return ok(textInput{Text: string(decoded)})

	case "challenge.id":
		id, err := computeChallengeID(req.Input)
		if err != nil {
			return fail(err, "generation_error")
		}
		return ok(struct {
			ID string `json:"id"`
		}{ID: id})

	default:
		return fail(fmt.Errorf("unknown operation: %s", req.Op), "unsupported_operation")
	}
}

// formatChallenge builds a wire.PaymentChallenge from the canonical golden
// object shape (request as a structured object) and serializes it. The
// request object is canonicalized through the SDK's own base64url-JSON
// encoder so the produced wire matches the SDK's production output exactly.
func formatChallenge(input json.RawMessage) (string, error) {
	var raw struct {
		ID          string          `json:"id"`
		Realm       string          `json:"realm"`
		Method      string          `json:"method"`
		Intent      string          `json:"intent"`
		Request     json.RawMessage `json:"request"`
		Expires     string          `json:"expires"`
		Description string          `json:"description"`
		Digest      string          `json:"digest"`
		Opaque      json.RawMessage `json:"opaque"`
	}
	if err := json.Unmarshal(input, &raw); err != nil {
		return "", err
	}
	requestB64, err := base64JSONFromRaw(raw.Request)
	if err != nil {
		return "", err
	}
	challenge := wire.PaymentChallenge{
		ID:          raw.ID,
		Realm:       raw.Realm,
		Method:      wire.NewMethodName(raw.Method),
		Intent:      wire.NewIntentName(raw.Intent),
		Request:     requestB64,
		Expires:     raw.Expires,
		Description: raw.Description,
		Digest:      raw.Digest,
	}
	if len(raw.Opaque) > 0 && string(raw.Opaque) != "null" {
		opaque, err := base64JSONFromRaw(raw.Opaque)
		if err != nil {
			return "", err
		}
		challenge.Opaque = &opaque
	}
	return wire.FormatWWWAuthenticate(challenge)
}

// credentialFromInput builds a wire.PaymentCredential from the canonical
// golden object shape, encoding the nested challenge.request object into the
// SDK's base64url-JSON wire form.
func credentialFromInput(input json.RawMessage) (wire.PaymentCredential, error) {
	var raw struct {
		Challenge struct {
			ID      string          `json:"id"`
			Realm   string          `json:"realm"`
			Method  string          `json:"method"`
			Intent  string          `json:"intent"`
			Request json.RawMessage `json:"request"`
			Expires string          `json:"expires"`
			Digest  string          `json:"digest"`
			Opaque  json.RawMessage `json:"opaque"`
		} `json:"challenge"`
		Source  string          `json:"source"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(input, &raw); err != nil {
		return wire.PaymentCredential{}, err
	}
	requestB64, err := base64JSONFromRaw(raw.Challenge.Request)
	if err != nil {
		return wire.PaymentCredential{}, err
	}
	echo := wire.ChallengeEcho{
		ID:      raw.Challenge.ID,
		Realm:   raw.Challenge.Realm,
		Method:  wire.NewMethodName(raw.Challenge.Method),
		Intent:  wire.NewIntentName(raw.Challenge.Intent),
		Request: requestB64,
		Expires: raw.Challenge.Expires,
		Digest:  raw.Challenge.Digest,
	}
	if len(raw.Challenge.Opaque) > 0 && string(raw.Challenge.Opaque) != "null" {
		opaque, err := base64JSONFromRaw(raw.Challenge.Opaque)
		if err != nil {
			return wire.PaymentCredential{}, err
		}
		echo.Opaque = &opaque
	}
	credential := wire.PaymentCredential{Challenge: echo, Source: raw.Source}
	if len(raw.Payload) > 0 && string(raw.Payload) != "null" {
		msg := raw.Payload
		credential.Payload = &msg
	}
	return credential, nil
}

// base64JSONFromRaw canonicalizes a raw JSON value through the SDK's
// base64url-JSON encoder (RFC 8785-style key sorting + base64url).
func base64JSONFromRaw(raw json.RawMessage) (wire.Base64URLJSON, error) {
	if len(raw) == 0 {
		return wire.NewBase64URLJSONValue(map[string]interface{}{})
	}
	var value interface{}
	if err := unmarshalNumber(raw, &value); err != nil {
		return wire.Base64URLJSON{}, err
	}
	return wire.NewBase64URLJSONValue(value)
}

// computeChallengeID canonicalizes the structured request through the SDK's
// base64url-JSON encoder, then derives the HMAC challenge id via the
// production wire.ComputeChallengeID. opaque enters the HMAC as its
// already-serialized pipe-slot string, matching the canonical ABI.
func computeChallengeID(input json.RawMessage) (string, error) {
	var in challengeIDInput
	if err := json.Unmarshal(input, &in); err != nil {
		return "", err
	}
	requestB64, err := base64JSONFromRaw(in.Request)
	if err != nil {
		return "", err
	}
	return wire.ComputeChallengeID(
		in.SecretKey,
		in.Realm,
		in.Method,
		in.Intent,
		requestB64.Raw(),
		in.Expires,
		in.Digest,
		in.Opaque,
	), nil
}

func main() {
	raw, err := io.ReadAll(os.Stdin)
	if err != nil {
		emit(response{Success: false, Error: err.Error(), ErrorType: "runner_error"})
		os.Exit(1)
	}
	var req request
	if err := json.Unmarshal(bytes.TrimSpace(raw), &req); err != nil {
		emit(response{Success: false, Error: err.Error(), ErrorType: "runner_error"})
		os.Exit(1)
	}
	emit(dispatch(req))
}

func emit(resp response) {
	out, err := json.Marshal(resp)
	if err != nil {
		fmt.Printf(`{"success":false,"error":%q,"error_type":"runner_error"}`, err.Error())
		return
	}
	fmt.Println(string(out))
}
