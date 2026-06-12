package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

func sseEvt(event string, data string) SseEvent {
	if event == "" {
		return SseEvent{Data: data}
	}
	return SseEvent{Event: &event, Data: data}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw)
}

type delta struct {
	Delta string `json:"delta"` // wire "delta": text fragment of a test app message
}

func decodeDelta(t *testing.T, raw json.RawMessage) delta {
	t.Helper()
	out := delta{}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode delta: %v", err)
	}
	return out
}

func TestSseDecoderHandlesSplitChunks(t *testing.T) {
	decoder := SseDecoder{}
	events, err := decoder.PushChunk([]byte("event: message\ndata: {\"delta\""))
	if err != nil {
		t.Fatalf("PushChunk: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("partial chunk dispatched %d events", len(events))
	}
	events, err = decoder.PushChunk([]byte(":\"hi\"}\n\n"))
	if err != nil {
		t.Fatalf("PushChunk: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	if events[0].Event == nil || *events[0].Event != "message" {
		t.Fatalf("event = %v, want message", events[0].Event)
	}
	if events[0].Data != `{"delta":"hi"}` {
		t.Fatalf("data = %q", events[0].Data)
	}
}

func TestSseDecoderHandlesMetadataCRLFCommentsAndFinish(t *testing.T) {
	decoder := SseDecoder{}
	events, err := decoder.PushChunk(
		[]byte(": keepalive\r\nid: evt-1\r\nretry: 250\r\ndata: hello\r\ndata: world\r\n\r\n"))
	if err != nil {
		t.Fatalf("PushChunk: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %d, want 1", len(events))
	}
	got := events[0]
	if got.Event != nil {
		t.Fatalf("event = %v, want nil", got.Event)
	}
	if got.Data != "hello\nworld" {
		t.Fatalf("data = %q, want multi-line join", got.Data)
	}
	if got.ID == nil || *got.ID != "evt-1" {
		t.Fatalf("id = %v, want evt-1", got.ID)
	}
	if got.Retry == nil || *got.Retry != 250 {
		t.Fatalf("retry = %v, want 250", got.Retry)
	}

	events, err = decoder.PushChunk([]byte("retry: nope\nunknown\n\n"))
	if err != nil {
		t.Fatalf("PushChunk: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("invalid retry/unknown field dispatched %d events", len(events))
	}

	events, err = decoder.PushChunk([]byte("event: message\ndata: tail"))
	if err != nil {
		t.Fatalf("PushChunk: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("incomplete event dispatched early")
	}
	events, err = decoder.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if len(events) != 1 || events[0].Event == nil || *events[0].Event != "message" || events[0].Data != "tail" {
		t.Fatalf("finish events = %+v, want trailing message", events)
	}
}

func TestSseDecoderRejectsInvalidUTF8(t *testing.T) {
	decoder := SseDecoder{}
	_, err := decoder.PushChunk([]byte{0xff})
	if err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
		t.Fatalf("error = %v, want UTF-8 rejection", err)
	}
}

func TestParseMeteredSseEvents(t *testing.T) {
	meteringDirective := directive("chan", "1000")
	parsed, err := ParseMeteredSseEvent(sseEvt("mpp.metering", mustJSON(t, meteringDirective)))
	if err != nil {
		t.Fatalf("ParseMeteredSseEvent: %v", err)
	}
	if parsed.Kind != MeteredSseEventMetering || parsed.Metering.Amount != "1000" {
		t.Fatalf("parsed = %+v, want metering amount 1000", parsed)
	}

	parsed, err = ParseMeteredSseEvent(sseEvt("message", `{"delta":"hello"}`))
	if err != nil {
		t.Fatalf("ParseMeteredSseEvent: %v", err)
	}
	if parsed.Kind != MeteredSseEventMessage {
		t.Fatalf("kind = %v, want message", parsed.Kind)
	}
	if decodeDelta(t, parsed.Message).Delta != "hello" {
		t.Fatalf("message = %s", parsed.Message)
	}
}

func TestParseMeteredSseUsageDoneOtherAndErrors(t *testing.T) {
	parsed, err := ParseMeteredSseEvent(sseEvt("mpp.usage", `{"deliveryId":"d1","amount":"17"}`))
	if err != nil {
		t.Fatalf("ParseMeteredSseEvent: %v", err)
	}
	if parsed.Kind != MeteredSseEventUsage {
		t.Fatalf("kind = %v, want usage", parsed.Kind)
	}
	amount, err := parsed.Usage.AmountBaseUnits()
	if err != nil || amount != 17 {
		t.Fatalf("usage amount = %d (%v), want 17", amount, err)
	}

	parsed, err = ParseMeteredSseEvent(sseEvt("done", ""))
	if err != nil || parsed.Kind != MeteredSseEventDone {
		t.Fatalf("done parse = %+v (%v)", parsed, err)
	}
	parsed, err = ParseMeteredSseEvent(sseEvt("", " [DONE] "))
	if err != nil || parsed.Kind != MeteredSseEventDone {
		t.Fatalf("[DONE] sentinel parse = %+v (%v)", parsed, err)
	}
	parsed, err = ParseMeteredSseEvent(sseEvt("trace", "ignored"))
	if err != nil || parsed.Kind != MeteredSseEventOther {
		t.Fatalf("other parse = %+v (%v)", parsed, err)
	}

	if _, err := ParseMeteredSseEvent(sseEvt("metering", "{")); err == nil {
		t.Fatal("invalid metering JSON accepted")
	}
	if _, err := ParseMeteredSseEvent(sseEvt("usage", "{")); err == nil {
		t.Fatal("invalid usage JSON accepted")
	}
	if _, err := ParseMeteredSseEvent(sseEvt("", "{")); err == nil {
		t.Fatal("invalid message JSON accepted")
	}
}

func TestMeteredSseAckUsesFinalUsageAmount(t *testing.T) {
	consumer, _ := newConsumer(t, false)
	stream := consumer.MeteredSse()
	meteringDirective := directive(consumer.Session().ChannelIDString(), "1000")
	meteringDirective.DeliveryID = "stream-1"

	message, err := stream.AcceptEvent(sseEvt("mpp.metering", mustJSON(t, meteringDirective)))
	if err != nil || message != nil {
		t.Fatalf("metering accept = %s (%v)", message, err)
	}
	message, err = stream.AcceptEvent(sseEvt("message", `{"delta":"hello"}`))
	if err != nil {
		t.Fatalf("AcceptEvent: %v", err)
	}
	if decodeDelta(t, message).Delta != "hello" {
		t.Fatalf("message = %s", message)
	}
	if _, err := stream.AcceptEvent(sseEvt("mpp.usage", `{"deliveryId":"stream-1","amount":"425"}`)); err != nil {
		t.Fatalf("usage accept: %v", err)
	}

	receipt, err := stream.Ack(context.Background())
	if err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if receipt.Amount != "425" || receipt.Cumulative != "425" {
		t.Fatalf("receipt = %+v, want final usage amount 425", receipt)
	}
	if consumer.Session().Cumulative() != 425 {
		t.Fatalf("session cumulative = %d, want 425", consumer.Session().Cumulative())
	}
}

func TestMeteredSseAckUsesReservedAmountWithoutUsageAndTracksDone(t *testing.T) {
	consumer, _ := newConsumer(t, false)
	stream := consumer.MeteredSse()
	meteringDirective := directive(consumer.Session().ChannelIDString(), "1000")

	if _, err := stream.AcceptEvent(sseEvt("mpp.metering", mustJSON(t, meteringDirective))); err != nil {
		t.Fatalf("metering accept: %v", err)
	}
	if _, err := stream.AcceptEvent(sseEvt("done", "")); err != nil {
		t.Fatalf("done accept: %v", err)
	}
	if !stream.IsDone() {
		t.Fatal("stream should be done")
	}

	receipt, err := stream.Ack(context.Background())
	if err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if receipt.Amount != "1000" || receipt.Cumulative != "1000" {
		t.Fatalf("receipt = %+v, want reserved amount 1000", receipt)
	}
}

func TestMeteredSseReportsMissingMeteringAndUsageMismatch(t *testing.T) {
	consumer, _ := newConsumer(t, false)
	stream := consumer.MeteredSse()
	if _, err := stream.Ack(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "mpp.metering") {
		t.Fatalf("error = %v, want missing metering", err)
	}

	stream = consumer.MeteredSse()
	meteringDirective := directive(consumer.Session().ChannelIDString(), "1000")
	meteringDirective.DeliveryID = "stream-1"
	if _, err := stream.AcceptEvent(sseEvt("mpp.metering", mustJSON(t, meteringDirective))); err != nil {
		t.Fatalf("metering accept: %v", err)
	}
	_, err := stream.AcceptEvent(sseEvt("mpp.usage", `{"deliveryId":"other","amount":"1"}`))
	if err == nil || !strings.Contains(err.Error(), "does not match directive") {
		t.Fatalf("error = %v, want usage mismatch", err)
	}
}

func TestMeteredSseUsageBeforeDirectiveAccepted(t *testing.T) {
	// A usage event may arrive before the directive; it is accepted and the
	// amount applies to whichever directive follows.
	consumer, _ := newConsumer(t, false)
	stream := consumer.MeteredSse()
	if _, err := stream.AcceptEvent(sseEvt("mpp.usage", `{"deliveryId":"stream-1","amount":"7"}`)); err != nil {
		t.Fatalf("usage-before-directive rejected: %v", err)
	}
	meteringDirective := directive(consumer.Session().ChannelIDString(), "1000")
	meteringDirective.DeliveryID = "stream-1"
	if _, err := stream.AcceptEvent(sseEvt("mpp.metering", mustJSON(t, meteringDirective))); err != nil {
		t.Fatalf("metering accept: %v", err)
	}
	receipt, err := stream.Ack(context.Background())
	if err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if receipt.Amount != "7" {
		t.Fatalf("receipt amount = %s, want early usage 7", receipt.Amount)
	}
}

func newCommitServer(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	commits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/commit", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sdk-test" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}
		payload := intents.CommitPayload{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		commits++
		receipt := intents.CommitReceipt{
			DeliveryID: payload.DeliveryID,
			SessionID:  payload.Voucher.Data.ChannelID,
			Amount:     payload.Voucher.Data.Cumulative,
			Cumulative: payload.Voucher.Data.Cumulative,
			Status:     intents.CommitStatusCommitted,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(receipt)
	})
	mux.HandleFunc("/commit-error", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "commit failed", http.StatusInternalServerError)
	})
	mux.HandleFunc("/commit-invalid-json", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server, &commits
}

func TestHTTPCommitTransportSuccessAndErrors(t *testing.T) {
	server, commits := newCommitServer(t)
	session, _ := newSession(t)
	meteringDirective := directive(session.ChannelIDString(), "88")
	voucher, err := session.PrepareIncrement(88)
	if err != nil {
		t.Fatalf("PrepareIncrement: %v", err)
	}
	payload := intents.CommitPayload{DeliveryID: meteringDirective.DeliveryID, Voucher: voucher}

	transport := &HTTPCommitTransport{
		DefaultCommitURL: server.URL + "/commit",
		Authorization:    "Bearer sdk-test",
	}
	receipt, err := transport.Commit(context.Background(), meteringDirective, payload)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if receipt.Cumulative != "88" {
		t.Fatalf("receipt cumulative = %s, want 88", receipt.Cumulative)
	}
	if *commits != 1 {
		t.Fatalf("commits = %d, want 1", *commits)
	}

	missingURL := &HTTPCommitTransport{}
	if _, err := missingURL.Commit(context.Background(), meteringDirective, payload); err == nil ||
		!strings.Contains(err.Error(), "missing commitUrl") {
		t.Fatalf("error = %v, want missing commitUrl", err)
	}

	serverError := &HTTPCommitTransport{DefaultCommitURL: server.URL + "/commit-error"}
	if _, err := serverError.Commit(context.Background(), meteringDirective, payload); err == nil ||
		!strings.Contains(err.Error(), "500") {
		t.Fatalf("error = %v, want 500 surfaced", err)
	}

	invalidJSON := &HTTPCommitTransport{DefaultCommitURL: server.URL + "/commit-invalid-json"}
	if _, err := invalidJSON.Commit(context.Background(), meteringDirective, payload); err == nil ||
		!strings.Contains(err.Error(), "invalid commit receipt") {
		t.Fatalf("error = %v, want invalid receipt", err)
	}

	// Directive CommitURL takes precedence over the default.
	commitURL := server.URL + "/commit"
	meteringDirective.CommitURL = &commitURL
	routed := &HTTPCommitTransport{
		DefaultCommitURL: server.URL + "/commit-error",
		Authorization:    "Bearer sdk-test",
	}
	if _, err := routed.Commit(context.Background(), meteringDirective, payload); err != nil {
		t.Fatalf("Commit via directive URL: %v", err)
	}
}

func TestMeteredSseStreamReadsMessagesAndAckDrains(t *testing.T) {
	commitServer, commits := newCommitServer(t)
	session, _ := newSession(t)
	meteringDirective := directive(session.ChannelIDString(), "275")
	meteringDirective.DeliveryID = "stream-1"

	streamBody := "event: mpp.metering\ndata: " + mustJSON(t, meteringDirective) + "\n\n" +
		"event: message\ndata: {\"delta\":\"first\"}\n\n" +
		"event: message\ndata: {\"delta\":\"second\"}\n\n" +
		"event: mpp.usage\ndata: {\"deliveryId\":\"stream-1\",\"amount\":\"275\"}\n\n" +
		"data: [DONE]"

	transport := &HTTPCommitTransport{
		DefaultCommitURL: commitServer.URL + "/commit",
		Authorization:    "Bearer sdk-test",
	}
	consumer := NewSessionConsumer(session, transport)
	stream := NewMeteredSseStream(consumer, strings.NewReader(streamBody))

	first, err := stream.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if decodeDelta(t, first).Delta != "first" {
		t.Fatalf("first message = %s", first)
	}

	receipt, err := stream.Ack(context.Background())
	if err != nil {
		t.Fatalf("Ack: %v", err)
	}
	if receipt.Amount != "275" || receipt.Cumulative != "275" {
		t.Fatalf("receipt = %+v, want 275", receipt)
	}
	if *commits != 1 {
		t.Fatalf("commits = %d, want 1", *commits)
	}
}

func TestMeteredSseStreamCanReturnConsumer(t *testing.T) {
	session, _ := newSession(t)
	consumer := NewSessionConsumer(session, &recordingTransport{})
	stream := NewMeteredSseStream(consumer, strings.NewReader("data: [DONE]\n\n"))
	message, err := stream.Next()
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if message != nil {
		t.Fatalf("message = %s, want done", message)
	}
	returned := stream.IntoConsumer()
	if returned.Session().Cumulative() != 0 {
		t.Fatalf("cumulative = %d, want 0", returned.Session().Cumulative())
	}
}

func TestMeteredSseStreamSurfacesEventErrors(t *testing.T) {
	session, _ := newSession(t)
	consumer := NewSessionConsumer(session, &recordingTransport{})

	invalidUTF8 := NewMeteredSseStream(consumer, strings.NewReader("event: message\ndata: \xff\n\n"))
	if _, err := invalidUTF8.Next(); err == nil || !strings.Contains(err.Error(), "valid UTF-8") {
		t.Fatalf("error = %v, want UTF-8 rejection", err)
	}

	badJSON := NewMeteredSseStream(consumer, strings.NewReader("event: metering\ndata: {\n\n"))
	if _, err := badJSON.Next(); err == nil || !strings.Contains(err.Error(), "invalid mpp.metering") {
		t.Fatalf("error = %v, want metering rejection", err)
	}

	// Ack without a metering directive surfaces the missing-directive error
	// after draining.
	empty := NewMeteredSseStream(consumer, strings.NewReader("data: [DONE]\n\n"))
	if _, err := empty.Ack(context.Background()); err == nil ||
		!strings.Contains(err.Error(), "mpp.metering") {
		t.Fatalf("error = %v, want missing metering", err)
	}
}
