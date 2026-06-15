package server

// Round-trips the server-side metered SSE writer through the client metered
// SSE decoder (SseDecoder + ParseMeteredSseEvent), proving the emitted frames
// carry the event names and payloads the metered session clients consume.

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/client"
	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

func decodeMeteredEvents(t *testing.T, raw string) []client.MeteredSseEvent {
	t.Helper()
	decoder := &client.SseDecoder{}
	events, err := decoder.PushChunk([]byte(raw))
	if err != nil {
		t.Fatalf("PushChunk: %v", err)
	}
	tail, err := decoder.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	events = append(events, tail...)
	parsed := make([]client.MeteredSseEvent, 0, len(events))
	for _, event := range events {
		metered, err := client.ParseMeteredSseEvent(event)
		if err != nil {
			t.Fatalf("ParseMeteredSseEvent(%+v): %v", event, err)
		}
		parsed = append(parsed, metered)
	}
	return parsed
}

func TestMeteredStreamRoundTripsThroughClientDecoder(t *testing.T) {
	recorder := httptest.NewRecorder()
	stream := NewMeteredStream(recorder)

	directive := intents.MeteringDirective{
		DeliveryID: "session-1:1",
		SessionID:  "session-1",
		Amount:     "100",
		Currency:   "USDC",
		Sequence:   1,
		ExpiresAt:  intents.DefaultSessionExpiresAt,
	}
	usage := intents.MeteringUsage{DeliveryID: "session-1:1", Amount: "80"}

	if err := stream.WriteEnvelope(map[string]string{"chunk": "A payment channel "}, directive); err != nil {
		t.Fatalf("WriteEnvelope: %v", err)
	}
	if err := stream.WriteUsage(usage); err != nil {
		t.Fatalf("WriteUsage: %v", err)
	}
	if err := stream.WriteDone(); err != nil {
		t.Fatalf("WriteDone: %v", err)
	}

	if contentType := recorder.Header().Get("Content-Type"); contentType != "text/event-stream" {
		t.Fatalf("Content-Type = %q", contentType)
	}
	if cacheControl := recorder.Header().Get("Cache-Control"); cacheControl != "no-cache" {
		t.Fatalf("Cache-Control = %q", cacheControl)
	}
	if !recorder.Flushed {
		t.Fatal("stream writes did not flush the response")
	}

	events := decodeMeteredEvents(t, recorder.Body.String())
	if len(events) != 4 {
		t.Fatalf("decoded %d events, want 4: %+v", len(events), events)
	}
	if events[0].Kind != client.MeteredSseEventMessage || !strings.Contains(string(events[0].Message), "A payment channel") {
		t.Fatalf("event 0 = %+v", events[0])
	}
	if events[1].Kind != client.MeteredSseEventMetering || events[1].Metering.DeliveryID != directive.DeliveryID {
		t.Fatalf("event 1 = %+v", events[1])
	}
	if events[1].Metering.Amount != "100" || events[1].Metering.Sequence != 1 {
		t.Fatalf("metering payload = %+v", events[1].Metering)
	}
	if events[2].Kind != client.MeteredSseEventUsage || events[2].Usage.Amount != "80" {
		t.Fatalf("event 2 = %+v", events[2])
	}
	if events[3].Kind != client.MeteredSseEventDone {
		t.Fatalf("event 3 = %+v", events[3])
	}
}

func TestMeteredStreamDoneEventVariant(t *testing.T) {
	recorder := httptest.NewRecorder()
	stream := NewMeteredStream(recorder)
	if err := stream.WriteDoneEvent(); err != nil {
		t.Fatalf("WriteDoneEvent: %v", err)
	}
	events := decodeMeteredEvents(t, recorder.Body.String())
	if len(events) != 1 || events[0].Kind != client.MeteredSseEventDone {
		t.Fatalf("events = %+v", events)
	}
}

func TestMeteredStreamSplitsMultiLineData(t *testing.T) {
	var buffer strings.Builder
	stream := NewMeteredStreamWriter(&buffer)
	if err := stream.WriteEvent("note", []byte("line-1\nline-2")); err != nil {
		t.Fatalf("WriteEvent: %v", err)
	}
	raw := buffer.String()
	if raw != "event: note\ndata: line-1\ndata: line-2\n\n" {
		t.Fatalf("frame = %q", raw)
	}

	decoder := &client.SseDecoder{}
	events, err := decoder.PushChunk([]byte(raw))
	if err != nil {
		t.Fatalf("PushChunk: %v", err)
	}
	if len(events) != 1 || events[0].Data != "line-1\nline-2" {
		t.Fatalf("events = %+v", events)
	}
}

func TestMeteredStreamRejectsEmptyData(t *testing.T) {
	stream := NewMeteredStreamWriter(&strings.Builder{})
	if err := stream.WriteEvent("note", nil); err == nil {
		t.Fatal("expected empty-data error")
	}
}

func TestMeteredStreamWriteJSONMarshalError(t *testing.T) {
	stream := NewMeteredStreamWriter(&strings.Builder{})
	if err := stream.WriteJSON(func() {}); err == nil {
		t.Fatal("expected marshal error")
	}
}
