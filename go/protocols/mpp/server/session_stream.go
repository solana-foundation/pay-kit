package server

// Server-side metered SSE stream writer.
//
// Emits the Server-Sent Event frames the metered session clients decode:
// "mpp.metering" directives, "mpp.usage" final-usage events, plain data
// payload messages, and the terminal "[DONE]" sentinel. The event names are
// canonical: they are the ones the SDK session clients parse (the Go
// client's SseDecoder/ParseMeteredSseEvent among them).

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// doneSentinel is the terminal data-only message recognized by the metered
// SSE decoders alongside the "done" event name.
const doneSentinel = "[DONE]"

// MeteredStream writes metered Server-Sent Events to an HTTP response. Build
// with NewMeteredStream; every write flushes so chunks reach the client as
// they are produced.
type MeteredStream struct {
	// writer receives the encoded SSE frames.
	writer io.Writer

	// flusher, when non-nil, is flushed after every frame so chunks reach
	// the client incrementally; nil writers buffer as usual.
	flusher http.Flusher
}

// NewMeteredStream prepares w for Server-Sent Events (Content-Type
// text/event-stream, no caching) and returns the stream writer. The
// ResponseWriter does not need to implement http.Flusher, but streaming is
// only incremental when it does.
func NewMeteredStream(w http.ResponseWriter) *MeteredStream {
	header := w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache")
	header.Set("Connection", "keep-alive")
	flusher, _ := w.(http.Flusher)
	return &MeteredStream{writer: w, flusher: flusher}
}

// NewMeteredStreamWriter wraps a raw writer (no header handling) for
// transports other than net/http.
func NewMeteredStreamWriter(w io.Writer) *MeteredStream {
	return &MeteredStream{writer: w}
}

// WriteEvent writes one SSE frame with an explicit event name. Empty event
// names emit a default (message) frame. The data must not be empty;
// multi-line data is split into one data: line per line per the SSE format.
func (m *MeteredStream) WriteEvent(event string, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("SSE event data must not be empty")
	}
	frame := ""
	if event != "" {
		frame = "event: " + event + "\n"
	}
	start := 0
	for i := 0; i <= len(data); i++ {
		if i == len(data) || data[i] == '\n' {
			frame += "data: " + string(data[start:i]) + "\n"
			start = i + 1
		}
	}
	frame += "\n"
	if _, err := io.WriteString(m.writer, frame); err != nil {
		return err
	}
	if m.flusher != nil {
		m.flusher.Flush()
	}
	return nil
}

// WriteJSON writes a default (message) frame whose data is the JSON encoding
// of v. Use for application payload chunks.
func (m *MeteredStream) WriteJSON(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return m.WriteEvent("", data)
}

// WriteMetering emits an "mpp.metering" event carrying the metering
// directive the client must commit after processing the paired payload.
func (m *MeteredStream) WriteMetering(directive intents.MeteringDirective) error {
	data, err := json.Marshal(directive)
	if err != nil {
		return err
	}
	return m.WriteEvent("mpp.metering", data)
}

// WriteUsage emits an "mpp.usage" event reporting the final amount owed for
// a streamed delivery. The amount must not exceed the amount reserved by the
// original directive.
func (m *MeteredStream) WriteUsage(usage intents.MeteringUsage) error {
	data, err := json.Marshal(usage)
	if err != nil {
		return err
	}
	return m.WriteEvent("mpp.usage", data)
}

// WriteEnvelope emits the payload as a default data frame followed by its
// "mpp.metering" directive, the pairing the metered session consumers
// expect.
func (m *MeteredStream) WriteEnvelope(payload any, directive intents.MeteringDirective) error {
	if err := m.WriteJSON(payload); err != nil {
		return err
	}
	return m.WriteMetering(directive)
}

// WriteDone emits the terminal "[DONE]" sentinel message.
func (m *MeteredStream) WriteDone() error {
	return m.WriteEvent("", []byte(doneSentinel))
}

// WriteDoneEvent emits an explicit "done" event, the alternative terminal
// frame the decoders accept.
func (m *MeteredStream) WriteDoneEvent() error {
	return m.WriteEvent("done", []byte(doneSentinel))
}
