// HTTP streaming helpers for metered sessions.
//
// LLM APIs commonly stream responses over Server-Sent Events (SSE) or chunked
// HTTP. This file keeps the parser transport-neutral (SseDecoder works on raw
// chunks from any reader), then layers a net/http-friendly stream and commit
// transport on top for applications that want batteries included.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// SseEvent is a parsed Server-Sent Event frame. Event, ID, and Retry are nil
// when the frame omitted the field.
type SseEvent struct {
	// Event is the event name from "event:" lines; nil means the frame used
	// the default "message" event.
	Event *string

	// Data is the frame payload: all "data:" line values joined with
	// newlines, empty when the frame carried no data lines.
	Data string

	// ID is the event id from the "id:" line, the value a reconnecting
	// client would echo as Last-Event-ID.
	ID *string

	// Retry is the reconnection delay in milliseconds from the "retry:"
	// line; non-numeric values are dropped.
	Retry *uint64
}

// SseDecoder is an incremental SSE decoder.
//
// Feed raw HTTP chunks with PushChunk. It returns all complete events decoded
// from that chunk and retains partial data internally.
type SseDecoder struct {
	// buffer holds the undecoded tail of the stream: bytes pushed but not
	// yet terminated by a newline.
	buffer string

	// current accumulates the fields of the in-progress event until a blank
	// line dispatches it.
	current SseEvent
}

// PushChunk decodes the events completed by a raw chunk of the stream body.
func (d *SseDecoder) PushChunk(chunk []byte) ([]SseEvent, error) {
	if !utf8.Valid(chunk) {
		return nil, fmt.Errorf("SSE chunk is not valid UTF-8")
	}
	d.buffer += string(chunk)

	var events []SseEvent
	for {
		index := strings.IndexByte(d.buffer, '\n')
		if index < 0 {
			break
		}
		line := d.buffer[:index]
		d.buffer = d.buffer[index+1:]
		line = strings.TrimSuffix(line, "\r")
		if event, ok := d.processLine(line); ok {
			events = append(events, event)
		}
	}
	return events, nil
}

// Finish flushes an incomplete final event, if any, at EOF.
func (d *SseDecoder) Finish() ([]SseEvent, error) {
	var events []SseEvent
	if d.buffer != "" {
		line := strings.TrimSuffix(d.buffer, "\r")
		d.buffer = ""
		if event, ok := d.processLine(line); ok {
			events = append(events, event)
		}
	}
	if event, ok := d.dispatchCurrent(); ok {
		events = append(events, event)
	}
	return events, nil
}

func (d *SseDecoder) processLine(line string) (SseEvent, bool) {
	if line == "" {
		return d.dispatchCurrent()
	}
	if strings.HasPrefix(line, ":") {
		return SseEvent{}, false
	}

	field := line
	value := ""
	if index := strings.IndexByte(line, ':'); index >= 0 {
		field = line[:index]
		value = strings.TrimPrefix(line[index+1:], " ")
	}

	switch field {
	case "event":
		event := value
		d.current.Event = &event
	case "data":
		if d.current.Data != "" {
			d.current.Data += "\n"
		}
		d.current.Data += value
	case "id":
		id := value
		d.current.ID = &id
	case "retry":
		if retry, err := strconv.ParseUint(value, 10, 64); err == nil {
			d.current.Retry = &retry
		}
	}
	return SseEvent{}, false
}

func (d *SseDecoder) dispatchCurrent() (SseEvent, bool) {
	if d.current.Event == nil && d.current.Data == "" && d.current.ID == nil && d.current.Retry == nil {
		return SseEvent{}, false
	}
	current := d.current
	d.current = SseEvent{}
	return current, true
}

// MeteredSseEventKind discriminates ParseMeteredSseEvent results.
type MeteredSseEventKind int

// MeteredSseEvent kinds.
const (
	// MeteredSseEventMetering is an mpp.metering / metering directive event.
	MeteredSseEventMetering MeteredSseEventKind = iota

	// MeteredSseEventUsage is an mpp.usage / usage final-amount event.
	MeteredSseEventUsage

	// MeteredSseEventMessage is an application message event.
	MeteredSseEventMessage

	// MeteredSseEventDone is a done event or [DONE] sentinel message.
	MeteredSseEventDone

	// MeteredSseEventOther is an unrecognized event passed through untouched.
	MeteredSseEventOther
)

// MeteredSseEvent is a parsed metered SSE event. Exactly the field matching
// Kind is populated.
type MeteredSseEvent struct {
	// Kind discriminates which of the payload fields below is set.
	Kind MeteredSseEventKind

	// Metering is the decoded directive of an mpp.metering/metering event
	// (the per-delivery amount reservation).
	Metering *intents.MeteringDirective

	// Usage is the decoded final-amount report of an mpp.usage/usage event.
	Usage *intents.MeteringUsage

	// Message is the raw JSON payload of an application message event, left
	// for the caller to decode.
	Message json.RawMessage

	// Other is the unrecognized event passed through verbatim.
	Other *SseEvent
}

// ParseMeteredSseEvent classifies an SSE event by the metered-session event
// names: "mpp.metering"/"metering", "mpp.usage"/"usage", "done", and the
// "[DONE]" sentinel on the default message event. Application messages keep
// their raw JSON payload for the caller to decode.
func ParseMeteredSseEvent(event SseEvent) (MeteredSseEvent, error) {
	eventName := "message"
	if event.Event != nil {
		eventName = *event.Event
	}
	switch eventName {
	case "mpp.metering", "metering":
		directive := intents.MeteringDirective{}
		if err := json.Unmarshal([]byte(event.Data), &directive); err != nil {
			return MeteredSseEvent{}, fmt.Errorf("invalid mpp.metering event: %w", err)
		}
		return MeteredSseEvent{Kind: MeteredSseEventMetering, Metering: &directive}, nil
	case "mpp.usage", "usage":
		usage := intents.MeteringUsage{}
		if err := json.Unmarshal([]byte(event.Data), &usage); err != nil {
			return MeteredSseEvent{}, fmt.Errorf("invalid mpp.usage event: %w", err)
		}
		return MeteredSseEvent{Kind: MeteredSseEventUsage, Usage: &usage}, nil
	case "done":
		return MeteredSseEvent{Kind: MeteredSseEventDone}, nil
	case "message":
		if strings.TrimSpace(event.Data) == "[DONE]" {
			return MeteredSseEvent{Kind: MeteredSseEventDone}, nil
		}
		if !json.Valid([]byte(event.Data)) {
			return MeteredSseEvent{}, fmt.Errorf("invalid SSE message event: %q", event.Data)
		}
		return MeteredSseEvent{Kind: MeteredSseEventMessage, Message: json.RawMessage(event.Data)}, nil
	default:
		other := event
		return MeteredSseEvent{Kind: MeteredSseEventOther, Other: &other}, nil
	}
}

// meteredStreamState pairs the live metering directive with the optional final
// usage amount.
type meteredStreamState struct {
	// directive is the latest mpp.metering directive seen on the stream;
	// nil until one arrives, which makes committing an error.
	directive *intents.MeteringDirective

	// finalAmount is the usage-reported final amount in token base units;
	// nil commits the directive's reserved amount instead.
	finalAmount *uint64

	// done is set once the stream signals completion via a done event, a
	// [DONE] sentinel message, or EOF.
	done bool
}

// applyEvent folds one SSE event into the state, returning the raw application
// message when the event carries one. A usage event must reference the live
// directive's deliveryId; it may override only the amount.
func (s *meteredStreamState) applyEvent(event SseEvent) (json.RawMessage, error) {
	parsed, err := ParseMeteredSseEvent(event)
	if err != nil {
		return nil, err
	}
	switch parsed.Kind {
	case MeteredSseEventMetering:
		s.directive = parsed.Metering
		return nil, nil
	case MeteredSseEventUsage:
		if s.directive != nil && parsed.Usage.DeliveryID != s.directive.DeliveryID {
			return nil, fmt.Errorf(
				"usage delivery %s does not match directive %s",
				parsed.Usage.DeliveryID, s.directive.DeliveryID)
		}
		amount, err := parsed.Usage.AmountBaseUnits()
		if err != nil {
			return nil, err
		}
		s.finalAmount = &amount
		return nil, nil
	case MeteredSseEventMessage:
		return parsed.Message, nil
	case MeteredSseEventDone:
		s.done = true
		return nil, nil
	default:
		return nil, nil
	}
}

// directiveForCommit returns the live directive with the final usage amount
// applied, erroring when the stream never emitted a metering event.
func (s *meteredStreamState) directiveForCommit() (intents.MeteringDirective, error) {
	if s.directive == nil {
		return intents.MeteringDirective{}, fmt.Errorf("stream did not include mpp.metering event")
	}
	directive := *s.directive
	if s.finalAmount != nil {
		directive.Amount = strconv.FormatUint(*s.finalAmount, 10)
	}
	return directive, nil
}

// MeteredSseSession is a transport-neutral state machine for one metered SSE
// stream: feed it decoded SSE events, then Ack to commit the final amount.
type MeteredSseSession struct {
	// consumer is the borrowed session consumer that signs and commits the
	// stream's final amount on Ack.
	consumer *SessionConsumer

	// state folds the metering directive, final usage amount, and done flag
	// out of the accepted events.
	state meteredStreamState
}

// MeteredSse starts a metered SSE state machine borrowing this consumer.
func (c *SessionConsumer) MeteredSse() *MeteredSseSession {
	return &MeteredSseSession{consumer: c}
}

// AcceptEvent folds one decoded SSE event into the stream state and returns
// the raw application message when the event carries one.
func (s *MeteredSseSession) AcceptEvent(event SseEvent) (json.RawMessage, error) {
	return s.state.applyEvent(event)
}

// IsDone reports whether the stream signaled completion.
func (s *MeteredSseSession) IsDone() bool { return s.state.done }

// Ack commits the stream's final amount (the usage amount when reported,
// otherwise the directive's reserved amount) through the consumer.
func (s *MeteredSseSession) Ack(ctx context.Context) (intents.CommitReceipt, error) {
	directive, err := s.state.directiveForCommit()
	if err != nil {
		return intents.CommitReceipt{}, err
	}
	return s.consumer.CommitDirective(ctx, directive)
}

// HTTPCommitTransport is a minimal net/http transport for commit endpoints.
// The zero value posts to each directive's CommitURL with the default client.
type HTTPCommitTransport struct {
	// Client is the HTTP client. nil uses http.DefaultClient.
	Client *http.Client

	// DefaultCommitURL is the commit endpoint used when a directive omits
	// CommitURL.
	DefaultCommitURL string

	// Authorization is an optional Authorization header value attached to
	// every commit request.
	Authorization string
}

// Commit posts the payload as JSON to the directive's commit endpoint and
// decodes the receipt.
func (t *HTTPCommitTransport) Commit(
	ctx context.Context,
	directive intents.MeteringDirective,
	payload intents.CommitPayload,
) (intents.CommitReceipt, error) {
	url := t.DefaultCommitURL
	if directive.CommitURL != nil {
		url = *directive.CommitURL
	}
	if url == "" {
		return intents.CommitReceipt{}, fmt.Errorf("metering directive missing commitUrl")
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return intents.CommitReceipt{}, fmt.Errorf("encode commit payload: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return intents.CommitReceipt{}, fmt.Errorf("build commit request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if t.Authorization != "" {
		request.Header.Set("Authorization", t.Authorization)
	}

	client := t.Client
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return intents.CommitReceipt{}, fmt.Errorf("commit request failed: %w", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return intents.CommitReceipt{}, fmt.Errorf(
			"commit endpoint returned %d: %s", response.StatusCode, string(detail))
	}

	receipt := intents.CommitReceipt{}
	if err := json.NewDecoder(response.Body).Decode(&receipt); err != nil {
		return intents.CommitReceipt{}, fmt.Errorf("invalid commit receipt: %w", err)
	}
	return receipt, nil
}

// MeteredSseStream reads a metered SSE response body, yielding raw application
// messages and committing the final amount on Ack.
type MeteredSseStream struct {
	// consumer is the session consumer that signs and commits the stream's
	// final amount on Ack; IntoConsumer hands it back for the next request.
	consumer *SessionConsumer

	// body is the SSE response body being drained; the caller retains
	// ownership and closes it after the stream is done.
	body io.Reader

	// decoder incrementally parses raw body chunks into SSE events.
	decoder SseDecoder

	// pending queues decoded application messages not yet returned by Next.
	pending []json.RawMessage

	// state folds the metering directive, final usage amount, and done flag
	// out of the decoded events.
	state meteredStreamState

	// buf is the reusable scratch buffer for body reads.
	buf []byte
}

// NewMeteredSseStream wraps a consumer and an SSE response body, e.g.
// http.Response.Body. The caller retains ownership of the body and closes it
// after the stream is drained.
func NewMeteredSseStream(consumer *SessionConsumer, body io.Reader) *MeteredSseStream {
	return &MeteredSseStream{
		consumer: consumer,
		body:     body,
		buf:      make([]byte, 4096),
	}
}

// Next returns the next application message, or nil once the stream is done.
func (s *MeteredSseStream) Next() (json.RawMessage, error) {
	for {
		if len(s.pending) > 0 {
			message := s.pending[0]
			s.pending = s.pending[1:]
			return message, nil
		}
		if s.state.done {
			return nil, nil
		}

		n, readErr := s.body.Read(s.buf)
		if n > 0 {
			events, err := s.decoder.PushChunk(s.buf[:n])
			if err != nil {
				return nil, err
			}
			if err := s.applyEvents(events); err != nil {
				return nil, err
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				return nil, fmt.Errorf("stream read failed: %w", readErr)
			}
			events, err := s.decoder.Finish()
			if err != nil {
				return nil, err
			}
			if err := s.applyEvents(events); err != nil {
				return nil, err
			}
			s.state.done = true
		}
	}
}

func (s *MeteredSseStream) applyEvents(events []SseEvent) error {
	for _, event := range events {
		message, err := s.state.applyEvent(event)
		if err != nil {
			return err
		}
		if message != nil {
			s.pending = append(s.pending, message)
		}
	}
	return nil
}

// Ack drains any remaining events and commits the stream's final amount.
func (s *MeteredSseStream) Ack(ctx context.Context) (intents.CommitReceipt, error) {
	if !s.state.done {
		for {
			message, err := s.Next()
			if err != nil {
				return intents.CommitReceipt{}, err
			}
			if message == nil {
				break
			}
		}
	}
	directive, err := s.state.directiveForCommit()
	if err != nil {
		return intents.CommitReceipt{}, err
	}
	return s.consumer.CommitDirective(ctx, directive)
}

// IntoConsumer returns the wrapped consumer for reuse on the next request.
func (s *MeteredSseStream) IntoConsumer() *SessionConsumer {
	return s.consumer
}
