// Kafka-style client helpers for metered session deliveries.
//
// SessionConsumer wraps an ActiveSession so applications can process delivered
// messages and call Ack/Commit instead of manually signing and posting
// vouchers. A failed commit never advances the local watermark, so the same
// directive can be retried safely.
package client

import (
	"context"
	"fmt"

	"github.com/solana-foundation/pay-kit/go/protocols/mpp/intents"
)

// CommitTransport sends a commit payload to the server and returns its receipt.
//
// HTTP clients, queues, and in-process tests all implement this. The directive
// is passed alongside the payload so transports can use CommitURL, Proof, or
// other routing hints without repeating them in the signed commit body.
type CommitTransport interface {
	Commit(ctx context.Context, directive intents.MeteringDirective, payload intents.CommitPayload) (intents.CommitReceipt, error)
}

// SessionConsumer is a client-side consumer for session-metered deliveries.
//
// SessionConsumer is not safe for concurrent use; the underlying ActiveSession
// watermark is advanced under Commit.
type SessionConsumer struct {
	// session is the wrapped ActiveSession; its cumulative watermark only
	// advances after the transport reports a successful commit.
	session *ActiveSession

	// transport posts signed commit payloads to the server and returns its
	// receipts.
	transport CommitTransport
}

// NewSessionConsumer wraps a session and a commit transport.
func NewSessionConsumer(session *ActiveSession, transport CommitTransport) *SessionConsumer {
	return &SessionConsumer{session: session, transport: transport}
}

// Session returns the wrapped session.
func (c *SessionConsumer) Session() *ActiveSession { return c.session }

// CommitDirective signs a voucher for the directive amount, sends it through
// the transport, and advances the local watermark only on success. It rejects
// directives whose session does not match, whose amount is not a valid base-unit
// integer, or whose amount is zero.
func (c *SessionConsumer) CommitDirective(ctx context.Context, directive intents.MeteringDirective) (intents.CommitReceipt, error) {
	if err := c.validateDirective(directive); err != nil {
		return intents.CommitReceipt{}, err
	}
	amount, err := directive.AmountBaseUnits()
	if err != nil {
		return intents.CommitReceipt{}, err
	}
	if amount == 0 {
		return intents.CommitReceipt{}, fmt.Errorf("metered delivery amount must be greater than zero")
	}

	voucher, err := c.session.PrepareIncrement(amount)
	if err != nil {
		return intents.CommitReceipt{}, err
	}
	payload := intents.CommitPayload{DeliveryID: directive.DeliveryID, Voucher: voucher}

	receipt, err := c.transport.Commit(ctx, directive, payload)
	if err != nil {
		return intents.CommitReceipt{}, err
	}
	// A replayed receipt means the server already settled this delivery, so its
	// Cumulative is the authoritative settled position. Recording the freshly
	// prepared (higher) voucher would push the local watermark past the server's
	// state and let a later close sign for more than was agreed; skipping it
	// entirely would instead leave the watermark behind the server when the
	// original response was lost, so the next delivery signs a non-monotonic
	// cumulative. Reconcile to the receipt cumulative on replay (never
	// regressing); record the voucher on a fresh committed receipt.
	switch receipt.Status {
	case intents.CommitStatusReplayed:
		settled, perr := parseCumulative(receipt.Cumulative)
		if perr != nil {
			return intents.CommitReceipt{}, fmt.Errorf("invalid replayed receipt cumulative: %w", perr)
		}
		// The server is untrusted: clamp to the voucher just prepared in this
		// call. An honest lost-response replay settles at or below it (the
		// session is single-threaded), so a server reporting a higher cumulative
		// cannot push the watermark past what the client actually signed —
		// otherwise the next voucher would over-authorize up to the deposit.
		prepared, perr := parseCumulative(voucher.Data.Cumulative)
		if perr != nil {
			return intents.CommitReceipt{}, fmt.Errorf("invalid prepared voucher cumulative: %w", perr)
		}
		if settled > prepared {
			settled = prepared
		}
		c.session.ReconcileSettled(settled)
	case intents.CommitStatusCommitted:
		if err := c.session.RecordVoucher(voucher); err != nil {
			return intents.CommitReceipt{}, err
		}
	default:
		// A malformed or unknown status must not advance local state.
		return intents.CommitReceipt{}, fmt.Errorf("unexpected commit receipt status: %q", receipt.Status)
	}
	return receipt, nil
}

func (c *SessionConsumer) validateDirective(directive intents.MeteringDirective) error {
	channelID := c.session.ChannelIDString()
	if directive.SessionID != channelID {
		return fmt.Errorf(
			"metered delivery session %s does not match active session %s", directive.SessionID, channelID)
	}
	return nil
}

// Accept validates an envelope and returns a delivery handle exposing Ack and
// Commit. The directive is validated up front so a mismatched session is
// rejected before the application processes the payload.
func Accept[P any](c *SessionConsumer, envelope intents.MeteredEnvelope[P]) (*MeteredDelivery[P], error) {
	if err := c.validateDirective(envelope.Metering); err != nil {
		return nil, err
	}
	return &MeteredDelivery[P]{
		consumer: c,
		payload:  envelope.Payload,
		metering: envelope.Metering,
	}, nil
}

// MeteredDelivery is a delivered payload paired with its metering directive.
// Call Ack (or its Commit alias) after the application has processed Payload.
type MeteredDelivery[P any] struct {
	// consumer is the consumer that accepted the delivery; Ack commits the
	// directive amount through it.
	consumer *SessionConsumer

	// payload is the delivered application payload.
	payload P

	// metering is the directive pricing this delivery; Ack signs a voucher
	// for its amount.
	metering intents.MeteringDirective
}

// Payload returns the delivered payload.
func (d *MeteredDelivery[P]) Payload() P { return d.payload }

// Metering returns the metering directive that accompanied the payload.
func (d *MeteredDelivery[P]) Metering() intents.MeteringDirective { return d.metering }

// Ack signs and commits a voucher for the directive amount.
func (d *MeteredDelivery[P]) Ack(ctx context.Context) (intents.CommitReceipt, error) {
	return d.consumer.CommitDirective(ctx, d.metering)
}

// Commit is an alias for Ack.
func (d *MeteredDelivery[P]) Commit(ctx context.Context) (intents.CommitReceipt, error) {
	return d.Ack(ctx)
}

// IntoParts returns the payload and metering directive without committing.
func (d *MeteredDelivery[P]) IntoParts() (P, intents.MeteringDirective) {
	return d.payload, d.metering
}
