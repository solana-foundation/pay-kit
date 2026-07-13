package paykit

import "context"

// Test-only hooks. Identifiers declared in an _test.go file are visible to the
// package's test binary but never exported to importers, which keeps these
// context helpers out of the public API.

// ContextWithPaymentForTests attaches a *Payment to ctx through the package's
// private context key.
func ContextWithPaymentForTests(ctx context.Context, pmt *Payment) context.Context {
	return context.WithValue(ctx, ctxKey{}, pmt)
}

// ContextWithChargeForTests attaches a *Charge to ctx through the package's
// private context key.
func ContextWithChargeForTests(ctx context.Context, c *Charge) context.Context {
	return context.WithValue(ctx, chargeKey{}, c)
}
