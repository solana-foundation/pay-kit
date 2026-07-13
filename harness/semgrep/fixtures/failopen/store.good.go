package server

// GOOD: a shared/persistent store is REQUIRED. No silent in-memory fallback —
// mis-configuration fails CLOSED (error) rather than fanning out per-process.

import "errors"

type Config struct {
	Store SessionStore
}

func NewServer(config Config) (*Server, error) {
	if config.Store == nil {
		return nil, errors.New("a shared SessionStore is required outside single-process deploys")
	}
	return &Server{store: config.Store}, nil
}

// GOOD: an in-memory store is fine when it is an explicit opt-in, not a
// silent nil-fallback. The variable here is not gated on a nil config field.
func newSingleProcessMethod() *Method {
	store := NewMemoryChannelStore()
	return &Method{store: store}
}
