package server

// GOOD: a shared/persistent store is REQUIRED. No silent in-memory fallback —
// mis-configuration fails CLOSED (error) rather than fanning out per-process.

import (
	"errors"
	"os"
)

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

// GOOD: a local-memory fallback may exist only behind a concrete off-localnet
// rejection and a deliberate environment opt-in.
func newGuardedMethod(options Options, network string) (*Method, error) {
	store := options.Store
	usesMemoryStore := false
	if store != nil {
		_, usesMemoryStore = store.(*MemoryChannelStore)
	}
	if network != "localnet" && (store == nil || usesMemoryStore) && os.Getenv("ALLOW_MEMORY") != "1" {
		return nil, errors.New("shared SessionStore required")
	}
	if store == nil {
		store = NewMemoryChannelStore()
	}
	return &Method{store: store}, nil
}

// GOOD: callers may combine an explicit option with an environment override
// before the fail-closed branch, rather than repeating os.Getenv in it.
func newGuardedMethodWithOption(options Options, network string) (*Method, error) {
	store := options.Store
	allowUnsafe := options.AllowUnsafe || os.Getenv("ALLOW_MEMORY") == "1"
	usesMemoryStore := false
	if store != nil {
		_, usesMemoryStore = store.(*MemoryChannelStore)
	}
	if network != "localnet" && (store == nil || usesMemoryStore) && !allowUnsafe {
		return nil, errors.New("shared SessionStore required")
	}
	if store == nil {
		store = NewMemoryChannelStore()
	}
	return &Method{store: store}, nil
}
