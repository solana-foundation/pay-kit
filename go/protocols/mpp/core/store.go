package core

import (
	"context"
	"encoding/json"
	"sync"
)

// Store is used for replay protection.
type Store interface {
	Get(ctx context.Context, key string) (json.RawMessage, bool, error)
	Put(ctx context.Context, key string, value any) error
	Delete(ctx context.Context, key string) error
	PutIfAbsent(ctx context.Context, key string, value any) (bool, error)
}

// MemoryStore is an in-memory Store implementation for tests and small deployments.
type MemoryStore struct {
	mu   sync.RWMutex
	data map[string]json.RawMessage
}

// NewMemoryStore creates a MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{data: map[string]json.RawMessage{}}
}

// Get returns a copy of the raw JSON value previously stored under key.
// The second return value reports whether the key was found.
func (s *MemoryStore) Get(_ context.Context, key string) (json.RawMessage, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.data[key]
	if !ok {
		return nil, false, nil
	}
	out := make(json.RawMessage, len(value))
	copy(out, value)
	return out, true, nil
}

// Put marshals value to JSON and stores it under key, overwriting any
// previous value at that key.
func (s *MemoryStore) Put(_ context.Context, key string, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = raw
	return nil
}

// Delete removes key from the store. Deleting a missing key is a no-op
// and is not reported as an error.
func (s *MemoryStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, key)
	return nil
}

// PutIfAbsent atomically stores value under key only when no value
// exists yet. It returns true when the value was inserted and false
// when the key was already present. This is the operation server-side
// replay protection relies on.
func (s *MemoryStore) PutIfAbsent(_ context.Context, key string, value any) (bool, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.data[key]; exists {
		return false, nil
	}
	s.data[key] = raw
	return true, nil
}
