package mpp

import (
	"context"
	"encoding/json"
	"testing"
)

func TestMemoryStoreRoundTrip(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()

	if _, ok, err := store.Get(ctx, "missing"); err != nil || ok {
		t.Fatalf("expected missing key, got ok=%v err=%v", ok, err)
	}
	if err := store.Put(ctx, "k", map[string]string{"name": "alice"}); err != nil {
		t.Fatalf("put failed: %v", err)
	}
	raw, ok, err := store.Get(ctx, "k")
	if err != nil || !ok {
		t.Fatalf("get failed: ok=%v err=%v", ok, err)
	}
	var payload map[string]string
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if payload["name"] != "alice" {
		t.Fatalf("unexpected payload: %#v", payload)
	}
	if err := store.Delete(ctx, "k"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
}

func TestMemoryStorePutMarshalError(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if err := store.Put(ctx, "k", make(chan int)); err == nil {
		t.Fatal("expected marshal error for channel value")
	}
}

func TestMemoryStorePutIfAbsentMarshalError(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	if _, err := store.PutIfAbsent(ctx, "k", make(chan int)); err == nil {
		t.Fatal("expected marshal error for channel value")
	}
}

func TestMemoryStorePutIfAbsent(t *testing.T) {
	store := NewMemoryStore()
	ctx := context.Background()
	inserted, err := store.PutIfAbsent(ctx, "k", true)
	if err != nil || !inserted {
		t.Fatalf("expected first insert to succeed, inserted=%v err=%v", inserted, err)
	}
	inserted, err = store.PutIfAbsent(ctx, "k", true)
	if err != nil || inserted {
		t.Fatalf("expected second insert to fail, inserted=%v err=%v", inserted, err)
	}
}
