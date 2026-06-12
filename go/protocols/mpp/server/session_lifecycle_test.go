package server

// Unit coverage of the SessionLifecycle idle-close watchdog: zero-delay
// disablement, idle firing, touch resets, channel removal, and shutdown.

import (
	"sync"
	"testing"
	"time"
)

// idleRecorder collects closeOnIdle invocations.
type idleRecorder struct {
	// mu guards fired.
	mu sync.Mutex

	// fired accumulates the channel ids passed to the handler, in order.
	fired []string

	// ch receives each fired channel id so tests can block until the
	// watchdog fires.
	ch chan string
}

func newIdleRecorder() *idleRecorder {
	return &idleRecorder{ch: make(chan string, 16)}
}

func (r *idleRecorder) handler(channelID string) {
	r.mu.Lock()
	r.fired = append(r.fired, channelID)
	r.mu.Unlock()
	r.ch <- channelID
}

func (r *idleRecorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.fired)
}

func TestSessionLifecycleZeroDelayDisablesTimers(t *testing.T) {
	recorder := newIdleRecorder()
	lifecycle := NewSessionLifecycle(recorder.handler, 0)
	lifecycle.Touch("c1")

	time.Sleep(30 * time.Millisecond)
	if recorder.count() != 0 {
		t.Fatalf("closeOnIdle fired %d times with disabled delay", recorder.count())
	}
}

func TestSessionLifecycleFiresAfterIdle(t *testing.T) {
	recorder := newIdleRecorder()
	lifecycle := NewSessionLifecycle(recorder.handler, 10*time.Millisecond)
	defer lifecycle.Shutdown()

	lifecycle.Touch("c1")
	select {
	case channelID := <-recorder.ch:
		if channelID != "c1" {
			t.Fatalf("fired for %q, want c1", channelID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("closeOnIdle never fired")
	}
}

func TestSessionLifecycleTouchResetsTimer(t *testing.T) {
	recorder := newIdleRecorder()
	lifecycle := NewSessionLifecycle(recorder.handler, 80*time.Millisecond)
	defer lifecycle.Shutdown()

	lifecycle.Touch("c1")
	// Keep touching before the delay elapses; the timer must keep resetting.
	for range 3 {
		time.Sleep(30 * time.Millisecond)
		lifecycle.Touch("c1")
		if recorder.count() != 0 {
			t.Fatal("closeOnIdle fired while the channel was being touched")
		}
	}
	select {
	case <-recorder.ch:
	case <-time.After(2 * time.Second):
		t.Fatal("closeOnIdle never fired after touches stopped")
	}
	if recorder.count() != 1 {
		t.Fatalf("closeOnIdle fired %d times, want 1", recorder.count())
	}
}

func TestSessionLifecycleRemoveChannelCancelsTimer(t *testing.T) {
	recorder := newIdleRecorder()
	lifecycle := NewSessionLifecycle(recorder.handler, 20*time.Millisecond)
	defer lifecycle.Shutdown()

	lifecycle.Touch("c1")
	lifecycle.RemoveChannel("c1")

	time.Sleep(60 * time.Millisecond)
	if recorder.count() != 0 {
		t.Fatalf("closeOnIdle fired %d times after RemoveChannel", recorder.count())
	}
}

func TestSessionLifecycleShutdownCancelsAllTimersAndDisablesTouch(t *testing.T) {
	recorder := newIdleRecorder()
	lifecycle := NewSessionLifecycle(recorder.handler, 20*time.Millisecond)

	lifecycle.Touch("c1")
	lifecycle.Touch("c2")
	lifecycle.Shutdown()
	lifecycle.Touch("c3")

	time.Sleep(60 * time.Millisecond)
	if recorder.count() != 0 {
		t.Fatalf("closeOnIdle fired %d times after Shutdown", recorder.count())
	}
}
