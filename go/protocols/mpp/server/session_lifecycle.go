package server

// Per-channel idle-close lifecycle.
//
// When the server accepts an open, it arms a single-shot timer keyed on the
// channel id. Every voucher / commit / topUp Touch resets the timer. When the
// timer fires, the closeOnIdle handler is invoked with the channel id so the
// server can run its close-and-settle path without waiting for a client close
// action.
//
// The idle-close watchdog mirrors the TypeScript-only extension in
// typescript/packages/mpp/src/server/session/lifecycle.ts; the rust
// SessionServer has no equivalent and host integrations there drive close
// explicitly.

import (
	"sync"
	"time"
)

// SessionLifecycle is the idle-close watchdog. Touch resets the per-channel
// timer, RemoveChannel cancels it, and Shutdown cancels everything.
type SessionLifecycle struct {
	mu          sync.Mutex
	timers      map[string]*time.Timer
	closeDelay  time.Duration
	closeOnIdle func(channelID string)
	shutdown    bool
}

// NewSessionLifecycle creates an idle-close watchdog. closeDelay <= 0
// disables the timer entirely (all operations become no-ops), the right
// default for tests and for callers that drive close explicitly.
//
// closeOnIdle is invoked with the channel id when a timer fires. Errors
// during idle close have no synchronous caller to report to; the handler is
// expected to log internally.
func NewSessionLifecycle(closeOnIdle func(channelID string), closeDelay time.Duration) *SessionLifecycle {
	return &SessionLifecycle{
		timers:      map[string]*time.Timer{},
		closeDelay:  closeDelay,
		closeOnIdle: closeOnIdle,
	}
}

// Touch resets the idle timer for channelID. No-op when the close delay is
// disabled or the lifecycle is shut down.
func (l *SessionLifecycle) Touch(channelID string) {
	if l.closeDelay <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.shutdown {
		return
	}
	l.cancelLocked(channelID)
	l.timers[channelID] = time.AfterFunc(l.closeDelay, func() {
		l.mu.Lock()
		delete(l.timers, channelID)
		stopped := l.shutdown
		l.mu.Unlock()
		if stopped {
			return
		}
		l.closeOnIdle(channelID)
	})
}

// RemoveChannel cancels the idle timer for channelID.
func (l *SessionLifecycle) RemoveChannel(channelID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cancelLocked(channelID)
}

// Shutdown cancels every outstanding timer and disables future touches.
func (l *SessionLifecycle) Shutdown() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.shutdown = true
	for channelID, timer := range l.timers {
		timer.Stop()
		delete(l.timers, channelID)
	}
}

// cancelLocked stops and forgets the timer for channelID. Callers hold l.mu.
func (l *SessionLifecycle) cancelLocked(channelID string) {
	if timer, ok := l.timers[channelID]; ok {
		timer.Stop()
		delete(l.timers, channelID)
	}
}
