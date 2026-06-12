package server

// Per-channel idle-close lifecycle.
//
// When the server accepts an open, it arms a single-shot timer keyed on the
// channel id. Every voucher / commit / topUp Touch resets the timer. When the
// timer fires, the closeOnIdle handler is invoked with the channel id so the
// server can run its close-and-settle path without waiting for a client close
// action.
//
// The idle-close watchdog is an extension beyond the draft MPP spec;
// without it, hosts drive close explicitly.

import (
	"sync"
	"time"
)

// SessionLifecycle is the idle-close watchdog. Touch resets the per-channel
// timer, RemoveChannel cancels it, and Shutdown cancels everything.
type SessionLifecycle struct {
	// mu guards timers and shutdown.
	mu sync.Mutex

	// timers holds the armed single-shot idle timer per channel id.
	timers map[string]*time.Timer

	// closeDelay is the idle duration before a channel is auto-closed;
	// <= 0 disables the watchdog entirely.
	closeDelay time.Duration

	// closeOnIdle is invoked with the channel id when its idle timer fires.
	closeOnIdle func(channelID string)

	// shutdown, once true, turns every later Touch into a no-op and stops
	// already-fired timers from invoking closeOnIdle.
	shutdown bool
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
