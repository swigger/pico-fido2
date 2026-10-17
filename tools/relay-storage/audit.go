package storage

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrAudit means a completed read disagreed with the exact committed object.
// Network errors/cancellation leave the object unverified and are retried idle.
var ErrAudit = errors.New("committed cloud snapshot failed background verification")

type snapshotAuditor struct {
	mu      sync.Mutex
	get     func(context.Context, string) ([]byte, error)
	pending *head
	cancel  context.CancelFunc
	done    chan struct{}
	failed  chan struct{}
	faulted bool
}

func newSnapshotAuditor(get func(context.Context, string) ([]byte, error)) *snapshotAuditor {
	return &snapshotAuditor{get: get, failed: make(chan struct{})}
}

// Only the newest queued snapshot is necessary: newer snapshots contain the
// entire vault. In-flight reads always compare their own immutable object/hash.
func (a *snapshotAuditor) enqueue(h head) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.pending = &h
}

func (a *snapshotAuditor) pause() error {
	a.mu.Lock()
	cancel, done := a.cancel, a.done
	a.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cancel, a.done = nil, nil
	if a.faulted {
		return ErrAudit
	}
	return nil
}

func (a *snapshotAuditor) resume(parent context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cancel != nil || a.pending == nil || a.faulted {
		return
	}
	ctx, cancel := context.WithCancel(parent)
	a.cancel, a.done = cancel, make(chan struct{})
	go a.run(ctx, a.done)
}

func (a *snapshotAuditor) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	// Let the release acknowledgement and CTAP response leave first.
	delay := 250 * time.Millisecond
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		a.mu.Lock()
		if a.pending == nil {
			a.mu.Unlock()
			return
		}
		h := *a.pending
		a.mu.Unlock()
		readCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		data, err := a.get(readCtx, h.Object)
		cancel()
		corrupt := errors.Is(err, ErrAudit) || (err == nil && (len(data) != h.Length || digest(data) != h.SHA256))
		clear(data)
		a.mu.Lock()
		if corrupt {
			a.faulted = true
			close(a.failed)
		} else if err == nil && a.pending != nil && a.pending.Object == h.Object {
			a.pending = nil
		}
		a.mu.Unlock()
		if corrupt || ctx.Err() != nil {
			return
		}
		delay = 5 * time.Second
	}
}
