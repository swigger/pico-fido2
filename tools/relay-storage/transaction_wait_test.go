package storage

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A real embedded coordinator: no production endpoint/profile or credentials.
func TestTransactionWaitAndCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cfg := newConfig(t)
	server := start(t, cfg)
	defer server.Close()
	a, b := client(t, cfg), client(t, cfg)
	objects := &memoryObjects{data: make(map[string][]byte)}
	const ns = "1123456789abcdef0123456789abcdef"
	owner := acquire(t, ctx, a, objects, ns, true)
	need(t, owner.Commit(ctx, blob(1), 0))
	short, stop := context.WithTimeout(ctx, 180*time.Millisecond)
	defer stop()
	started := time.Now()
	canceled, err := acquireLocked(short, b, objects, ns, OpenExisting, nil, false, true)
	if canceled != nil {
		canceled.Close()
		t.Fatal("canceled waiter acquired a lease")
	}
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(started) > 2*time.Second {
		t.Fatalf("lock cancellation was not bounded: %v", err)
	}
	need(t, owner.Check(ctx)) // Canceled waiter cannot revoke the owner's lease.
	type result struct {
		held *Locked
		err  error
	}
	acquired := make(chan result, 1)
	go func() {
		held, err := acquireLocked(ctx, b, objects, ns, OpenExisting, nil, false, true)
		acquired <- result{held, err}
	}()
	select {
	case got := <-acquired:
		if got.held != nil {
			got.held.Close()
		}
		t.Fatalf("waiter did not wait for owner: %v", got.err)
	case <-time.After(250 * time.Millisecond):
	}
	need(t, owner.Commit(ctx, blob(2), 1))
	need(t, owner.Close())
	select {
	case got := <-acquired:
		need(t, got.err)
		defer got.held.Close()
		bytes, generation, err := got.held.Read(ctx)
		need(t, err)
		if generation != 2 || bytes[len(bytes)-1] != 2 {
			t.Fatal("waiter received a stale snapshot")
		}
		need(t, got.held.Commit(ctx, blob(3), 2))
	case <-time.After(3 * time.Second):
		t.Fatal("waiter failed to acquire released lease")
	}
}
