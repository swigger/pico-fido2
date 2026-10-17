package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

func TestExplicitInitializationRecovery(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cfg := newConfig(t)
	server := start(t, cfg)
	t.Cleanup(server.Close)
	c := client(t, cfg)
	objects := &memoryObjects{data: make(map[string][]byte)}
	ns := "0123456789abcdef0123456789abcdef"
	prefix := "/pico-fido2/v1/" + ns
	token := bytes.Repeat([]byte{0x42}, 32)
	open := func(mode OpenMode, token []byte) *Locked {
		t.Helper()
		locked, err := AcquireWithToken(ctx, c, objects, ns, mode, token)
		need(t, err)
		return locked
	}
	locked := open(OpenNew, token)
	need(t, locked.Close())
	if _, err := Acquire(ctx, c, objects, ns, false); !errors.Is(err, ErrMissing) {
		t.Fatal("ordinary open recovered pending initialization")
	}
	if bad, err := AcquireWithToken(ctx, c, objects, ns, OpenResume, bytes.Repeat([]byte{0x43}, 32)); err == nil {
		bad.Close()
		t.Fatal("another creation intent took over pending initialization")
	}
	locked = open(OpenResume, token)
	if _, _, err := locked.Read(ctx); !errors.Is(err, ErrMissing) {
		t.Fatal("pending recovery exposed empty credential data")
	}
	need(t, locked.Commit(ctx, blob(7), 0))
	need(t, locked.Close())
	locked = open(OpenResume, token)
	data, generation, err := locked.Read(ctx)
	need(t, err)
	if generation != 1 || !bytes.Equal(data, blob(7)) {
		t.Fatal("resume did not return already committed snapshot")
	}
	need(t, locked.Close())
	if bad, err := AcquireWithToken(ctx, c, objects, ns, OpenResume, bytes.Repeat([]byte{0x43}, 32)); err == nil {
		bad.Close()
		t.Fatal("another creation intent adopted a published vault")
	}
	// Deleting the head must not turn a committed vault back into an empty seed.
	_, err = c.Delete(ctx, prefix+"/head")
	need(t, err)
	if bad, err := AcquireWithToken(ctx, c, objects, ns, OpenResume, token); !errors.Is(err, ErrMissing) {
		if bad != nil {
			bad.Close()
		}
		t.Fatalf("missing published head was reset: %v", err)
	}
	// Resume also handles a crash before the helper ever reserved its namespace.
	ns = "1123456789abcdef0123456789abcdef"
	prefix = "/pico-fido2/v1/" + ns
	locked = open(OpenResume, token)
	need(t, locked.Commit(ctx, blob(8), 0))
	need(t, locked.Close())
	// Simulate a pre-marker-format deployment with a complete head. Only that
	// intact state can be upgraded; a headless legacy marker cannot be recovered.
	_, err = c.Txn(ctx).Then(clientv3.OpPut(prefix+"/initialized", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"), clientv3.OpDelete(prefix+"/committed")).Commit()
	need(t, err)
	locked = open(OpenExisting, nil)
	need(t, locked.Check(ctx))
	need(t, locked.Close())
	mark, err := c.Get(ctx, prefix+"/committed")
	need(t, err)
	if len(mark.Kvs) != 1 || string(mark.Kvs[0].Value) != "1" {
		t.Fatal("legacy published vault not upgraded durably")
	}
	_, err = c.Delete(ctx, prefix+"/committed")
	need(t, err)
	if bad, err := Acquire(ctx, c, objects, ns, false); !errors.Is(err, ErrMissing) {
		if bad != nil {
			bad.Close()
		}
		t.Fatal("missing permanent commit marker accepted")
	}
}
