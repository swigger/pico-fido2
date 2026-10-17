package storage

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
	"go.etcd.io/etcd/server/v3/embed"
	"go.uber.org/zap"
)

type memoryObjects struct {
	mu                sync.Mutex
	data              map[string][]byte
	afterPut          func()
	putError, corrupt bool
	gets              int
}

func (m *memoryObjects) PutNew(ctx context.Context, name string, data []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	if m.putError {
		m.mu.Unlock()
		return errors.New("injected failed upload")
	}
	if _, found := m.data[name]; found {
		m.mu.Unlock()
		return ErrExists
	}
	m.data[name] = bytes.Clone(data)
	hook := m.afterPut
	m.mu.Unlock()
	if hook != nil {
		hook()
	}
	return nil
}
func (m *memoryObjects) Get(ctx context.Context, name string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.gets++
	data, found := m.data[name]
	if !found {
		return nil, errors.New("missing object")
	}
	copy := bytes.Clone(data)
	if m.corrupt {
		copy[len(copy)-1] ^= 1
	}
	return copy, nil
}
func blob(value byte) []byte { return append([]byte("PF2BAK01"), bytes.Repeat([]byte{value}, 104)...) }

type disposableMemory struct{ *memoryObjects }

func (m *disposableMemory) Close() {}

func TestCachedSnapshotRevalidatesHeadAndOwnership(t *testing.T) {
	ctx := context.Background()
	cfg := newConfig(t)
	server := start(t, cfg)
	t.Cleanup(server.Close)
	coordinator := client(t, cfg)
	objects := &memoryObjects{data: make(map[string][]byte)}
	namespace := "0123456789abcdef0123456789abcdef"
	first := acquire(t, ctx, coordinator, objects, namespace, true)
	need(t, first.Commit(ctx, blob(1), 0))
	need(t, first.Close())
	checksum, err := hex.DecodeString(digest(blob(1)))
	need(t, err)
	opens := 0
	deferred := &deferredObjects{open: func() (managedObjects, error) {
		opens++
		return &disposableMemory{objects}, nil
	}}
	defer deferred.Close()
	second := acquire(t, ctx, coordinator, deferred, namespace, false)
	before := objects.gets
	got, generation, err := second.ReadCached(ctx, 1, checksum)
	need(t, err)
	if len(got) != 0 || generation != 1 || objects.gets != before || opens != 0 {
		t.Fatal("matching authoritative snapshot was downloaded again")
	}
	need(t, second.Commit(ctx, blob(2), 1))
	if opens != 1 {
		t.Fatal("provider was not opened exactly once for commit/readback")
	}
	need(t, second.Close())
	third := acquire(t, ctx, coordinator, objects, namespace, false)
	got, generation, err = third.ReadCached(ctx, 1, checksum)
	need(t, err)
	if !bytes.Equal(got, blob(2)) || generation != 2 {
		t.Fatal("another client's commit was hidden by the cache")
	}
	// A matching generation alone must never authorize stale/different bytes.
	got, _, err = third.ReadCached(ctx, 2, checksum)
	need(t, err)
	if !bytes.Equal(got, blob(2)) {
		t.Fatal("mismatching ciphertext digest accepted")
	}
	checksum, err = hex.DecodeString(digest(blob(2)))
	need(t, err)
	_, err = coordinator.Revoke(ctx, third.session.Lease())
	need(t, err)
	if _, _, err := third.ReadCached(ctx, 2, checksum); err == nil {
		t.Fatal("cached snapshot bypassed lost ownership")
	}
	_ = third.Close()
}
func need(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func freeURL(t *testing.T) url.URL {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	need(t, err)
	address := listener.Addr().String()
	need(t, listener.Close())
	return url.URL{Scheme: "http", Host: address}
}
func newConfig(t *testing.T) *embed.Config {
	cfg := embed.NewConfig()
	cfg.Dir = t.TempDir()
	cfg.LogLevel = "error"
	cfg.ListenClientUrls = []url.URL{freeURL(t)}
	cfg.AdvertiseClientUrls = cfg.ListenClientUrls
	cfg.ListenPeerUrls = []url.URL{freeURL(t)}
	cfg.AdvertisePeerUrls = cfg.ListenPeerUrls
	cfg.InitialCluster = cfg.InitialClusterFromName(cfg.Name)
	return cfg
}
func start(t *testing.T, cfg *embed.Config) *embed.Etcd {
	t.Helper()
	server, err := embed.StartEtcd(cfg)
	need(t, err)
	select {
	case <-server.Server.ReadyNotify():
	case <-time.After(15 * time.Second):
		server.Close()
		t.Fatal("etcd readiness timeout")
	}
	return server
}
func client(t *testing.T, cfg *embed.Config) *clientv3.Client {
	t.Helper()
	c, err := clientv3.New(clientv3.Config{Endpoints: []string{cfg.AdvertiseClientUrls[0].String()}, DialTimeout: 3 * time.Second, Logger: zap.NewNop()})
	need(t, err)
	t.Cleanup(func() { c.Close() })
	return c
}
func acquire(t *testing.T, ctx context.Context, c *clientv3.Client, objects Objects, namespace string, initialize bool) *Locked {
	t.Helper()
	locked, err := Acquire(ctx, c, objects, namespace, initialize)
	need(t, err)
	t.Cleanup(func() { locked.Close() })
	return locked
}

func TestRealEtcdCoordination(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Second)
	defer cancel()
	cfg := newConfig(t)
	server := start(t, cfg)
	t.Cleanup(func() { server.Close() })
	a, b := client(t, cfg), client(t, cfg)
	objects := &memoryObjects{data: make(map[string][]byte)}
	const space = "0123456789abcdef0123456789abcdef"
	if _, err := Acquire(ctx, a, objects, space, false); !errors.Is(err, ErrMissing) {
		t.Fatalf("missing vault opened: %v", err)
	}
	first := acquire(t, ctx, a, objects, space, true)
	if _, err := Acquire(ctx, b, objects, space, false); !errors.Is(err, concurrency.ErrLocked) {
		t.Fatalf("second client acquired lock: %v", err)
	}
	if _, _, err := first.Read(ctx); !errors.Is(err, ErrMissing) {
		t.Fatal("uncommitted initial head was readable")
	}
	need(t, first.Commit(ctx, blob(1), 0))
	need(t, first.Close())
	if _, err := Acquire(ctx, a, objects, space, true); !errors.Is(err, ErrExists) {
		t.Fatal("initialized cloud vault reset")
	}
	second := acquire(t, ctx, b, objects, space, false)
	got, generation, err := second.Read(ctx)
	need(t, err)
	if generation != 1 || !bytes.Equal(got, blob(1)) {
		t.Fatal("read wrong committed object")
	}
	if second.Commit(ctx, blob(2), 0) == nil {
		t.Fatal("stale generation accepted")
	}
	need(t, second.Commit(ctx, blob(2), 1))
	need(t, second.Close())
	// A real etcd restart must preserve the authoritative head and initialization marker.
	server.Close()
	server = start(t, cfg)
	third := acquire(t, ctx, a, objects, space, false)
	got, generation, err = third.Read(ctx)
	need(t, err)
	if generation != 2 || !bytes.Equal(got, blob(2)) {
		t.Fatal("etcd restart lost committed head")
	}
	server.Close()
	outage, endOutage := context.WithTimeout(ctx, 250*time.Millisecond)
	if third.Check(outage) == nil {
		t.Fatal("coordinator outage allowed work")
	}
	endOutage()
	server = start(t, cfg)
	if third.Check(ctx) == nil {
		t.Fatal("old handle resumed after coordinator outage")
	}
	need(t, third.Close())
}

func TestStaleWriterCannotPublishAfterSuccessor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg := newConfig(t)
	server := start(t, cfg)
	t.Cleanup(server.Close)
	a, b := client(t, cfg), client(t, cfg)
	objects := &memoryObjects{data: make(map[string][]byte)}
	const space = "11111111111111111111111111111111"
	old := acquire(t, ctx, a, objects, space, true)
	need(t, old.Commit(ctx, blob(1), 0))
	var successor *Locked
	objects.afterPut = func() {
		objects.afterPut = nil
		// Remove ownership while keeping the old lease alive. This reproduces a
		// paused worker before local keepalive notices loss; only Txn fencing helps.
		_, err := b.Delete(ctx, old.mutex.Key())
		need(t, err)
		successor = acquire(t, ctx, b, objects, space, false)
		need(t, successor.Commit(ctx, blob(3), 1))
	}
	if err := old.Commit(ctx, blob(2), 1); !errors.Is(err, ErrLost) {
		t.Fatalf("stale writer published: %v", err)
	}
	if old.Check(ctx) == nil {
		t.Fatal("faulted writer resumed")
	}
	got, generation, err := successor.Read(ctx)
	need(t, err)
	if generation != 2 || !bytes.Equal(got, blob(3)) {
		t.Fatal("stale writer overwrote successor")
	}
	need(t, old.Close())
	need(t, successor.Check(ctx)) // Old close must not release the successor's lock.
	_, err = b.Revoke(ctx, successor.session.Lease())
	need(t, err)
	if successor.Check(ctx) == nil {
		t.Fatal("revoked lease remained authoritative")
	}
}

func TestFailedSyncAndMissingDataFailClosed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cfg := newConfig(t)
	server := start(t, cfg)
	t.Cleanup(server.Close)
	c := client(t, cfg)
	objects := &memoryObjects{data: make(map[string][]byte)}
	const space = "22222222222222222222222222222222"
	locked := acquire(t, ctx, c, objects, space, true)
	need(t, locked.Commit(ctx, blob(1), 0))
	need(t, locked.Close())
	for _, mode := range []string{"upload", "readback"} {
		locked = acquire(t, ctx, c, objects, space, false)
		objects.putError, objects.corrupt = mode == "upload", mode == "readback"
		if locked.Commit(ctx, blob(2), 1) == nil {
			t.Fatal("failed sync published")
		}
		objects.putError, objects.corrupt = false, false
		if locked.Check(ctx) == nil {
			t.Fatal("failed writer resumed without reopen")
		}
		need(t, locked.Close())
		locked = acquire(t, ctx, c, objects, space, false)
		got, generation, err := locked.Read(ctx)
		need(t, err)
		if generation != 1 || !bytes.Equal(got, blob(1)) {
			t.Fatal("failed sync changed head")
		}
		need(t, locked.Close())
	}
	locked = acquire(t, ctx, c, objects, space, false)
	objects.data[locked.current.Object][0] ^= 1
	if _, _, err := locked.Read(ctx); err == nil {
		t.Fatal("corrupt object returned")
	}
	need(t, locked.Close())
	_, err := c.Delete(ctx, locked.prefix+"/head")
	need(t, err)
	if _, err := Acquire(ctx, c, objects, space, false); !errors.Is(err, ErrMissing) {
		t.Fatal("missing head became empty vault")
	}
	if _, err := Acquire(ctx, c, objects, space, true); !errors.Is(err, ErrExists) {
		t.Fatal("missing head allowed reinitialization")
	}
	const incomplete = "33333333333333333333333333333333"
	locked = acquire(t, ctx, c, objects, incomplete, true)
	need(t, locked.Close())
	if _, err := Acquire(ctx, c, objects, incomplete, false); !errors.Is(err, ErrMissing) {
		t.Fatal("interrupted initialization reopened")
	}
	if _, err := Acquire(ctx, c, objects, incomplete, true); !errors.Is(err, ErrExists) {
		t.Fatal("interrupted initialization reset")
	}
}

func TestTransferTimeoutScaling(t *testing.T) {
	for _, c := range []struct {
		payload int
		want    time.Duration
	}{
		{0, 30 * time.Second},
		{64 * 1024, 31 * time.Second},
		{MaxBlob, 30*time.Second + time.Duration(MaxBlob)*time.Second/(64*1024)},
		{2 * MaxBlob, 30*time.Second + time.Duration(2*MaxBlob)*time.Second/(64*1024)},
		{1 << 40, 5 * time.Minute},
	} {
		if got := transferTimeout(c.payload); got != c.want || got > 5*time.Minute {
			t.Fatalf("transferTimeout(%d) = %v, want %v", c.payload, got, c.want)
		}
	}
}
