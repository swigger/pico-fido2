package storage

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

func TestMaintenanceCannotInitializePublishOrRepairMissingHead(t *testing.T) {
	ctx := context.Background()
	cfg := newConfig(t)
	server := start(t, cfg)
	t.Cleanup(server.Close)
	client := client(t, cfg)
	objects := &memoryObjects{data: make(map[string][]byte)}
	prefix := "/pico-fido2/v1/" + webdavSpace
	assertState := func(marker, published string, heads int64) {
		t.Helper()
		for _, item := range []struct{ key, value string }{{"initialized", marker}, {"committed", published}} {
			got, err := client.Get(ctx, prefix+"/"+item.key)
			need(t, err)
			if item.value == "" {
				if len(got.Kvs) != 0 {
					t.Fatal("maintenance created a marker")
				}
			} else if len(got.Kvs) != 1 || string(got.Kvs[0].Value) != item.value {
				t.Fatal("maintenance changed a marker")
			}
		}
		got, err := client.Get(ctx, prefix+"/head")
		need(t, err)
		if got.Count != heads {
			t.Fatal("maintenance changed head existence")
		}
	}
	inspect := func() *Locked {
		t.Helper()
		locked, err := acquireForMaintenance(ctx, client, objects, webdavSpace)
		need(t, err)
		if locked.Commit(ctx, blob(9), 0) == nil {
			t.Fatal("maintenance published ciphertext")
		}
		need(t, locked.Check(ctx))
		if competing, err := Acquire(ctx, client, objects, webdavSpace, true); !errors.Is(err, concurrency.ErrLocked) {
			if competing != nil {
				competing.Close()
			}
			t.Fatal("maintenance did not exclude a writer")
		}
		return locked
	}
	locked := inspect()
	assertState("", "", 0)
	need(t, locked.Close())
	anchor := "v3:" + strings.Repeat("a", 64)
	_, err := client.Put(ctx, prefix+"/initialized", anchor)
	need(t, err)
	locked = inspect()
	assertState(anchor, "", 0)
	need(t, locked.Close())
	_, err = client.Put(ctx, prefix+"/committed", "1")
	need(t, err)
	if lost, err := acquireForMaintenance(ctx, client, objects, webdavSpace); err == nil {
		lost.Close()
		t.Fatal("missing published head accepted")
	}
	assertState(anchor, "1", 0)
	// A legacy published namespace is readable without implicitly upgrading it.
	legacy := strings.Repeat("b", 64)
	data, name := blob(3), strings.Repeat("c", 64)
	objects.data[name] = data
	encoded, err := json.Marshal(head{Version: 1, Generation: 1, Object: name, SHA256: digest(data), Length: len(data)})
	need(t, err)
	_, err = client.Txn(ctx).Then(clientv3.OpPut(prefix+"/initialized", legacy), clientv3.OpDelete(prefix+"/committed"), clientv3.OpPut(prefix+"/head", string(encoded))).Commit()
	need(t, err)
	locked = inspect()
	read, generation, err := locked.Read(ctx)
	need(t, err)
	if generation != 1 || string(read) != string(data) {
		t.Fatal("maintenance read changed the snapshot")
	}
	assertState(legacy, "", 1)
	_, err = client.Put(ctx, prefix+"/initialized", strings.Repeat("d", 64))
	need(t, err)
	if locked.Check(ctx) == nil {
		t.Fatal("maintenance ignored changed namespace identity")
	}
	need(t, locked.Close())
}
