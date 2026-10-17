package storage

import (
	"encoding/binary"
	"errors"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

func TestCoordinatorHelperLifecycle(t *testing.T) {
	f := newSecureCoordinatorFixture(t)
	ctx, setup, ca, client, prefix := f.ctx, f.config, f.ca, f.client, f.prefix
	objects := &memoryObjects{data: make(map[string][]byte)}
	fixture := startDAV(t)
	testProfileSetup(t, setup, fixture)
	testOAuthEnrollmentProtocol(t, setup)
	profilePath := filepath.Join(t.TempDir(), "cloud-profile.dpapi")
	need(t, CreateProfile(profilePath, CloudProfile{Version: 1, Namespace: webdavSpace, Coordinator: setup, Provider: fixture.config(t)}))
	missing := startHelperProcess(t, profilePath, webdavSpace)
	if got := missing.request(t, PipeOpen, []byte{0}); len(got) != 1 || got[0] != 1 {
		t.Fatal("missing vault opened")
	}
	select {
	case err := <-missing.done:
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 {
			t.Fatalf("failed acquisition panicked or reported corruption: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("failed acquisition leaked helper")
	}
	helper := startHelperProcess(t, profilePath, webdavSpace)
	if got := helper.request(t, PipeOpen, []byte{1}); len(got) != 9 || got[0] != 0 {
		t.Fatal("real helper initialization")
	}
	if got := helper.request(t, PipeCommit, append(make([]byte, 8), blob(4)...)); len(got) != 9 || got[0] != 0 || binary.LittleEndian.Uint64(got[1:]) != 1 {
		t.Fatal("real helper cloud commit")
	}
	fixture.mu.Lock()
	connections := fixture.connections
	fixture.mu.Unlock()
	if helper.request(t, PipeRelease, nil)[0] != 0 {
		t.Fatal("release")
	}
	ownersAfterRelease, err := client.Get(ctx, prefix+"lock/", clientv3.WithPrefix())
	need(t, err)
	if len(ownersAfterRelease.Kvs) != 0 {
		t.Fatal("idle helper held distributed mutex")
	}
	if helper.request(t, PipeWake, nil)[0] != 0 || helper.request(t, PipeOpen, []byte{0})[0] != 0 {
		t.Fatal("retained helper reopen")
	}
	fixture.mu.Lock()
	reused := fixture.connections == connections
	fixture.mu.Unlock()
	if !reused {
		t.Fatal("second transaction rebuilt the TLS connection pool")
	}
	if got := helper.request(t, PipeClose, nil); len(got) != 1 || got[0] != 0 {
		t.Fatal("real helper close")
	}
	helper.finish(t, true)
	testProfileMaintenance(t, setup, fixture, profilePath, ca)
	helper = startHelperProcess(t, profilePath, webdavSpace)
	if got := helper.request(t, PipeOpen, []byte{0}); len(got) != 121 || got[0] != 0 || got[len(got)-1] != 4 {
		t.Fatal("new helper did not reopen durable cloud state")
	}
	owners, err := client.Get(ctx, prefix+"lock/", clientv3.WithPrefix())
	need(t, err)
	if len(owners.Kvs) != 1 {
		t.Fatal("helper did not hold one lease-backed mutex")
	}
	leaseID := clientv3.LeaseID(owners.Kvs[0].Lease)
	need(t, helper.kill()) // Simulated crash: no clean Close/Unlock executes in the helper.
	helper.finish(t, false)
	profile, err := OpenProfile(profilePath, webdavSpace)
	need(t, err)
	profile.Close()
	if held, err := Acquire(ctx, client, objects, webdavSpace, false); !errors.Is(err, concurrency.ErrLocked) {
		if held != nil {
			held.Close()
		}
		t.Fatalf("crashed writer's lease disappeared without expiry: %v", err)
	}
	expiry := time.Now().Add(22 * time.Second)
	for {
		ttl, err := client.TimeToLive(ctx, leaseID)
		need(t, err)
		if ttl.TTL < 0 {
			break
		}
		if time.Now().After(expiry) {
			t.Fatal("crashed helper lease failed to expire")
		}
		time.Sleep(200 * time.Millisecond)
	}
	remote := davObjects(t, fixture)
	recovered := acquire(t, ctx, client, remote, webdavSpace, false)
	data, generation, err := recovered.Read(ctx)
	need(t, err)
	if generation != 1 || len(data) != 112 || data[len(data)-1] != 4 {
		t.Fatal("helper crash lost committed cloud state")
	}
	need(t, recovered.Close())
}
