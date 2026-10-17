package storage

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/obscure"
	"golang.org/x/net/webdav"
)

const webdavSpace = "fedcba9876543210fedcba9876543210"
const davPassword = "fictional-webdav-\"\\中文-password"

type davFixture struct {
	mu                                 sync.Mutex
	server                             *httptest.Server
	root, ca                           string
	puts, gets, deletes, preconditions int
	connections                        int
	rejectPut, truncateGet, blockGet   bool
}

func startDAV(t *testing.T) *davFixture {
	t.Helper()
	fixture := &davFixture{root: t.TempDir()}
	dav := &webdav.Handler{FileSystem: webdav.Dir(fixture.root), LockSystem: webdav.NewMemLS()}
	fixture.server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, p, ok := r.BasicAuth()
		if !ok || u != "fixture" || p != davPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
			http.Error(w, "unauthorized", 401)
			return
		}
		fixture.mu.Lock()
		if r.Method == "PUT" {
			fixture.puts++
			if r.Header.Get("If-None-Match") == "*" {
				fixture.preconditions++
			}
		}
		if r.Method == "GET" {
			fixture.gets++
		}
		if r.Method == "DELETE" {
			fixture.deletes++
		}
		reject, truncate, block := fixture.rejectPut, fixture.truncateGet, fixture.blockGet
		fixture.mu.Unlock()
		if r.Method == "PUT" && reject {
			http.Error(w, "fixture storage unavailable", 507)
			return
		}
		if r.Method == "GET" && block {
			<-r.Context().Done()
			return
		}
		if r.Method == "GET" && truncate {
			w.Header().Set("Content-Length", "112")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("short"))
			return
		}
		dav.ServeHTTP(w, r)
	}))
	fixture.server.Config.ErrorLog = log.New(io.Discard, "", 0)
	fixture.server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			fixture.mu.Lock()
			fixture.connections++
			fixture.mu.Unlock()
		}
	}
	fixture.server.StartTLS()
	t.Cleanup(fixture.server.Close)
	fixture.ca = filepath.Join(t.TempDir(), "ca.pem")
	need(t, os.WriteFile(fixture.ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: fixture.server.Certificate().Raw}), 0600))
	return fixture
}
func (f *davFixture) config(t *testing.T) ProviderConfig {
	t.Helper()
	pass, err := obscure.Obscure(davPassword)
	need(t, err)
	return ProviderConfig{Provider: "webdav", Root: "pico-fido2", CACertFile: f.ca,
		Options: map[string]string{"url": f.server.URL, "vendor": "other", "user": "fixture", "pass": pass}}
}
func davObjects(t *testing.T, fixture *davFixture) *RcloneObjects {
	t.Helper()
	remote, err := NewRcloneObjects(context.Background(), fixture.config(t), webdavSpace, nil)
	need(t, err)
	t.Cleanup(remote.Close)
	return remote
}
func (f *davFixture) file(name string) string {
	return filepath.Join(f.root, "pico-fido2", webdavSpace, "objects", name)
}

func TestRcloneWebDAVTLSRoundTripAndExclusion(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	fixture := startDAV(t)
	remote := davObjects(t, fixture)
	cfg := newConfig(t)
	server := start(t, cfg)
	t.Cleanup(server.Close)
	a, b := client(t, cfg), client(t, cfg)
	first := acquire(t, ctx, a, remote, webdavSpace, true)
	need(t, first.Commit(ctx, blob(7), 0))
	if fixture.puts != 1 || fixture.gets != 1 || fixture.preconditions != 1 {
		t.Fatal("missing provider upload/readback/create precondition")
	}
	if _, err := Acquire(ctx, b, remote, webdavSpace, false); err == nil {
		t.Fatal("second client opened active provider")
	}
	firstName := first.current.Object
	if err := remote.PutNew(ctx, firstName, blob(8)); !errors.Is(err, ErrExists) {
		t.Fatal("provider overwrote existing object")
	}
	if fixture.puts != 1 {
		t.Fatal("collision reached provider write")
	}
	need(t, first.Close())
	remote.Close()
	// New backend instance and a separate etcd client must obtain data from cloud.
	remote = davObjects(t, fixture)
	second := acquire(t, ctx, b, remote, webdavSpace, false)
	got, generation, err := second.Read(ctx)
	need(t, err)
	if generation != 1 || !bytes.Equal(got, blob(7)) {
		t.Fatal("reopened wrong cloud data")
	}
	need(t, second.Commit(ctx, blob(9), 1))
	old, err := os.ReadFile(fixture.file(firstName))
	need(t, err)
	if !bytes.Equal(old, blob(7)) || fixture.deletes != 0 {
		t.Fatal("new generation mutated previous snapshot")
	}
	need(t, second.Close())
}

func TestRcloneFailuresNeverPublish(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	fixture := startDAV(t)
	remote := davObjects(t, fixture)
	cfg := newConfig(t)
	server := start(t, cfg)
	t.Cleanup(server.Close)
	c := client(t, cfg)
	initial := acquire(t, ctx, c, remote, webdavSpace, true)
	need(t, initial.Commit(ctx, blob(1), 0))
	oldName := initial.current.Object
	need(t, initial.Close())
	remote.Close()
	for _, mode := range []string{"upload", "readback"} {
		remote = davObjects(t, fixture)
		locked := acquire(t, ctx, c, remote, webdavSpace, false)
		fixture.mu.Lock()
		fixture.rejectPut, fixture.truncateGet = mode == "upload", mode == "readback"
		fixture.mu.Unlock()
		if locked.Commit(ctx, blob(2), 1) == nil {
			t.Fatal("failed provider write published head")
		}
		fixture.mu.Lock()
		fixture.rejectPut, fixture.truncateGet = false, false
		fixture.mu.Unlock()
		if locked.Check(ctx) == nil {
			t.Fatal("failed writer resumed")
		}
		need(t, locked.Close())
		remote.Close()
		remote = davObjects(t, fixture)
		reopened := acquire(t, ctx, c, remote, webdavSpace, false)
		got, generation, err := reopened.Read(ctx)
		need(t, err)
		if generation != 1 || !bytes.Equal(got, blob(1)) {
			t.Fatal("provider failure changed authoritative state")
		}
		need(t, reopened.Close())
		remote.Close()
	}
	remote = davObjects(t, fixture)
	reopened := acquire(t, ctx, c, remote, webdavSpace, false)
	need(t, os.Remove(fixture.file(oldName)))
	if _, _, err := reopened.Read(ctx); err == nil {
		t.Fatal("deleted cloud object became local or empty data")
	}
}

func TestRcloneTrustBoundsCancellationAndOptions(t *testing.T) {
	fixture := startDAV(t)
	config := fixture.config(t)
	ctx := context.Background()
	for _, provider := range []string{"drive", "onedrive", "webdav"} {
		if _, err := fs.Find(provider); err != nil {
			t.Fatal("required rclone provider not linked")
		}
	}
	bad := config
	bad.CACertFile = ""
	remote, err := NewRcloneObjects(ctx, bad, webdavSpace, nil)
	if err == nil {
		defer remote.Close()
		if remote.PutNew(ctx, strings.Repeat("a", 64), blob(1)) == nil {
			t.Fatal("untrusted TLS certificate accepted")
		}
	}
	bad = config
	bad.Options = maps.Clone(config.Options)
	bad.Options["pass"], err = obscure.Obscure("wrong-fixture-password")
	need(t, err)
	remote, err = NewRcloneObjects(ctx, bad, webdavSpace, nil)
	if err == nil {
		defer remote.Close()
		if remote.PutNew(ctx, strings.Repeat("b", 64), blob(1)) == nil {
			t.Fatal("unauthenticated WebDAV accepted")
		}
	}
	for _, key := range []string{"bearer_token_command", "unix_socket", "auth_redirect", "url vendor", "no_check_certificate"} {
		bad = config
		bad.Options = maps.Clone(config.Options)
		bad.Options[key] = "not-executed"
		if ValidateProviderConfig(bad) == nil {
			t.Fatalf("unsafe option accepted: %s", key)
		}
	}
	for _, root := range []string{"../vault", "/vault", "vault/../other", `C:\vault`, "vault//other", ""} {
		bad = config
		bad.Root = root
		if ValidateProviderConfig(bad) == nil {
			t.Fatal("invalid root accepted")
		}
	}
	for _, address := range []string{"http://127.0.0.1", "https://user:pass@example.invalid", "https://example.invalid?token=secret", "https://example.invalid/#fragment"} {
		bad = config
		bad.Options = maps.Clone(config.Options)
		bad.Options["url"] = address
		if ValidateProviderConfig(bad) == nil {
			t.Fatal("unsafe endpoint accepted")
		}
	}
	remote = davObjects(t, fixture)
	name := strings.Repeat("c", 64)
	need(t, remote.PutNew(ctx, name, blob(3)))
	fixture.mu.Lock()
	fixture.blockGet = true
	fixture.mu.Unlock()
	short, end := context.WithTimeout(ctx, 150*time.Millisecond)
	defer end()
	before := time.Now()
	if _, err := remote.Get(short, name); err == nil || time.Since(before) > 3*time.Second {
		t.Fatal("cancellation did not stop cloud read")
	}
	fixture.mu.Lock()
	fixture.blockGet = false
	fixture.mu.Unlock()
	if _, err := remote.Get(ctx, name); err == nil {
		t.Fatal("canceled provider automatically resumed")
	}
	remote = davObjects(t, fixture)
	file, err := os.OpenFile(fixture.file(name), os.O_RDWR, 0600)
	need(t, err)
	need(t, file.Truncate(MaxBlob+1))
	need(t, file.Close())
	if _, err := remote.Get(ctx, name); err == nil {
		t.Fatal("oversized cloud object read")
	}
	if _, err := remote.Get(ctx, "../escape"); err == nil {
		t.Fatal("path traversal accepted")
	}
}

func TestAuditCancellationDoesNotPoisonForeground(t *testing.T) {
	fixture := startDAV(t)
	remote := davObjects(t, fixture)
	name := strings.Repeat("d", 64)
	need(t, remote.PutNew(context.Background(), name, blob(3)))
	fixture.mu.Lock()
	fixture.blockGet = true
	fixture.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	if _, err := remote.GetForAudit(ctx, name); err == nil {
		t.Fatal("blocked audit unexpectedly succeeded")
	}
	fixture.mu.Lock()
	fixture.blockGet = false
	fixture.mu.Unlock()
	data, err := remote.Get(context.Background(), name)
	need(t, err)
	if !bytes.Equal(data, blob(3)) {
		t.Fatal("canceled audit corrupted foreground backend")
	}
}

func TestOAuthRefreshPersistenceFailsClosed(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var saved map[string]string
	mapper := &providerMap{values: map[string]string{"token": "old"}, defaults: map[string]string{"unused": "default"}, cancel: cancel,
		save: func(next map[string]string) error { saved = maps.Clone(next); return nil }}
	mapper.Set("token", "new")
	if got, _ := mapper.Get("token"); got != "new" || saved["token"] != "new" || len(saved) != 1 || mapper.check() != nil {
		t.Fatal("token refresh not saved")
	}
	mapper.save = func(map[string]string) error { return errors.New("injected disk failure") }
	mapper.Set("token", "unsaved")
	if got, _ := mapper.Get("token"); got != "new" || mapper.check() == nil || ctx.Err() == nil {
		t.Fatal("failed token persistence did not cancel")
	}
	mapper.Set("token", "later")
	if got, _ := mapper.Get("token"); got != "new" {
		t.Fatal("faulted token store resumed")
	}
}

type afterUpload struct {
	Objects
	hook func()
}

func (o *afterUpload) PutNew(ctx context.Context, name string, data []byte) error {
	if err := o.Objects.PutNew(ctx, name, data); err != nil {
		return err
	}
	if o.hook != nil {
		o.hook()
	}
	return nil
}

func TestStaleWriterWithRealWebDAV(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fixture := startDAV(t)
	oldRemote, newRemote := davObjects(t, fixture), davObjects(t, fixture)
	cfg := newConfig(t)
	server := start(t, cfg)
	t.Cleanup(server.Close)
	a, b := client(t, cfg), client(t, cfg)
	objects := &afterUpload{Objects: oldRemote}
	old := acquire(t, ctx, a, objects, webdavSpace, true)
	need(t, old.Commit(ctx, blob(1), 0))
	var successor *Locked
	objects.hook = func() {
		// Keep the old session alive but remove its authority after a real upload.
		// A successor uploads, verifies and publishes before the old commit resumes.
		_, err := b.Delete(ctx, old.mutex.Key())
		need(t, err)
		successor = acquire(t, ctx, b, newRemote, webdavSpace, false)
		need(t, successor.Commit(ctx, blob(3), 1))
	}
	if err := old.Commit(ctx, blob(2), 1); !errors.Is(err, ErrLost) {
		t.Fatalf("stale real-cloud writer accepted: %v", err)
	}
	got, generation, err := successor.Read(ctx)
	need(t, err)
	if generation != 2 || !bytes.Equal(got, blob(3)) {
		t.Fatal("stale upload replaced real-cloud head")
	}
	need(t, old.Close())
	need(t, successor.Check(ctx))
}
