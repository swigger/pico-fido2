package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rclone/rclone/fs/config/obscure"
)

func testProfileSetup(t *testing.T, coordinator CoordinatorConfig, dav *davFixture) {
	t.Helper()
	config := CloudProfile{Version: 1, Namespace: webdavSpace, Coordinator: coordinator, Provider: dav.config(t)}
	config.Coordinator.ClusterID = "" // First contact pins the verified TLS/RBAC cluster.
	delete(config.Provider.Options, "pass")
	request := ProfileSetup{Profile: config, WebDAVPassword: davPassword}
	encoded, err := json.Marshal(request)
	need(t, err)
	path := filepath.Join(t.TempDir(), "setup.dpapi")
	helper := startHelperProcess(t, path, webdavSpace, "--setup-pipe")
	if response := helper.request(t, PipeProfile, encoded); !bytes.Equal(response, []byte{0}) {
		t.Fatal("profile setup failed")
	}
	helper.finish(t, true)
	profile, err := OpenProfile(path, webdavSpace)
	need(t, err)
	saved, err := profile.Config()
	need(t, err)
	profile.Close()
	password, err := obscure.Reveal(saved.Provider.Options["pass"])
	need(t, err)
	if password != davPassword || saved.Coordinator.ClusterID != coordinator.ClusterID {
		t.Fatal("setup secret or cluster identity mismatch")
	}
	cipher, err := os.ReadFile(path)
	need(t, err)
	for _, secret := range []string{davPassword, "PRIVATE KEY", coordinator.Endpoints[0]} {
		if bytes.Contains(cipher, []byte(secret)) {
			t.Fatal("setup secret stored in plaintext")
		}
	}
	// Setup never overwrites an existing profile, even if its data is valid.
	if SaveProfileSetup(context.Background(), path, webdavSpace, encoded) == nil {
		t.Fatal("setup overwrote protected profile")
	}
	after, err := os.ReadFile(path)
	need(t, err)
	if !bytes.Equal(cipher, after) {
		t.Fatal("failed setup changed existing profile")
	}
	request.Profile.Coordinator.ClusterID = "0000000000000001"
	wrong, err := json.Marshal(request)
	need(t, err)
	badPath := filepath.Join(t.TempDir(), "wrong.dpapi")
	if SaveProfileSetup(context.Background(), badPath, webdavSpace, wrong) == nil {
		t.Fatal("wrong cluster accepted")
	}
	if _, err := os.Stat(badPath); !os.IsNotExist(err) {
		t.Fatal("wrong cluster created profile")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if SaveProfileSetup(ctx, badPath, webdavSpace, encoded) == nil {
		t.Fatal("canceled setup created profile")
	}
}

func TestProfileSetupRejectsMalformedAndSeparateProtocol(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.dpapi")
	for _, data := range [][]byte{nil, []byte("{bad"), []byte(`{"unknown":"fictional-secret"}`), bytes.Repeat([]byte("x"), profileLimit+1)} {
		if SaveProfileSetup(context.Background(), path, webdavSpace, data) == nil {
			t.Fatal("malformed setup accepted")
		}
	}
	for _, op := range []byte{PipeProfile, PipeOpen, PipeOpenCached} {
		input, write := io.Pipe()
		read, output := io.Pipe()
		client := &pipeTestClient{input: write, output: read, done: make(chan error, 1), next: 1}
		go func() {
			client.done <- ServeProfileSetup(context.Background(), input, output, path, webdavSpace)
			input.Close()
			output.Close()
		}()
		if got := client.request(t, op, []byte(`{"fictional-secret":"must-not-be-echoed"}`)); !bytes.Equal(got, []byte{1}) {
			t.Fatal("setup error leaked payload or accepted wrong command")
		}
		client.finish(t, false)
		write.Close()
		read.Close()
	}
	header := requestBytes(PipeProfile, 1, nil)
	binary.LittleEndian.PutUint32(header[8:], profileLimit+1)
	if _, err := readFrameLimit(bytes.NewReader(header), 1, profileLimit); err == nil {
		t.Fatal("oversized setup accepted")
	}
	if err := ServeProfileSetup(context.Background(), bytes.NewReader(nil), io.Discard, path, webdavSpace); err == nil {
		t.Fatal("EOF setup accepted")
	}
	vault := startPipe(t, func(context.Context, OpenMode, []byte) (PipeSession, error) {
		t.Fatal("setup opened a vault session")
		return nil, nil
	})
	if got := vault.request(t, PipeProfile, []byte("{}")); !bytes.Equal(got, []byte{1}) {
		t.Fatal("vault child accepted profile setup")
	}
	vault.finish(t, false)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("invalid setup wrote a profile")
	}
}
