package storage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.etcd.io/etcd/client/pkg/v3/transport"
	clientv3 "go.etcd.io/etcd/client/v3"
	"go.uber.org/zap"
	"golang.org/x/sys/windows"
)

// Optional cross-language test: build RelayCloudTests with CMake and provide its
// absolute path. Every credential, provider and certificate here is disposable.
func TestNativeCloudVault(t *testing.T) {
	native := os.Getenv("PICO_FIDO_NATIVE_CLOUD_TEST")
	if native == "" {
		t.Skip("set PICO_FIDO_NATIVE_CLOUD_TEST to the built RelayCloudTests.exe")
	}
	if !filepath.IsAbs(native) {
		t.Fatal("native test executable must be an absolute path")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	dir, err := os.MkdirTemp("", "pf2-cloud-interop-")
	need(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	write := func(name, text string) string {
		path := filepath.Join(dir, name)
		need(t, os.WriteFile(path, []byte(text), 0600))
		return path
	}
	ca := authority(t)
	cert, key := ca.leaf(t, "fixture-server", true, false)
	cfg := newConfig(t)
	cfg.ListenClientUrls[0].Scheme = "https"
	cfg.AdvertiseClientUrls = cfg.ListenClientUrls
	cfg.ClientTLSInfo = transport.TLSInfo{CertFile: write("server.pem", cert), KeyFile: write("server.key", key),
		TrustedCAFile: write("ca.pem", ca.pem), ClientCertAuth: true}
	server := start(t, cfg)
	t.Cleanup(server.Close)
	rootCert, rootKey := ca.leaf(t, "root", false, false)
	setup := CoordinatorConfig{Endpoints: []string{cfg.AdvertiseClientUrls[0].String()}, CAPEM: ca.pem, ClientCertPEM: rootCert, ClientKeyPEM: rootKey}
	tlsConfig, err := coordinatorTLS(setup)
	need(t, err)
	admin, err := clientv3.New(clientv3.Config{Endpoints: setup.Endpoints, TLS: tlsConfig, Logger: zap.NewNop()})
	need(t, err)
	t.Cleanup(func() { admin.Close() })
	_, err = admin.UserAddWithOptions(ctx, "root", "", &clientv3.UserAddOptions{NoPassword: true})
	need(t, err)
	_, err = admin.UserGrantRole(ctx, "root", "root")
	need(t, err)
	_, err = admin.UserAddWithOptions(ctx, "fixture", "", &clientv3.UserAddOptions{NoPassword: true})
	need(t, err)
	_, err = admin.RoleAdd(ctx, "fixture-vault")
	need(t, err)
	prefix := "/pico-fido2/v1/" + webdavSpace + "/"
	_, err = admin.RoleGrantPermission(ctx, "fixture-vault", prefix, clientv3.GetPrefixRangeEnd(prefix), clientv3.PermissionType(clientv3.PermReadWrite))
	need(t, err)
	_, err = admin.UserGrantRole(ctx, "fixture", "fixture-vault")
	need(t, err)
	_, err = admin.AuthEnable(ctx)
	need(t, err)
	setup.ClientCertPEM, setup.ClientKeyPEM = ca.leaf(t, "fixture", false, false)
	setup.ClusterID, err = InspectCoordinator(ctx, setup)
	need(t, err)
	dav := startDAV(t)
	profile := filepath.Join(dir, "fictional cloud profile 中文.dpapi")
	write("client.pem", setup.ClientCertPEM)
	write("client.key", setup.ClientKeyPEM)
	davCA, err := os.ReadFile(dav.ca)
	need(t, err)
	write("dav-ca.pem", string(davCA))
	write("setup-input.txt", dav.server.URL+"\n"+setup.Endpoints[0]+"\n")
	helper := filepath.Join(dir, "PicoFidoStorage.exe")
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-o", helper, "./cmd/relay-storage-helper")
	build.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("helper build failed: %v\n%s", err, output)
	}
	commandNamespace := webdavSpace
	command := func(mode, archive string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, native, mode, commandNamespace, profile, helper, filepath.Join(dir, archive))
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
		return cmd
	}
	run := func(mode, archive string, success bool) {
		t.Helper()
		output, err := command(mode, archive).CombinedOutput()
		if (err == nil) != success {
			t.Fatalf("native operation %s: %v\n%s", mode, err, output)
		}
	}
	run("--real-setup", "setup-input.txt", true)
	webdavProfile := profile
	profile = filepath.Join(dir, "oauth-native-cancel.dpapi")
	run("--real-enroll-cancel", "setup-input.txt", true)
	if _, err := os.Stat(profile + ".lock"); !os.IsNotExist(err) {
		t.Fatal("native OAuth cancellation left a profile marker")
	}
	oauthExisting := oauthProfileFixture(t, "drive")
	oauthExisting.Coordinator = setup
	oauthExisting.Provider.Options["token"] = `{"access_token":"fictional-old","refresh_token":"fictional-refresh"}`
	need(t, CreateProfile(profile, oauthExisting))
	run("--real-maintain-cancel", "setup-input.txt", true)
	profile = webdavProfile
	run("--real-maintain-webdav", "setup-input.txt", true) // An unused namespace stays uninitialized.
	protected, err := OpenProfile(profile, webdavSpace)
	need(t, err)
	saved, err := protected.Config()
	need(t, err)
	protected.Close()
	if saved.Coordinator.ClusterID != setup.ClusterID {
		t.Fatal("native setup did not pin cluster identity")
	}
	if _, err := os.Stat(profile + ".selection"); !os.IsNotExist(err) {
		t.Fatal("profile setup selected or opened credential backend")
	}
	decrypt := func(encrypted []byte) []byte {
		t.Helper()
		if len(encrypted) < 112 || string(encrypted[:8]) != "PF2BAK01" || binary.LittleEndian.Uint32(encrypted[8:12]) != 600000 ||
			int(binary.LittleEndian.Uint32(encrypted[56:60])) != len(encrypted)-76 {
			t.Fatal("native envelope invalid")
		}
		derived, err := pbkdf2.Key(sha256.New, "synthetic-cloud-password-中文", encrypted[12:44], 600000, 32)
		need(t, err)
		defer clear(derived)
		block, err := aes.NewCipher(derived)
		need(t, err)
		gcm, err := cipher.NewGCM(block)
		need(t, err)
		plain, err := gcm.Open(nil, encrypted[44:56], encrypted[60:], encrypted[:60])
		need(t, err)
		return plain
	}
	snapshot := func(archive string, generation uint64) []byte {
		t.Helper()
		response, err := admin.Get(ctx, prefix+"head")
		need(t, err)
		if len(response.Kvs) != 1 {
			t.Fatal("native commit missing authoritative head")
		}
		head, err := decodeHead(response.Kvs[0].Value)
		need(t, err)
		cloud, err := os.ReadFile(dav.file(head.Object))
		need(t, err)
		plain := decrypt(cloud)
		defer clear(plain)
		backup, err := os.ReadFile(filepath.Join(dir, archive))
		need(t, err)
		backupPlain := decrypt(backup)
		defer clear(backupPlain)
		if !bytes.Equal(plain, backupPlain) || head.Generation != generation || string(plain[:8]) != "PF2VLT02" ||
			hex.EncodeToString(plain[8:24]) != webdavSpace || binary.LittleEndian.Uint64(plain[24:32]) != generation ||
			binary.LittleEndian.Uint32(plain[32:36]) != 1 {
			t.Fatal("native committed payload differs from authenticated backup")
		}
		return cloud
	}
	run("--real-init", "registered.pf2bak", true)
	snapshot("registered.pf2bak", 2)
	run("--real-open", "asserted.pf2bak", true)
	before := snapshot("asserted.pf2bak", 3)
	run("--real-maintain-webdav", "setup-input.txt", true)
	run("--real-maintain-coordinator", "setup-input.txt", true)
	if after := snapshot("asserted.pf2bak", 3); !bytes.Equal(after, before) {
		t.Fatal("native profile maintenance modified vault ciphertext")
	}
	// Failure after native approval must not acknowledge a signature or move head.
	dav.mu.Lock()
	dav.rejectPut = true
	dav.mu.Unlock()
	run("--real-failure", "unused.pf2bak", true)
	if !bytes.Equal(snapshot("asserted.pf2bak", 3), before) {
		t.Fatal("failed PUT changed committed snapshot")
	}
	dav.mu.Lock()
	dav.rejectPut = false
	dav.mu.Unlock()
	// The faulted parent may terminate its owned helper before clean lease release.
	// A successor must wait for the real lease, never force-unlock an old owner.
	until := time.Now().Add(22 * time.Second)
	for {
		owners, err := admin.Get(ctx, prefix+"lock/", clientv3.WithPrefix())
		need(t, err)
		if len(owners.Kvs) == 0 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("failed native helper ownership did not expire")
		}
		time.Sleep(200 * time.Millisecond)
	}
	// Approval holds no cloud lease. A competing writer may hold the lock
	// when approval completes; the actual native helper must wait and reacquire.
	cmd := command("--real-wait", "waited.pf2bak")
	input, err := cmd.StdinPipe()
	need(t, err)
	output, err := cmd.StdoutPipe()
	need(t, err)
	need(t, cmd.Start())
	defer func() {
		input.Close()
		output.Close()
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill() // Only this test's owned native process.
			_ = cmd.Wait()
		}
	}()
	scanner := bufio.NewScanner(output)
	if !scanner.Scan() || scanner.Text() != "APPROVAL" {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("native approval did not start")
	}
	owners, err := admin.Get(ctx, prefix+"lock/", clientv3.WithPrefix())
	need(t, err)
	if len(owners.Kvs) != 0 {
		t.Fatal("native approval retained distributed ownership")
	}
	competitor := acquire(t, ctx, admin, davObjects(t, dav), webdavSpace, false)
	_, err = fmt.Fprintln(input, "continue")
	need(t, err)
	input.Close()
	time.Sleep(250 * time.Millisecond)
	need(t, competitor.Check(ctx))
	need(t, competitor.Close())
	if !scanner.Scan() || scanner.Text() != "native cloud vault ok" {
		t.Fatal("native writer did not resume after lock contention")
	}
	need(t, cmd.Wait())
	snapshot("waited.pf2bak", 4)
	// Production selection/migration API: fail the first seed upload after the
	// local source is durably retired, then explicitly recover through new processes.
	originalProfile := profile
	profile = filepath.Join(dir, "migration-profile.dpapi")
	localOutput, err := command("--real-local", "local-before.pf2bak").CombinedOutput()
	if err != nil {
		t.Fatalf("native local seed: %v\n%s", err, localOutput)
	}
	commandNamespace = strings.TrimSpace(string(localOutput))
	if !namespacePattern.MatchString(commandNamespace) {
		t.Fatal("native source identity missing")
	}
	movePrefix := "/pico-fido2/v1/" + commandNamespace + "/"
	_, err = admin.RoleGrantPermission(ctx, "fixture-vault", movePrefix, clientv3.GetPrefixRangeEnd(movePrefix), clientv3.PermissionType(clientv3.PermReadWrite))
	need(t, err)
	need(t, CreateProfile(profile, CloudProfile{Version: 1, Namespace: commandNamespace, Coordinator: setup, Provider: dav.config(t)}))
	dav.mu.Lock()
	dav.rejectPut = true
	dav.mu.Unlock()
	run("--real-migrate-failure", "unused.pf2bak", true)
	dav.mu.Lock()
	dav.rejectPut = false
	dav.mu.Unlock()
	until = time.Now().Add(22 * time.Second)
	for {
		owners, err := admin.Get(ctx, movePrefix+"lock/", clientv3.WithPrefix())
		need(t, err)
		if len(owners.Kvs) == 0 {
			break
		}
		if time.Now().After(until) {
			t.Fatal("failed migration helper lease did not expire")
		}
		time.Sleep(200 * time.Millisecond)
	}
	run("--real-resume", "local-after.pf2bak", true)
	beforeMove, err := os.ReadFile(filepath.Join(dir, "local-before.pf2bak"))
	need(t, err)
	afterMove, err := os.ReadFile(filepath.Join(dir, "local-after.pf2bak"))
	need(t, err)
	beforePlain, afterPlain := decrypt(beforeMove), decrypt(afterMove)
	defer clear(beforePlain)
	defer clear(afterPlain)
	if !bytes.Equal(beforePlain, afterPlain) || binary.LittleEndian.Uint64(afterPlain[24:32]) != 3 {
		t.Fatal("native migration altered the saved vault")
	}
	moveHead, err := admin.Get(ctx, movePrefix+"head")
	need(t, err)
	if len(moveHead.Kvs) != 1 {
		t.Fatal("recovered migration did not publish head")
	}
	migrated, err := decodeHead(moveHead.Kvs[0].Value)
	need(t, err)
	if migrated.Generation != 1 {
		t.Fatal("cloud head generation confused with vault revision")
	}
	cloudMove, err := os.ReadFile(filepath.Join(dav.root, "pico-fido2", commandNamespace, "objects", migrated.Object))
	need(t, err)
	cloudPlain := decrypt(cloudMove)
	defer clear(cloudPlain)
	if !bytes.Equal(cloudPlain, beforePlain) {
		t.Fatal("recovered cloud object differs from original local credentials")
	}
	profile, commandNamespace = originalProfile, webdavSpace
	// A missing object must not open a local vault or initialize a new cloud head.
	response, err := admin.Get(ctx, prefix+"head")
	need(t, err)
	head, err := decodeHead(response.Kvs[0].Value)
	need(t, err)
	need(t, os.Remove(dav.file(head.Object)))
	run("--real-open", "missing.pf2bak", false)
}
