//go:build unix

package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func withProfileKey(t *testing.T, source func(bool) ([]byte, error)) {
	t.Helper()
	previous := profileKeySource
	profileKeySource = source
	t.Cleanup(func() { profileKeySource = previous })
}

func TestSealedProfileFormatAndPermissions(t *testing.T) {
	config := profileFixture(t)
	dir := filepath.Join(t.TempDir(), "private", "cloud")
	path := filepath.Join(dir, config.Namespace+profileExtension)
	need(t, CreateProfile(path, config))
	sealed, err := os.ReadFile(path)
	need(t, err)
	if !bytes.HasPrefix(sealed, sealMagic) || len(sealed) < len(sealMagic)+sealNonceSize+sealTagSize+len(profileMagic) {
		t.Fatal("sealed profile format")
	}
	for name, want := range map[string]os.FileMode{dir: 0700, path: 0600, path + ".lock": 0600} {
		info, err := os.Lstat(name)
		need(t, err)
		if info.Mode().Perm()&^want != 0 {
			t.Fatalf("%s permissions %v exceed %v", filepath.Base(name), info.Mode().Perm(), want)
		}
	}
	// The namespace is authenticated: the same bytes never open as another namespace.
	if _, err := unprotectProfile(sealed, "00000000000000000000000000000001"); err == nil {
		t.Fatal("sealed profile opened under another namespace")
	}
	tampered := bytes.Clone(sealed)
	tampered[len(sealMagic)] ^= 1 // Nonce.
	if _, err := unprotectProfile(tampered, config.Namespace); err == nil {
		t.Fatal("tampered nonce accepted")
	}
	tampered = bytes.Clone(sealed)
	tampered[3] ^= 1 // Magic.
	if _, err := unprotectProfile(tampered, config.Namespace); err == nil {
		t.Fatal("unknown format accepted")
	}
	// Two seals of the same profile never reuse a nonce.
	again, err := profileCipher(config)
	need(t, err)
	if bytes.Equal(again[:len(sealMagic)+sealNonceSize], sealed[:len(sealMagic)+sealNonceSize]) {
		t.Fatal("nonce reused")
	}
}

func TestSealedProfileKeyFailsClosed(t *testing.T) {
	config := profileFixture(t)
	path := filepath.Join(t.TempDir(), "profile"+profileExtension)
	need(t, CreateProfile(path, config))
	withProfileKey(t, func(bool) ([]byte, error) { return bytes.Repeat([]byte{7}, 32), nil })
	if p, err := OpenProfile(path, config.Namespace); err == nil {
		p.Close()
		t.Fatal("profile opened with another user's key")
	}
	var creates []bool
	withProfileKey(t, func(create bool) ([]byte, error) {
		creates = append(creates, create)
		return nil, errors.New("fictional keyring unavailable")
	})
	if p, err := OpenProfile(path, config.Namespace); err == nil {
		p.Close()
		t.Fatal("profile opened without keyring")
	}
	other := filepath.Join(t.TempDir(), "never"+profileExtension)
	if CreateProfile(other, config) == nil {
		t.Fatal("profile created without keyring")
	}
	for _, name := range []string{other, other + ".lock"} {
		if _, err := os.Lstat(name); !os.IsNotExist(err) {
			t.Fatal("keyring failure left profile state")
		}
	}
	if len(creates) != 2 || creates[0] || !creates[1] {
		t.Fatalf("key creation allowed on read or refused on create: %v", creates)
	}
	withProfileKey(t, func(bool) ([]byte, error) { return make([]byte, 16), nil })
	if CreateProfile(other, config) == nil {
		t.Fatal("short profile key accepted")
	}
}

func TestSealedProfileRefusesSymlinks(t *testing.T) {
	config := profileFixture(t)
	dir := t.TempDir()
	real := filepath.Join(dir, "real"+profileExtension)
	need(t, CreateProfile(real, config))
	link := filepath.Join(dir, "link"+profileExtension)
	need(t, os.Symlink(real, link))
	need(t, os.Symlink(real+".lock", link+".lock"))
	if p, err := OpenProfile(link, config.Namespace); err == nil {
		p.Close()
		t.Fatal("symlinked profile or marker followed")
	}
	if CreateProfile(link, config) == nil {
		t.Fatal("profile created through symlink")
	}
	// A symlinked marker alone is refused too, even when its target is valid.
	mixed := filepath.Join(dir, "mixed"+profileExtension)
	data, err := os.ReadFile(real)
	need(t, err)
	need(t, os.WriteFile(mixed, data, 0600))
	need(t, os.Symlink(real+".lock", mixed+".lock"))
	if p, err := OpenProfile(mixed, config.Namespace); err == nil {
		p.Close()
		t.Fatal("symlinked marker followed")
	}
	if _, err := readProfileFile(link); err == nil {
		t.Fatal("symlinked profile read")
	}
}

func TestSealedProfileLockAndAtomicReplace(t *testing.T) {
	config := profileFixture(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "profile"+profileExtension)
	need(t, CreateProfile(path, config))
	profile, err := OpenProfile(path, config.Namespace)
	need(t, err)
	if _, err := openProfileLock(path, false); err == nil {
		t.Fatal("flock not exclusive")
	}
	before, err := os.Stat(path)
	need(t, err)
	next := mapsClone(config.Provider.Options)
	next["token"] = `{"access_token":"rotated-fixture"}`
	need(t, profile.SaveTokens(next))
	after, err := os.Stat(path)
	need(t, err)
	if os.SameFile(before, after) {
		t.Fatal("profile rewritten in place instead of renamed")
	}
	if after.Mode().Perm() != 0600 {
		t.Fatal("replacement permissions")
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".pico-cloud-*.tmp"))
	need(t, err)
	if len(leftovers) != 0 {
		t.Fatal("temporary profile left behind")
	}
	profile.Close()
	lock, err := openProfileLock(path, false)
	need(t, err) // Close released the flock.
	lock.close()

	// First publication never replaces an existing destination.
	original, err := os.ReadFile(path)
	need(t, err)
	if writeProfile(path, []byte("replacement"), true) == nil {
		t.Fatal("initial publish replaced an existing profile")
	}
	current, err := os.ReadFile(path)
	need(t, err)
	if !bytes.Equal(current, original) {
		t.Fatal("refused publish changed the profile")
	}
}

func TestSealedProfileFailedReplaceUnix(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not restrict root")
	}
	config := profileFixture(t)
	dir := filepath.Join(t.TempDir(), "cloud")
	path := filepath.Join(dir, "profile"+profileExtension)
	need(t, CreateProfile(path, config))
	original, err := os.ReadFile(path)
	need(t, err)
	profile, err := OpenProfile(path, config.Namespace)
	need(t, err)
	defer profile.Close()
	need(t, os.Chmod(dir, 0500)) // No temporary file or rename is possible.
	t.Cleanup(func() { os.Chmod(dir, 0700) })
	next := mapsClone(config.Provider.Options)
	next["token"] = `{"access_token":"not-saved"}`
	if profile.SaveTokens(next) == nil {
		t.Fatal("failed profile replacement reported success")
	}
	need(t, os.Chmod(dir, 0700))
	if _, err := profile.Config(); err == nil {
		t.Fatal("faulted profile resumed")
	}
	if profile.SaveTokens(next) == nil {
		t.Fatal("faulted profile retried write")
	}
	profile.Close()
	after, err := os.ReadFile(path)
	need(t, err)
	if !bytes.Equal(original, after) {
		t.Fatal("failed replacement damaged original")
	}
}

func TestDefaultProfilePathUnix(t *testing.T) {
	namespace := webdavSpace
	t.Setenv("HOME", "/home/fixture")
	t.Setenv("XDG_DATA_HOME", "/data/fixture")
	got, err := DefaultProfilePath(namespace)
	need(t, err)
	want := "/data/fixture/PicoFido2Remote/safe-end/cloud/" + namespace + ".sealed"
	if runtime.GOOS == "darwin" {
		want = "/home/fixture/Library/Application Support/PicoFido2Remote/safe-end/cloud/" + namespace + ".sealed"
	}
	if got != want {
		t.Fatalf("default profile path %q, want %q", got, want)
	}
	if runtime.GOOS != "darwin" {
		t.Setenv("XDG_DATA_HOME", "relative/data") // Non-absolute values are ignored per XDG.
		got, err = DefaultProfilePath(namespace)
		need(t, err)
		if got != "/home/fixture/.local/share/PicoFido2Remote/safe-end/cloud/"+namespace+".sealed" {
			t.Fatalf("relative XDG_DATA_HOME used: %q", got)
		}
	}
	t.Setenv("HOME", "relative")
	if _, err := DefaultProfilePath(namespace); err == nil {
		t.Fatal("relative HOME accepted")
	}
	if _, err := DefaultProfilePath("not-a-namespace"); err == nil {
		t.Fatal("invalid namespace accepted")
	}
}
