//go:build unix

package storage

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/zalando/go-keyring"
	"golang.org/x/sys/unix"
)

// Unix profiles are sealed with AES-256-GCM under one random per-user key kept
// in the OS keyring (macOS Keychain or a Secret Service such as GNOME Keyring /
// KWallet). File format: "PF2CLS01" | nonce[12] | ciphertext | tag[16]. The magic
// and the profile namespace are authenticated as associated data, so a sealed
// profile cannot be moved to another namespace. There is no plaintext fallback:
// without a keyring every profile operation fails closed.
const profileExtension = ".sealed"

const (
	profileKeyService = "PicoFido2Remote-storage"
	profileKeyAccount = "profile-key-v1"
	sealNonceSize     = 12
	sealTagSize       = 16
)

var sealMagic = []byte("PF2CLS01")

// profileKeySource returns the 32-byte profile key. create permits generating
// and storing a new key when none exists; reads never create one. Tests replace
// it so unit tests do not depend on a running keyring.
var profileKeySource = keyringProfileKey

var profileKeyMu sync.Mutex

func cloudProfileDirectory() (string, error) {
	home := os.Getenv("HOME")
	if home == "" || !filepath.IsAbs(home) {
		return "", errors.New("cannot find local profile directory")
	}
	var base string
	if runtime.GOOS == "darwin" {
		base = filepath.Join(home, "Library", "Application Support")
	} else if data := os.Getenv("XDG_DATA_HOME"); data != "" && filepath.IsAbs(data) {
		base = data
	} else {
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "PicoFido2Remote", "safe-end", "cloud"), nil
}

func decodeProfileKey(text string) ([]byte, error) {
	if len(text) != 64 {
		return nil, errors.New("invalid profile key in keyring")
	}
	key, err := hex.DecodeString(text)
	if err != nil {
		return nil, errors.New("invalid profile key in keyring")
	}
	return key, nil
}

// keyringProfileKey reads the key, or under an exclusive per-user file lock
// generates, stores and reads it back. The lock stops two first-time helpers
// from each storing a different key and sealing a profile with the loser's.
func keyringProfileKey(create bool) ([]byte, error) {
	profileKeyMu.Lock()
	defer profileKeyMu.Unlock()
	unavailable := errors.New("OS keyring unavailable; cloud profile cannot be protected or unlocked")
	text, err := keyring.Get(profileKeyService, profileKeyAccount)
	if err == nil {
		return decodeProfileKey(text)
	}
	if !errors.Is(err, keyring.ErrNotFound) {
		return nil, unavailable
	}
	if !create {
		return nil, errors.New("cloud profile key missing from OS keyring")
	}
	dir, err := cloudProfileDirectory()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, errors.New("cannot create local profile directory")
	}
	lock, err := os.OpenFile(filepath.Join(dir, ".profile-key.lock"), os.O_RDWR|os.O_CREATE|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errors.New("cannot lock profile key creation")
	}
	defer lock.Close()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return nil, errors.New("cannot lock profile key creation")
	}
	if text, err = keyring.Get(profileKeyService, profileKeyAccount); err == nil {
		return decodeProfileKey(text)
	} else if !errors.Is(err, keyring.ErrNotFound) {
		return nil, unavailable
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	encoded := hex.EncodeToString(key)
	if err := keyring.Set(profileKeyService, profileKeyAccount, encoded); err != nil {
		clear(key)
		return nil, unavailable
	}
	back, err := keyring.Get(profileKeyService, profileKeyAccount)
	if err != nil || back != encoded {
		clear(key)
		return nil, unavailable
	}
	return key, nil
}

func profileAEAD(create bool) (cipher.AEAD, error) {
	key, err := profileKeySource(create)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	if len(key) != 32 {
		return nil, errors.New("invalid profile key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func sealAAD(namespace string) []byte { return append(bytes.Clone(sealMagic), namespace...) }

func protectProfile(plain []byte, namespace string) ([]byte, error) {
	if len(plain) == 0 || len(plain)+len(sealMagic)+sealNonceSize+sealTagSize > profileLimit || !namespacePattern.MatchString(namespace) {
		return nil, errors.New("invalid protected profile size")
	}
	aead, err := profileAEAD(true)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(sealMagic)+sealNonceSize, len(sealMagic)+sealNonceSize+len(plain)+sealTagSize)
	copy(out, sealMagic)
	if _, err := rand.Read(out[len(sealMagic):]); err != nil {
		return nil, err
	}
	return aead.Seal(out, out[len(sealMagic):], plain, sealAAD(namespace)), nil
}
func unprotectProfile(sealed []byte, namespace string) ([]byte, error) {
	if len(sealed) < len(sealMagic)+sealNonceSize+sealTagSize || len(sealed) > profileLimit ||
		!bytes.HasPrefix(sealed, sealMagic) || !namespacePattern.MatchString(namespace) {
		return nil, errors.New("unsupported cloud profile format")
	}
	aead, err := profileAEAD(false)
	if err != nil {
		return nil, err
	}
	nonce := sealed[len(sealMagic) : len(sealMagic)+sealNonceSize]
	plain, err := aead.Open(nil, nonce, sealed[len(sealMagic)+sealNonceSize:], sealAAD(namespace))
	if err != nil {
		return nil, errors.New("cannot unlock cloud profile for this user")
	}
	return plain, nil
}

func openProfileForRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

func syncDirectory(dir string) error {
	d, err := os.OpenFile(dir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// publishProfile moves a flushed temporary file into place. The first publication
// uses link(), which fails if the destination exists; replacement uses rename().
// The parent directory is flushed so the new name is durable.
func publishProfile(temp, path string, initial bool) error {
	if err := os.Chmod(temp, 0600); err != nil {
		return err
	}
	if initial {
		if err := os.Link(temp, path); err != nil {
			return err
		}
	} else if err := os.Rename(temp, path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

// profileLock holds flock(LOCK_EX) on the persistent marker for its lifetime.
// Locks are per open file description and fail immediately rather than wait.
type profileLock struct{ f *os.File }

func openProfileLock(path string, initial bool) (*profileLock, error) {
	name := path + ".lock"
	flags := os.O_RDWR | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if initial {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(name, flags, 0600)
	if err != nil {
		if initial && errors.Is(err, os.ErrExist) {
			return nil, errProfileLockExists
		}
		return nil, errors.New("cloud profile uninitialized, already initialized or in use")
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		f.Close()
		return nil, errors.New("cloud profile uninitialized, already initialized or in use")
	}
	return &profileLock{f: f}, nil
}
func (l *profileLock) writeMarker(marker []byte) error {
	if n, err := l.f.WriteAt(marker, 0); err != nil || n != len(marker) {
		return errors.New("cannot initialize cloud profile marker")
	}
	if l.f.Sync() != nil || syncDirectory(filepath.Dir(l.f.Name())) != nil {
		return errors.New("cannot flush cloud profile marker")
	}
	return nil
}

// readMarker returns at most one byte more than a valid marker so callers can
// reject trailing data with an exact comparison.
func (l *profileLock) readMarker() ([]byte, error) {
	marker := make([]byte, len(profileMarkerMagic)+32+1)
	n, err := l.f.ReadAt(marker, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return marker[:n], nil
}
func (l *profileLock) close() {
	if l.f != nil {
		l.f.Close() // Closing the only descriptor releases the flock.
		l.f = nil
	}
}
