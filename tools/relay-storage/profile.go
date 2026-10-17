package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const profileLimit = 256 * 1024

var profileMagic = []byte("PF2CLD01")

// profileMarkerMagic prefixes the namespace in the persistent "<profile>.lock"
// marker. The marker is the OS lock target and survives interrupted creation.
const profileMarkerMagic = "PF2CLCK1"

var errProfileLockExists = errors.New("cloud profile marker already exists")

// CloudProfile stores provider credentials and coordinator enrollment only. Vault
// encryption passwords and credential private keys never belong in this profile.
type CloudProfile struct {
	Version     int               `json:"version"`
	Namespace   string            `json:"namespace"`
	Coordinator CoordinatorConfig `json:"coordinator"`
	Provider    ProviderConfig    `json:"provider"`
}

func (p CloudProfile) validate() error {
	return p.validateForMaintenance(false)
}
func (p CloudProfile) validateForMaintenance(maintenance bool) error {
	if p.Version != 1 || !namespacePattern.MatchString(p.Namespace) || !clusterPattern.MatchString(p.Coordinator.ClusterID) || p.Coordinator.ClusterID == "0000000000000000" {
		return errors.New("invalid cloud profile identity")
	}
	if _, err := coordinatorTLSForProfile(p.Coordinator, maintenance); err != nil {
		return err
	}
	return validateProviderConfig(p.Provider, !maintenance)
}

// DefaultProfilePath is <per-user data>/PicoFido2Remote/safe-end/cloud/<namespace>
// plus ".dpapi" (Windows DPAPI) or ".sealed" (keyring-sealed AES-GCM elsewhere).
func DefaultProfilePath(namespace string) (string, error) {
	if !namespacePattern.MatchString(namespace) {
		return "", errors.New("invalid vault namespace")
	}
	base, err := cloudProfileDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, namespace+profileExtension), nil
}

func profileMarker(namespace string) []byte { return []byte(profileMarkerMagic + namespace) }

func readProfileFile(path string) ([]byte, error) {
	f, err := openProfileForRead(path)
	if err != nil {
		return nil, errors.New("cloud profile missing or unreadable")
	}
	defer f.Close()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("invalid cloud profile file")
	}
	data, err := io.ReadAll(io.LimitReader(f, profileLimit+1))
	if err != nil || len(data) == 0 || len(data) > profileLimit {
		return nil, errors.New("invalid cloud profile file")
	}
	return data, nil
}
func profileCipher(p CloudProfile) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	text, err := json.Marshal(p)
	if err != nil {
		return nil, errors.New("cannot encode cloud profile")
	}
	defer clear(text)
	plain := append(bytes.Clone(profileMagic), text...)
	defer clear(plain)
	return protectProfile(plain, p.Namespace)
}
func parseProfile(cipher []byte, namespace string) (CloudProfile, error) {
	return parseProfileForMaintenance(cipher, namespace, false)
}
func parseProfileForMaintenance(cipher []byte, namespace string, maintenance bool) (CloudProfile, error) {
	var p CloudProfile
	plain, err := unprotectProfile(cipher, namespace)
	if err != nil {
		return p, err
	}
	defer clear(plain)
	if !bytes.HasPrefix(plain, profileMagic) {
		return p, errors.New("unsupported cloud profile format")
	}
	decoder := json.NewDecoder(bytes.NewReader(plain[len(profileMagic):]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return p, errors.New("invalid cloud profile data")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || p.Namespace != namespace {
		return CloudProfile{}, errors.New("cloud profile identity mismatch")
	}
	if err := p.validateForMaintenance(maintenance); err != nil {
		return CloudProfile{}, err
	}
	return p, nil
}

// writeProfile flushes a private temporary file in the destination directory and
// publishes it atomically. initial publication never replaces an existing file.
func writeProfile(path string, cipher []byte, initial bool) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pico-cloud-*.tmp")
	if err != nil {
		return errors.New("cannot create encrypted profile temporary file")
	}
	temp := f.Name()
	defer os.Remove(temp)
	if _, err = f.Write(cipher); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return errors.New("cannot flush encrypted cloud profile")
	}
	if err := publishProfile(temp, path, initial); err != nil {
		return errors.New("cannot replace encrypted cloud profile")
	}
	back, err := readProfileFile(path)
	if err != nil || !bytes.Equal(back, cipher) {
		return errors.New("cloud profile readback failed")
	}
	return nil
}

// profileCreatable reports whether CreateProfile could proceed: the profile file
// is absent and either no marker exists or only this namespace's exact marker
// remains from an interrupted creation. It takes no lock; CreateProfile rechecks.
func profileCreatable(path, namespace string) error {
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("cloud profile already exists or is inaccessible")
	}
	marker, err := os.Lstat(path + ".lock")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	expected := profileMarker(namespace)
	if err != nil || !marker.Mode().IsRegular() || marker.Size() != int64(len(expected)) {
		return errors.New("cloud profile marker invalid or in use")
	}
	if existing, err := os.ReadFile(path + ".lock"); err != nil || !bytes.Equal(existing, expected) {
		return errors.New("cloud profile marker invalid or in use")
	}
	return nil
}

// CreateProfile performs no remote access or backend selection. A persistent
// marker prevents interrupted creation from silently overwriting prior settings.
// If an earlier creation stopped after writing this namespace's exact marker but
// before publishing the profile, creation resumes under the same exclusive lock.
func CreateProfile(path string, p CloudProfile) error {
	cipher, err := profileCipher(p)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return errors.New("cloud profile already exists or is inaccessible")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	marker := profileMarker(p.Namespace)
	lock, err := openProfileLock(path, true)
	if errors.Is(err, errProfileLockExists) {
		// Interrupted creation: only the exact marker of this namespace, held
		// exclusively, with the profile still absent, may be completed.
		lock, err = openProfileLock(path, false)
		if err != nil {
			return err
		}
		defer lock.close()
		existing, readErr := lock.readMarker()
		if readErr != nil || !bytes.Equal(existing, marker) {
			return errors.New("cloud profile initialization marker invalid")
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("cloud profile already exists or is inaccessible")
		}
		return writeProfile(path, cipher, true)
	}
	if err != nil {
		return err
	}
	defer lock.close()
	if err := lock.writeMarker(marker); err != nil {
		return err
	}
	return writeProfile(path, cipher, true)
}

// Profile holds a local OS lock for the lifetime of a helper session. Its token
// callback saves under the same lock and detects unexpected file replacement.
type Profile struct {
	mu      sync.Mutex
	path    string
	lock    *profileLock
	saved   [32]byte
	value   CloudProfile
	faulted bool
}

func OpenProfile(path, namespace string) (*Profile, error) {
	return openProfileForMaintenance(path, namespace, false)
}
func openProfileForMaintenance(path, namespace string, maintenance bool) (*Profile, error) {
	if !namespacePattern.MatchString(namespace) {
		return nil, errors.New("invalid vault namespace")
	}
	lock, err := openProfileLock(path, false)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			lock.close()
		}
	}()
	marker, err := lock.readMarker()
	if err != nil || !bytes.Equal(marker, profileMarker(namespace)) {
		return nil, errors.New("cloud profile initialization marker invalid")
	}
	cipher, err := readProfileFile(path)
	if err != nil {
		return nil, err
	}
	value, err := parseProfileForMaintenance(cipher, namespace, maintenance)
	if err != nil {
		return nil, err
	}
	ok = true
	return &Profile{path: path, lock: lock, saved: sha256.Sum256(cipher), value: value}, nil
}
func (p *Profile) Config() (CloudProfile, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.faulted || p.lock == nil {
		return CloudProfile{}, errors.New("cloud profile unavailable")
	}
	copy := p.value
	copy.Provider.Options = mapsClone(p.value.Provider.Options)
	copy.Coordinator.Endpoints = append([]string(nil), p.value.Coordinator.Endpoints...)
	return copy, nil
}
func mapsClone(values map[string]string) map[string]string {
	copy := make(map[string]string, len(values))
	for k, v := range values {
		copy[k] = v
	}
	return copy
}
func (p *Profile) SaveTokens(options map[string]string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.faulted || p.lock == nil {
		return errors.New("cloud profile unavailable")
	}
	// OAuth refresh must never silently change provider/root/namespace/enrollment.
	if len(options) != len(p.value.Provider.Options) {
		return errors.New("unexpected cloud configuration change")
	}
	for k, v := range p.value.Provider.Options {
		if k != "token" && options[k] != v {
			return errors.New("unexpected cloud configuration change")
		}
	}
	next := p.value
	next.Provider.Options = mapsClone(options)
	return p.replaceLocked(next, nil)
}

// The caller must hold mu and, for explicit maintenance, an independently
// verified distributed ownership guard. Automatic token rotation remains narrow.
func (p *Profile) replaceLocked(next CloudProfile, check func() error) error {
	cipher, err := profileCipher(next)
	if err != nil {
		return err
	}
	p.faulted = true
	current, err := readProfileFile(p.path)
	if err != nil || sha256.Sum256(current) != p.saved {
		return errors.New("cloud profile changed while locked")
	}
	if check != nil {
		if err := check(); err != nil {
			return err
		}
	}
	if err := writeProfile(p.path, cipher, false); err != nil {
		return err
	}
	if check != nil {
		if err := check(); err != nil {
			return err // A durable write is never rolled back on later lease loss.
		}
	}
	p.saved = sha256.Sum256(cipher)
	p.value = next
	p.faulted = false
	return nil
}
func (p *Profile) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.faulted = true
	if p.lock != nil {
		p.lock.close()
		p.lock = nil
	}
	p.value = CloudProfile{}
}
