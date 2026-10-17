package storage

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"maps"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	_ "github.com/rclone/rclone/backend/drive"
	_ "github.com/rclone/rclone/backend/onedrive"
	_ "github.com/rclone/rclone/backend/webdav"
	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/fs/object"
)

var ErrProvider = errors.New("cloud provider operation failed")

// ProviderConfig contains rclone configuration values. Secrets must come from an
// explicitly unlocked local store; never print this structure or place it in argv.
// Root is relative to the selected remote. Namespace/objects is appended below it.
type ProviderConfig struct {
	Provider   string            `json:"provider"`
	Root       string            `json:"root"`
	Options    map[string]string `json:"options"`
	CACertFile string            `json:"ca_cert_file,omitempty"`
}

var optionAllow = map[string]string{
	"webdav":   "url vendor user pass bearer_token",
	"drive":    "client_id client_secret token scope root_folder_id team_drive",
	"onedrive": "client_id client_secret token drive_id drive_type region",
}
var rootPart = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]{0,63}$`)

// ValidateProviderConfig rejects command hooks, TLS bypasses, arbitrary API
// endpoints and other unreviewed rclone options before constructing any backend.
func ValidateProviderConfig(c ProviderConfig) error {
	return validateProviderConfig(c, true)
}
func validateProviderConfig(c ProviderConfig, checkCAFile bool) error {
	allowed, ok := optionAllow[c.Provider]
	if !ok || c.Root == "" || len(c.Root) > 240 || len(c.Options) > 12 {
		return errors.New("invalid cloud provider configuration")
	}
	for _, component := range strings.Split(c.Root, "/") {
		if !rootPart.MatchString(component) {
			return errors.New("invalid relative cloud root")
		}
	}
	for k, v := range c.Options {
		if !slices.Contains(strings.Fields(allowed), k) || len(v) > 16384 || strings.ContainsRune(v, 0) {
			return errors.New("unsupported cloud provider option")
		}
	}
	if c.Provider == "webdav" {
		u, err := url.Parse(c.Options["url"])
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
			return errors.New("WebDAV requires an HTTPS endpoint without embedded credentials or query")
		}
		switch c.Options["vendor"] {
		case "", "other", "nextcloud", "owncloud", "fastmail", "rclone":
		default:
			return errors.New("unsupported WebDAV vendor")
		}
		if c.Options["bearer_token"] != "" && (c.Options["user"] != "" || c.Options["pass"] != "") {
			return errors.New("ambiguous WebDAV authentication")
		}
	} else {
		if c.Options["token"] == "" {
			return errors.New("OAuth enrollment is required")
		}
		if c.Provider == "onedrive" {
			if c.Options["drive_id"] == "" || c.Options["drive_type"] == "" {
				return errors.New("OneDrive drive identity is required")
			}
			switch c.Options["region"] {
			case "", "global", "us", "de", "cn":
			default:
				return errors.New("unsupported OneDrive region")
			}
			switch c.Options["drive_type"] {
			case "personal", "business", "documentLibrary":
			default:
				return errors.New("unsupported OneDrive drive type")
			}
		}
	}
	if c.CACertFile != "" && checkCAFile {
		file, err := os.Open(c.CACertFile)
		if err != nil {
			return errors.New("cannot read provider CA file")
		}
		defer file.Close()
		pem, err := io.ReadAll(io.LimitReader(file, 65537))
		if err != nil || len(pem) > 65536 || !x509.NewCertPool().AppendCertsFromPEM(pem) {
			return errors.New("invalid provider CA file")
		}
	}
	return nil
}

// providerMap satisfies rclone's token storage contract. Set has no error return
// in the upstream interface, so persistence errors latch and cancel the backend.
// The caller must save atomically and durably; the callback receives only explicit
// configuration values, never the large set of upstream defaults.
type providerMap struct {
	mu               sync.Mutex
	values, defaults map[string]string
	save             func(map[string]string) error
	cancel           context.CancelFunc
	faulted          bool
}

func (m *providerMap) Get(key string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value, ok := m.values[key]
	if !ok {
		value, ok = m.defaults[key]
	}
	return value, ok
}
func (m *providerMap) Set(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.faulted {
		return
	}
	if key != "token" || m.save == nil || len(value) > 16384 {
		m.faulted = true
		m.cancel()
		return
	}
	next := maps.Clone(m.values)
	next[key] = value
	if err := m.save(next); err != nil {
		m.faulted = true
		m.cancel()
		return
	}
	m.values = next
}
func (m *providerMap) check() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.faulted {
		return errors.New("cloud authentication update could not be saved")
	}
	return nil
}

var _ configmap.Mapper = (*providerMap)(nil)

// RcloneObjects reuses only the three requested rclone backends. It never loads
// the user's default rclone config or environment options and never starts an RC
// server or subprocess. The owner context must outlive the object store.
type RcloneObjects struct {
	mu       sync.Mutex
	remote   fs.Fs
	provider string
	config   *providerMap
	ctx      context.Context
	cancel   context.CancelFunc
	faulted  bool
}

func NewRcloneObjects(owner context.Context, c ProviderConfig, namespace string, save func(map[string]string) error) (*RcloneObjects, error) {
	if err := ValidateProviderConfig(c); err != nil {
		return nil, err
	}
	if !namespacePattern.MatchString(namespace) {
		return nil, errors.New("invalid vault namespace")
	}
	if c.Provider != "webdav" && save == nil {
		return nil, errors.New("OAuth token persistence is required")
	}
	life, cancel := context.WithCancel(owner)
	ctx, ci := fs.AddConfig(life)
	ci.InsecureSkipVerify, ci.Dump, ci.NoConsole = false, 0, true
	ci.ConnectTimeout, ci.Timeout = fs.Duration(5*time.Second), fs.Duration(15*time.Second)
	ci.LowLevelRetries, ci.Retries, ci.Checkers, ci.Transfers = 1, 1, 1, 1
	ci.PasswordCommand, ci.Headers, ci.UploadHeaders, ci.DownloadHeaders = nil, nil, nil, nil
	ci.ClientCert, ci.ClientKey, ci.ClientPass, ci.HTTPProxy = "", "", "", ""
	ci.CaCert = nil
	if c.CACertFile != "" {
		ci.CaCert = []string{c.CACertFile}
	}
	registry, err := fs.Find(c.Provider)
	if err != nil {
		cancel()
		return nil, ErrProvider
	}
	mapper := &providerMap{values: maps.Clone(c.Options), defaults: make(map[string]string), save: save, cancel: cancel}
	for _, option := range registry.Options {
		mapper.defaults[option.Name] = option.String()
	}
	if c.Provider == "drive" {
		mapper.defaults["skip_gdocs"] = "true"
	}
	remote, err := registry.NewFs(ctx, "pico-fido2-cloud", path.Join(c.Root, namespace, "objects"), mapper)
	if err != nil || mapper.check() != nil || life.Err() != nil {
		cancel()
		return nil, ErrProvider
	}
	return &RcloneObjects{remote: remote, provider: c.Provider, config: mapper, ctx: ctx, cancel: cancel}, nil
}

// request bounds one provider operation by its payload (see transferTimeout).
func (r *RcloneObjects) request(parent context.Context, payload int) (context.Context, context.CancelFunc, error) {
	if r.faulted || r.ctx.Err() != nil || r.config.check() != nil {
		return nil, nil, ErrProvider
	}
	ctx, cancel := context.WithTimeout(fs.CopyConfig(parent, r.ctx), transferTimeout(payload))
	stop := context.AfterFunc(r.ctx, cancel)
	return ctx, func() { stop(); cancel() }, nil
}
func (r *RcloneObjects) fail() error { r.faulted = true; r.cancel(); return ErrProvider }
func (r *RcloneObjects) Close()      { r.mu.Lock(); defer r.mu.Unlock(); r.faulted = true; r.cancel() }

// PutNew checks for collisions before upload. WebDAV additionally receives the
// standard If-None-Match precondition. Other providers rely on coordinator-issued
// unpredictable 256-bit names: their APIs do not promise universal create-only CAS.
// Do not supply user-chosen names or reuse failed upload names.
// Upstream WebDAV may delete its own partial new upload on failure; it must never
// be given the name of an already published snapshot for writing.
func (r *RcloneObjects) PutNew(parent context.Context, name string, data []byte) error {
	_, err := r.PutNewVerified(parent, name, data)
	return err
}
func (r *RcloneObjects) PutNewVerified(parent context.Context, name string, data []byte) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !namePattern.MatchString(name) || len(data) < 112 || len(data) > MaxBlob {
		return false, errors.New("invalid cloud object")
	}
	ctx, cancel, err := r.request(parent, len(data))
	if err != nil {
		return false, err
	}
	defer cancel()
	_, err = r.remote.NewObject(ctx, name)
	if err == nil {
		return false, ErrExists
	}
	if !errors.Is(err, fs.ErrorObjectNotFound) {
		return false, r.fail()
	}
	info := object.NewStaticObjectInfo(name, time.Now(), int64(len(data)), true, nil, r.remote)
	var options []fs.OpenOption
	if r.provider == "webdav" {
		options = append(options, &fs.HTTPOption{Key: "If-None-Match", Value: "*"})
	}
	obj, err := r.remote.Put(ctx, bytes.NewReader(data), info, options...)
	if err != nil || r.config.check() != nil || ctx.Err() != nil {
		return false, r.fail()
	}
	verified, err := verifyUploadReceipt(ctx, obj, data)
	if err != nil {
		return false, r.fail()
	}
	return verified, nil
}

func verifyUploadReceipt(ctx context.Context, obj fs.Object, data []byte) (bool, error) {
	if obj == nil || obj.Size() != int64(len(data)) {
		return false, ErrProvider
	}
	// Prefer a cryptographic digest when offered. QuickXorHash remains useful
	// for accidental corruption; authenticated vault reads still check SHA-256.
	types := obj.Fs().Hashes().Array()
	slices.SortFunc(types, func(a, b hash.Type) int {
		rank := func(t hash.Type) int {
			if t == hash.SHA256 {
				return 0
			}
			if t == hash.SHA1 {
				return 1
			}
			if t == hash.MD5 {
				return 2
			}
			return 3
		}
		return rank(a) - rank(b)
	})
	for _, kind := range types {
		remote, err := obj.Hash(ctx, kind)
		if err != nil || remote == "" {
			continue
		}
		local, err := hash.NewMultiHasherTypes(hash.NewHashSet(kind))
		if err != nil {
			return false, err
		}
		if _, err = local.Write(data); err != nil {
			return false, err
		}
		if !strings.EqualFold(remote, local.Sums()[kind]) {
			return false, ErrProvider
		}
		return true, nil
	}
	return false, nil
}

func (r *RcloneObjects) Get(parent context.Context, name string) ([]byte, error) {
	return r.get(parent, name, false)
}

// A canceled/background read must not poison the shared foreground transport.
func (r *RcloneObjects) GetForAudit(parent context.Context, name string) ([]byte, error) {
	return r.get(parent, name, true)
}
func (r *RcloneObjects) get(parent context.Context, name string, audit bool) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !namePattern.MatchString(name) {
		return nil, errors.New("invalid cloud object name")
	}
	ctx, cancel, err := r.request(parent, MaxBlob) // Size is unknown until listed; the caller's context is tighter.
	if err != nil {
		return nil, err
	}
	defer cancel()
	fail := func() error {
		if audit {
			return ErrProvider
		}
		return r.fail()
	}
	obj, err := r.remote.NewObject(ctx, name)
	if err != nil || obj.Size() > MaxBlob || obj.Size() < 112 {
		if audit && err == nil {
			return nil, ErrAudit
		}
		return nil, fail()
	}
	stream, err := obj.Open(ctx)
	if err != nil {
		return nil, fail()
	}
	data, readErr := io.ReadAll(io.LimitReader(stream, MaxBlob+1))
	closeErr := stream.Close()
	if readErr != nil || closeErr != nil || int64(len(data)) != obj.Size() || len(data) > MaxBlob || r.config.check() != nil || ctx.Err() != nil {
		return nil, fail()
	}
	return data, nil
}
