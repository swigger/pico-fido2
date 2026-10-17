// Package storage coordinates immutable encrypted snapshots for the native vault's
// private-pipe backend. Cloud payloads contain no plaintext credentials.
package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

const MaxBlob = 8*1024*1024 + 76

var (
	ErrLost          = errors.New("storage ownership or snapshot changed; reopen required")
	ErrMissing       = errors.New("initialized cloud vault has no valid head; explicit recovery required")
	ErrExists        = errors.New("cloud vault already initialized")
	namePattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	namespacePattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
)

// Objects stores ciphertext only. PutNew must refuse an existing name. Get must
// limit its response to MaxBlob bytes. Backends must honor context cancellation.
// There is deliberately no delete, overwrite, merge, or fallback operation.
type Objects interface {
	PutNew(context.Context, string, []byte) error
	Get(context.Context, string) ([]byte, error)
}

// A verified upload receipt checks server-reported size and content checksum.
// Backends without such a receipt retain synchronous readback verification.
type verifiedObjects interface {
	PutNewVerified(context.Context, string, []byte) (bool, error)
}

type head struct {
	Version    int    `json:"version"`
	Generation uint64 `json:"generation"`
	Object     string `json:"object"`
	SHA256     string `json:"sha256"`
	Length     int    `json:"length"`
}

func decodeHead(data []byte) (head, error) {
	var h head
	if len(data) > 512 {
		return h, ErrMissing
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(&h); err != nil {
		return h, ErrMissing
	}
	var extra any
	if d.Decode(&extra) != io.EOF || h.Version != 1 || h.Generation == 0 || !namePattern.MatchString(h.Object) ||
		!namePattern.MatchString(h.SHA256) || h.Length < 112 || h.Length > MaxBlob {
		return h, ErrMissing
	}
	// Exact canonical encoding excludes duplicate fields and ambiguous encodings.
	canonical, _ := json.Marshal(h)
	if !bytes.Equal(canonical, data) {
		return h, ErrMissing
	}
	return h, nil
}

func randomName(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// Locked holds the upstream etcd mutex for its entire lifetime. Every observable
// read and committed head update also checks the mutex's creation revision inside
// a linearizable transaction. Lease expiry therefore fences paused writers even
// when their keepalive goroutine has not noticed the loss yet.
type Locked struct {
	mu                     sync.Mutex
	client                 *clientv3.Client
	session                *concurrency.Session
	mutex                  *concurrency.Mutex
	objects                Objects
	ctx                    context.Context
	cancel                 context.CancelFunc
	prefix, anchor         string
	revision               int64
	current                head
	faulted, closed, owned bool
	inspect, legacyState   bool
	audit                  func(head)
}

// Acquire fails immediately when another writer owns the namespace. initialize
// is an explicit operation: it reserves a permanent marker before uploading. If
// initialization is interrupted, reopening fails closed instead of creating empty
// storage. The caller owns client; closing Locked does not close the client.
func Acquire(ctx context.Context, client *clientv3.Client, objects Objects, namespace string, initialize bool) (*Locked, error) {
	mode := OpenExisting
	if initialize {
		mode = OpenNew
	}
	return AcquireMode(ctx, client, objects, namespace, mode)
}

type OpenMode byte

const (
	OpenExisting OpenMode = iota
	OpenNew
	OpenResume
)

// OpenResume requires the original creation token through AcquireWithToken. It may
// seed a never-committed v3 namespace or read that attempt's already committed head.
// It can never replace a missing published head or adopt another creation attempt.
func AcquireMode(ctx context.Context, client *clientv3.Client, objects Objects, namespace string, mode OpenMode) (*Locked, error) {
	return AcquireWithToken(ctx, client, objects, namespace, mode, nil)
}
func AcquireWithToken(ctx context.Context, client *clientv3.Client, objects Objects, namespace string, mode OpenMode, token []byte) (*Locked, error) {
	return acquireLocked(ctx, client, objects, namespace, mode, token, false, false)
}

// acquireForMaintenance can inspect an unused or never-published namespace but
// cannot initialize, upgrade, resume, or commit it. It holds the same upstream
// mutex as every vault user, including throughout protected profile replacement.
func acquireForMaintenance(ctx context.Context, client *clientv3.Client, objects Objects, namespace string) (*Locked, error) {
	return acquireLocked(ctx, client, objects, namespace, OpenExisting, nil, true, false)
}
func acquireLocked(ctx context.Context, client *clientv3.Client, objects Objects, namespace string, mode OpenMode, token []byte, inspect, wait bool) (*Locked, error) {
	if client == nil || objects == nil || !namespacePattern.MatchString(namespace) || mode > OpenResume ||
		(len(token) != 0 && len(token) != 32) || (mode == OpenExisting && len(token) != 0) || (mode == OpenResume && len(token) != 32) {
		return nil, errors.New("invalid storage configuration")
	}
	life, cancel := context.WithCancel(ctx)
	limit := 30 * time.Second
	if wait {
		limit = 90 * time.Second
	}
	acquireCtx, endAcquire := context.WithTimeout(ctx, limit)
	defer endAcquire()
	lease, err := client.Grant(acquireCtx, 15)
	if err != nil {
		cancel()
		return nil, err
	}
	s, err := concurrency.NewSession(client, concurrency.WithLease(lease.ID), concurrency.WithContext(life))
	if err != nil {
		cancel()
		return nil, err
	}
	l := &Locked{client: client, objects: objects, session: s, prefix: "/pico-fido2/v1/" + namespace, ctx: life, cancel: cancel, inspect: inspect}
	l.mutex = concurrency.NewMutex(s, l.prefix+"/lock")
	if wait {
		err = l.mutex.Lock(acquireCtx)
	} else {
		err = l.mutex.TryLock(acquireCtx)
	}
	if err != nil {
		l.Close()
		return nil, err
	}
	l.owned = true
	go func() {
		select {
		case <-s.Done():
			cancel()
		case <-life.Done():
		}
	}()
	ctx, finish := l.requestContext(ctx, 0)
	defer finish()
	resp, err := client.Txn(ctx).If(l.mutex.IsOwner()).Then(clientv3.OpGet(l.prefix+"/initialized"), clientv3.OpGet(l.prefix+"/head"), clientv3.OpGet(l.prefix+"/committed")).Commit()
	if err != nil || !resp.Succeeded {
		l.Close()
		return nil, errors.Join(ErrLost, err)
	}
	markers, heads := resp.Responses[0].GetResponseRange().Kvs, resp.Responses[1].GetResponseRange().Kvs
	committed := resp.Responses[2].GetResponseRange().Kvs
	if inspect && len(markers) == 0 && len(heads) == 0 && len(committed) == 0 {
		return l, nil // Absence stays absent; no initialization marker is written.
	}
	if mode == OpenNew || (mode == OpenResume && len(markers) == 0) {
		if len(markers) != 0 || len(heads) != 0 || len(committed) != 0 {
			l.Close()
			return nil, ErrExists
		}
		l.anchor, err = randomName(32)
		if err == nil {
			l.anchor = "v2:" + l.anchor
			if len(token) == 32 {
				l.anchor = "v3:" + digest(token)
			}
			var reserved *clientv3.TxnResponse
			reserved, err = client.Txn(ctx).If(l.mutex.IsOwner(), clientv3.Compare(clientv3.Version(l.prefix+"/initialized"), "=", 0),
				clientv3.Compare(clientv3.Version(l.prefix+"/head"), "=", 0), clientv3.Compare(clientv3.Version(l.prefix+"/committed"), "=", 0)).Then(clientv3.OpPut(l.prefix+"/initialized", l.anchor)).Commit()
			if err == nil && !reserved.Succeeded {
				err = ErrLost
			}
		}
		if err != nil {
			l.Close()
			return nil, err
		}
	} else {
		if len(markers) != 1 {
			l.Close()
			return nil, ErrMissing
		}
		l.anchor = string(markers[0].Value)
		modern := (strings.HasPrefix(l.anchor, "v2:") || strings.HasPrefix(l.anchor, "v3:")) && namePattern.MatchString(l.anchor[3:])
		legacy := namePattern.MatchString(l.anchor)
		if mode == OpenResume && l.anchor != "v3:"+digest(token) {
			l.Close()
			return nil, ErrExists
		}
		if (mode == OpenResume || inspect) && modern && len(heads) == 0 && len(committed) == 0 {
			return l, nil
		}
		if len(heads) != 1 || (!modern && !legacy) || (modern && (len(committed) != 1 || string(committed[0].Value) != "1")) ||
			(legacy && len(committed) != 0) {
			l.Close()
			return nil, ErrMissing
		}
		l.revision = heads[0].ModRevision
		l.current, err = decodeHead(heads[0].Value)
		if err != nil {
			l.Close()
			return nil, err
		}
		l.legacyState = legacy && inspect
		if legacy && !inspect {
			// Upgrade only with an intact published head, never guess whether a
			// legacy marker with no head was once committed.
			nextAnchor := "v2:" + l.anchor
			upgraded, updateErr := client.Txn(ctx).If(l.mutex.IsOwner(), clientv3.Compare(clientv3.Value(l.prefix+"/initialized"), "=", l.anchor),
				clientv3.Compare(clientv3.ModRevision(l.prefix+"/head"), "=", l.revision), clientv3.Compare(clientv3.Version(l.prefix+"/committed"), "=", 0)).
				Then(clientv3.OpPut(l.prefix+"/initialized", nextAnchor), clientv3.OpPut(l.prefix+"/committed", "1")).Commit()
			if updateErr != nil || !upgraded.Succeeded {
				l.Close()
				return nil, errors.Join(ErrLost, updateErr)
			}
			l.anchor = nextAnchor
		}
	}
	return l, nil
}

// transferTimeout bounds one storage request carrying payload bytes: a 30 s base
// plus 64 KiB/s, capped at 5 minutes (an 8 MiB commit needs ~286 s).
func transferTimeout(payload int) time.Duration {
	const base, rate, ceiling = 30 * time.Second, 64 * 1024, 5 * time.Minute
	if payload <= 0 {
		return base
	}
	if payload > int(ceiling/time.Second)*rate {
		return ceiling
	}
	return min(base+time.Duration(payload)*time.Second/rate, ceiling)
}

func (l *Locked) requestContext(parent context.Context, payload int) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(parent, transferTimeout(payload))
	stop := context.AfterFunc(l.ctx, cancel)
	return ctx, func() { stop(); cancel() }
}

func (l *Locked) comparisons() []clientv3.Cmp {
	committed := clientv3.Compare(clientv3.Version(l.prefix+"/committed"), "=", 0)
	if l.revision != 0 && !l.legacyState {
		committed = clientv3.Compare(clientv3.Value(l.prefix+"/committed"), "=", "1")
	}
	initialized := clientv3.Compare(clientv3.Value(l.prefix+"/initialized"), "=", l.anchor)
	if l.inspect && l.anchor == "" {
		initialized = clientv3.Compare(clientv3.Version(l.prefix+"/initialized"), "=", 0)
	}
	return []clientv3.Cmp{l.mutex.IsOwner(), committed, initialized,
		clientv3.Compare(clientv3.ModRevision(l.prefix+"/head"), "=", l.revision)}
}

func (l *Locked) check(ctx context.Context) error {
	if l.faulted || l.closed || l.ctx.Err() != nil {
		return ErrLost
	}
	r, err := l.client.Txn(ctx).If(l.comparisons()...).Then(clientv3.OpGet(l.prefix + "/head")).Commit()
	if err != nil || !r.Succeeded {
		l.faulted = true
		return errors.Join(ErrLost, err)
	}
	return nil
}

// Check must also be used before exposing an approval/read-only result. A local
// cached lease deadline is never sufficient authority to return credentials.
func (l *Locked) Check(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	ctx, cancel := l.requestContext(ctx, 0)
	defer cancel()
	return l.check(ctx)
}

func digest(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

func (l *Locked) Read(ctx context.Context) ([]byte, uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ctx, cancel := l.requestContext(ctx, l.current.Length) // Download of the published head.
	defer cancel()
	return l.read(ctx)
}

// ReadCached still acquires/checks authoritative ownership and head metadata.
// An exact generation AND ciphertext digest match permits reuse of a snapshot
// that this parent has already authenticated. No plaintext is sent to the helper.
func (l *Locked) ReadCached(ctx context.Context, generation uint64, checksum []byte) ([]byte, uint64, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ctx, cancel := l.requestContext(ctx, l.current.Length)
	defer cancel()
	if len(checksum) != sha256.Size || generation == 0 {
		return nil, 0, errors.New("invalid snapshot cache hint")
	}
	if l.revision != 0 && generation == l.current.Generation && hex.EncodeToString(checksum) == l.current.SHA256 {
		if err := l.check(ctx); err != nil {
			return nil, 0, err
		}
		return nil, generation, nil
	}
	return l.read(ctx)
}

func (l *Locked) read(ctx context.Context) ([]byte, uint64, error) {
	if err := l.check(ctx); err != nil {
		return nil, 0, err
	}
	if l.revision == 0 {
		return nil, 0, ErrMissing
	}
	data, err := l.objects.Get(ctx, l.current.Object)
	if err != nil || len(data) != l.current.Length || digest(data) != l.current.SHA256 {
		l.faulted = true
		return nil, 0, errors.Join(errors.New("cloud object missing or corrupt"), err)
	}
	if err := l.check(ctx); err != nil {
		return nil, 0, err
	}
	return data, l.current.Generation, nil
}

// Commit verifies the upload receipt (or falls back to full readback), then
// publishes the immutable object under ownership/generation checks. A receipt-
// verified commit schedules full verification outside the transaction.
// Failure permanently faults this handle. An ambiguous transaction is never
// retried; reopening reads the authoritative head to discover the durable result.
func (l *Locked) Commit(ctx context.Context, ciphertext []byte, expectedGeneration uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.inspect {
		return errors.New("maintenance cannot publish vault data")
	}
	ctx, cancel := l.requestContext(ctx, 2*len(ciphertext)) // Upload plus full readback.
	defer cancel()
	if err := l.check(ctx); err != nil {
		return err
	}
	if expectedGeneration != l.current.Generation || expectedGeneration == math.MaxUint64 {
		return errors.New("unexpected cloud generation")
	}
	if len(ciphertext) < 112 || len(ciphertext) > MaxBlob || !bytes.Equal(ciphertext[:8], []byte("PF2BAK01")) {
		return errors.New("invalid encrypted vault envelope")
	}
	name, err := randomName(32)
	if err != nil {
		return err
	}
	l.faulted = true // Includes unknown PutNew or Txn outcomes; clear only after confirmed commit.
	verified := false
	if objects, ok := l.objects.(verifiedObjects); ok {
		verified, err = objects.PutNewVerified(ctx, name, ciphertext)
	} else {
		err = l.objects.PutNew(ctx, name, ciphertext)
	}
	if err != nil {
		return fmt.Errorf("cloud upload: %w", err)
	}
	if !verified || l.audit == nil {
		back, readErr := l.objects.Get(ctx, name)
		if readErr != nil || !bytes.Equal(back, ciphertext) {
			return errors.Join(errors.New("cloud upload readback failed"), readErr)
		}
	}
	next := head{Version: 1, Generation: expectedGeneration + 1, Object: name, SHA256: digest(ciphertext), Length: len(ciphertext)}
	encoded, _ := json.Marshal(next)
	r, err := l.client.Txn(ctx).If(l.comparisons()...).Then(clientv3.OpPut(l.prefix+"/head", string(encoded)), clientv3.OpPut(l.prefix+"/committed", "1")).Commit()
	if err != nil || !r.Succeeded {
		return errors.Join(ErrLost, err)
	}
	// A lost lease after this point may hide the response, but never rolls back head.
	l.current, l.revision = next, r.Header.Revision
	if l.ctx.Err() != nil {
		return ErrLost
	}
	l.faulted = false
	if verified && l.audit != nil {
		l.audit(next)
	}
	return nil
}

// Close releases ownership only after in-flight methods finish. Failed uploads
// can leave unreachable ciphertext objects; they are never adopted automatically.
func (l *Locked) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var unlock error
	if l.owned {
		unlock = l.mutex.Unlock(ctx)
	}
	l.cancel()
	// Orphan stops keepalive immediately; bounded Revoke releases any surviving lease.
	l.session.Orphan()
	_, revoke := l.client.Revoke(ctx, l.session.Lease())
	return errors.Join(unlock, revoke)
}
