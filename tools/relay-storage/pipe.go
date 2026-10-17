package storage

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"sync"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
)

// Private parent/child protocol: 24-byte header, PF2STO01, length LE32,
// operation byte, three reserved zero bytes, sequence LE64 (starts at one).
// Response operation is request|0x80; its first payload byte is 0(success)/1(error).
// Credentials are encrypted PF2BAK01 bytes. There are no network IPC listeners.
const (
	PipeOpen          byte = 1
	PipeRead          byte = 2
	PipeCheck         byte = 3
	PipeCommit        byte = 4
	PipeClose         byte = 5
	PipeProfile       byte = 6 // One-shot setup child only; never a vault-session operation.
	PipeEnrollStart   byte = 7
	PipeEnrollAnswer  byte = 8
	PipeEnrollPoll    byte = 9
	PipeMaintain      byte = 10 // Existing-profile maintenance child only.
	PipeOpenCached    byte = 11 // Existing snapshot: generation LE64 + ciphertext SHA-256.
	PipeRelease       byte = 12 // Release the lease, retain transports until idle expiry.
	PipeWake          byte = 13 // Idle-only handshake before opening another transaction.
	pipeLimit              = MaxBlob + 9
	helperIdleTimeout      = 5 * time.Minute
)

var pipeMagic = []byte("PF2STO01")

type pipeFrame struct {
	op   byte
	id   uint64
	data []byte
}

func readFrame(r io.Reader, expected uint64) (pipeFrame, error) {
	return readFrameLimit(r, expected, pipeLimit)
}
func readFrameLimit(r io.Reader, expected uint64, maximum uint32) (pipeFrame, error) {
	var f pipeFrame
	header := make([]byte, 24)
	if _, err := io.ReadFull(r, header); err != nil {
		return f, err
	}
	length := binary.LittleEndian.Uint32(header[8:12])
	f.op, f.id = header[12], binary.LittleEndian.Uint64(header[16:])
	if string(header[:8]) != string(pipeMagic) || length > maximum || f.op < PipeOpen || f.op > PipeWake ||
		header[13] != 0 || header[14] != 0 || header[15] != 0 || f.id != expected || f.id == 0 {
		return f, errors.New("invalid storage pipe frame")
	}
	f.data = make([]byte, length)
	_, err := io.ReadFull(r, f.data)
	if err != nil {
		clear(f.data)
	}
	return f, err
}
func sendFrame(w io.Writer, frame pipeFrame, failed bool, data []byte) error {
	status := byte(0)
	if failed {
		status = 1
	}
	return sendFrameStatus(w, frame, status, data)
}
func sendFrameStatus(w io.Writer, frame pipeFrame, status byte, data []byte) error {
	if len(data)+1 > pipeLimit {
		return errors.New("storage pipe response too large")
	}
	header := make([]byte, 25)
	copy(header, pipeMagic)
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(data)+1))
	header[12] = frame.op | 0x80
	binary.LittleEndian.PutUint64(header[16:24], frame.id)
	header[24] = status
	if _, err := io.Copy(w, bytes.NewReader(header)); err != nil {
		return err
	}
	_, err := io.Copy(w, bytes.NewReader(data))
	return err
}

type PipeSession interface {
	Read(context.Context) ([]byte, uint64, error)
	Check(context.Context) error
	Commit(context.Context, []byte, uint64) error
	Close() error
}
type PipeFactory func(context.Context, OpenMode, []byte) (PipeSession, error)

type managedObjects interface {
	Objects
	Close()
}

// A matching cached head needs only the coordinator. Some provider constructors
// perform several remote directory lookups, so defer those until ciphertext IO.
// Initialization is attempted once; any failure ends this handle, never retries.
type deferredObjects struct {
	mu      sync.Mutex
	open    func() (managedObjects, error)
	current managedObjects
	closed  bool
}

func (d *deferredObjects) ready() error {
	if d.closed {
		return ErrProvider
	}
	if d.current == nil {
		var err error
		d.current, err = d.open()
		if err != nil {
			d.closed = true
			return err
		}
	}
	return nil
}
func (d *deferredObjects) Get(ctx context.Context, name string) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := d.ready(); err != nil {
		return nil, err
	}
	return d.current.Get(ctx, name)
}
func (d *deferredObjects) PutNew(ctx context.Context, name string, data []byte) error {
	_, err := d.PutNewVerified(ctx, name, data)
	return err
}
func (d *deferredObjects) PutNewVerified(ctx context.Context, name string, data []byte) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := d.ready(); err != nil {
		return false, err
	}
	if verified, ok := d.current.(verifiedObjects); ok {
		return verified.PutNewVerified(ctx, name, data)
	}
	return false, d.current.PutNew(ctx, name, data)
}
func (d *deferredObjects) GetForAudit(ctx context.Context, name string) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := d.ready(); err != nil {
		return nil, err
	}
	if reader, ok := d.current.(interface {
		GetForAudit(context.Context, string) ([]byte, error)
	}); ok {
		return reader.GetForAudit(ctx, name)
	}
	return d.current.Get(ctx, name)
}
func (d *deferredObjects) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.closed = true
	if d.current != nil {
		d.current.Close()
		d.current = nil
	}
}

// ServeProfilePipe retains the profile, coordinator and provider between short
// leases. No transaction or distributed lock is held during the idle interval.
func ServeProfilePipe(ctx context.Context, input io.Reader, output io.Writer, path, namespace string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var profile *Profile
	var coordinator *clientv3.Client
	var remote *deferredObjects
	defer func() {
		if remote != nil {
			remote.Close()
		}
		if coordinator != nil {
			coordinator.Close()
		}
		if profile != nil {
			profile.Close()
		}
	}()
	auditor := newSnapshotAuditor(func(ctx context.Context, name string) ([]byte, error) {
		return remote.GetForAudit(ctx, name)
	})
	factory := func(life context.Context, mode OpenMode, token []byte) (PipeSession, error) {
		if profile == nil {
			var err error
			profile, err = OpenProfile(path, namespace)
			if err != nil {
				return nil, err
			}
			config, err := profile.Config()
			if err != nil {
				return nil, err
			}
			coordinator, err = OpenCoordinator(ctx, config.Coordinator)
			if err != nil {
				return nil, err
			}
			remote = &deferredObjects{open: func() (managedObjects, error) {
				return NewRcloneObjects(ctx, config.Provider, namespace, profile.SaveTokens)
			}}
		}
		locked, err := acquireLocked(life, coordinator, remote, namespace, mode, token, false, true)
		if err != nil {
			return nil, err
		}
		locked.audit = auditor.enqueue
		return locked, nil
	}
	return servePipe(ctx, input, output, factory, &pipeLifecycle{idle: helperIdleTimeout, pause: auditor.pause, resume: auditor.resume, failed: auditor.failed})
}

type pipeLifecycle struct {
	idle   time.Duration
	pause  func() error
	resume func(context.Context)
	failed <-chan struct{}
}

// ServePipe accepts successive short sessions per child. Malformed frames, operation failures,
// response loss, parent EOF and cancellation end the session. A dedicated reader
// notices parent exit while provider/approval-independent IO is still in flight.
// The caller closes input/output when this function returns to release the reader.
func ServePipe(parent context.Context, input io.Reader, output io.Writer, open PipeFactory) error {
	return servePipe(parent, input, output, open, nil)
}
func servePipe(parent context.Context, input io.Reader, output io.Writer, open PipeFactory, hooks *pipeLifecycle) (result error) {
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	idle := helperIdleTimeout
	var failed <-chan struct{}
	if hooks != nil {
		idle, failed = hooks.idle, hooks.failed
		defer func() { result = errors.Join(result, hooks.pause()) }()
	}
	timer := time.NewTimer(idle)
	defer timer.Stop()
	stopTimer := func() {
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
	}
	frames := make(chan pipeFrame)
	go func() {
		for id := uint64(1); ; id++ {
			frame, err := readFrame(input, id)
			if err != nil || (id == math.MaxUint64 && frame.op != PipeClose) {
				cancel()
				return
			}
			select {
			case frames <- frame:
			case <-ctx.Done():
				return
			}
			if frame.op == PipeClose || id == math.MaxUint64 {
				return
			}
		}
	}()
	var session PipeSession
	defer func() {
		if session != nil {
			session.Close()
		}
	}()
	for {
		var frame pipeFrame
		select {
		case <-timer.C:
			return nil // No lease held; parent may start a fresh helper before Open.
		case <-failed:
			return ErrAudit
		case <-ctx.Done():
			return errors.New("storage pipe closed or canceled")
		case frame = <-frames:
		}
		var response []byte
		var err error
		stopTimer()
		if hooks != nil {
			err = hooks.pause()
		}
		if err != nil {
			_ = sendFrameStatus(output, frame, 2, nil) // pause reports confirmed audit corruption only.
			return err
		}
		switch frame.op {
		case PipeWake:
			if session != nil || len(frame.data) != 0 {
				err = errors.New("invalid idle wake")
			}
		case PipeOpenCached:
			if session != nil || len(frame.data) != 40 || binary.LittleEndian.Uint64(frame.data[:8]) == 0 {
				err = errors.New("invalid cached storage open")
				break
			}
			session, err = open(ctx, OpenExisting, nil)
			if err == nil {
				var data []byte
				var generation uint64
				if cached, ok := session.(interface {
					ReadCached(context.Context, uint64, []byte) ([]byte, uint64, error)
				}); ok {
					data, generation, err = cached.ReadCached(ctx, binary.LittleEndian.Uint64(frame.data[:8]), frame.data[8:])
				} else {
					data, generation, err = session.Read(ctx)
				}
				if err == nil {
					response = make([]byte, 8, 8+len(data))
					binary.LittleEndian.PutUint64(response, generation)
					response = append(response, data...)
				}
			}
		case PipeOpen:
			if session != nil || (len(frame.data) != 1 && len(frame.data) != 33) || frame.data[0] > byte(OpenResume) {
				err = errors.New("invalid storage open")
				break
			}
			if (OpenMode(frame.data[0]) == OpenExisting && len(frame.data) != 1) || (OpenMode(frame.data[0]) == OpenResume && len(frame.data) != 33) {
				err = errors.New("invalid storage creation token")
				break
			}
			session, err = open(ctx, OpenMode(frame.data[0]), frame.data[1:])
			if err == nil {
				if frame.data[0] == 1 {
					response = make([]byte, 8)
				} else {
					var data []byte
					var generation uint64
					data, generation, err = session.Read(ctx)
					if OpenMode(frame.data[0]) == OpenResume && errors.Is(err, ErrMissing) {
						err = session.Check(ctx) // Valid acquired, never-committed head only.
					}
					if err == nil {
						response = make([]byte, 8, 8+len(data))
						binary.LittleEndian.PutUint64(response, generation)
						response = append(response, data...)
					}
				}
			}
		case PipeRead:
			if session == nil || len(frame.data) != 0 {
				err = errors.New("invalid storage read")
				break
			}
			var data []byte
			var generation uint64
			data, generation, err = session.Read(ctx)
			if err == nil {
				response = make([]byte, 8, 8+len(data))
				binary.LittleEndian.PutUint64(response, generation)
				response = append(response, data...)
			}
		case PipeCheck:
			if session == nil || len(frame.data) != 0 {
				err = errors.New("invalid storage check")
				break
			}
			err = session.Check(ctx)
		case PipeCommit:
			if session == nil || len(frame.data) < 120 {
				err = errors.New("invalid storage commit")
				break
			}
			generation := binary.LittleEndian.Uint64(frame.data[:8])
			err = session.Commit(ctx, frame.data[8:], generation)
			if err == nil {
				response = make([]byte, 8)
				binary.LittleEndian.PutUint64(response, generation+1)
			}
		case PipeRelease, PipeClose:
			if len(frame.data) != 0 || (session == nil && frame.op == PipeRelease) {
				err = errors.New("invalid storage close")
				break
			}
			if session != nil {
				err = session.Close()
				session = nil
			}
		default:
			err = errors.New("unsupported vault session operation")
		}
		if err != nil {
			// Never send upstream OAuth/network errors that could echo a secret.
			_ = sendFrame(output, frame, true, nil)
			return errors.New("storage operation failed; reopen required")
		}
		if err := sendFrame(output, frame, false, response); err != nil {
			return errors.New("storage response delivery failed")
		}
		if frame.op == PipeClose {
			return nil
		}
		if session == nil {
			timer.Reset(idle)
			if hooks != nil && frame.op == PipeRelease {
				hooks.resume(ctx)
			}
		}
	}
}
