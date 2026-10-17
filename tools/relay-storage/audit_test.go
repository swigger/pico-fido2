package storage

import (
	"context"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/hash"
	"github.com/rclone/rclone/fs/object"
)

type receiptObject struct {
	fs.Object
	empty bool
}

func (o receiptObject) Hash(ctx context.Context, kind hash.Type) (string, error) {
	if o.empty {
		return "", nil
	}
	return o.Object.Hash(ctx, kind)
}
func (o receiptObject) Open(context.Context, ...fs.OpenOption) (io.ReadCloser, error) {
	panic("receipt verification downloaded content")
}

func TestUploadReceiptChecksContentAndSize(t *testing.T) {
	ctx := context.Background()
	good := receiptObject{Object: object.NewMemoryObject("snapshot", time.Now(), blob(1))}
	verified, err := verifyUploadReceipt(ctx, good, blob(1))
	need(t, err)
	if !verified {
		t.Fatal("valid upload checksum ignored")
	}
	if _, err := verifyUploadReceipt(ctx, good, blob(2)); err == nil {
		t.Fatal("mismatching receipt accepted")
	}
	if _, err := verifyUploadReceipt(ctx, good, append(blob(1), 1)); err == nil {
		t.Fatal("wrong length accepted")
	}
	good.empty = true
	verified, err = verifyUploadReceipt(ctx, good, blob(1))
	need(t, err)
	if verified {
		t.Fatal("missing hash accepted as verified")
	}
}

type receiptMemory struct{ *memoryObjects }

func (m *receiptMemory) PutNewVerified(ctx context.Context, name string, data []byte) (bool, error) {
	err := m.PutNew(ctx, name, data)
	return err == nil, err
}

func TestReceiptCommitPublishesBeforeDeferredReadAndStillFences(t *testing.T) {
	ctx := context.Background()
	cfg := newConfig(t)
	server := start(t, cfg)
	t.Cleanup(server.Close)
	c := client(t, cfg)
	objects := &receiptMemory{&memoryObjects{data: make(map[string][]byte)}}
	l := acquire(t, ctx, c, objects, webdavSpace, true)
	var audits []head
	l.audit = func(h head) { audits = append(audits, h) }
	need(t, l.Commit(ctx, blob(1), 0))
	if objects.gets != 0 || len(audits) != 1 || audits[0].Object != l.current.Object {
		t.Fatal("commit waited for download or audited another object")
	}
	objects.afterPut = func() { _, err := c.Delete(ctx, l.mutex.Key()); need(t, err) }
	if err := l.Commit(ctx, blob(2), 1); !errors.Is(err, ErrLost) {
		t.Fatalf("unfenced commit: %v", err)
	}
	if len(audits) != 1 {
		t.Fatal("unpublished object scheduled as committed")
	}
	need(t, l.Close())
}

func TestBackgroundAuditPreemptsAndDistinguishesCorruption(t *testing.T) {
	entered := make(chan struct{}, 1)
	var mode atomic.Int32
	a := newSnapshotAuditor(func(ctx context.Context, name string) ([]byte, error) {
		if name != "exact-object" {
			t.Error("audit read a different object")
		}
		entered <- struct{}{}
		switch mode.Load() {
		case 0:
			<-ctx.Done()
			return nil, ctx.Err()
		case 1:
			return nil, errors.New("transient network error")
		default:
			return blob(2), nil
		}
	})
	a.enqueue(head{Object: "exact-object", Length: len(blob(1)), SHA256: digest(blob(1))})
	a.resume(context.Background())
	<-entered
	before := time.Now()
	need(t, a.pause())
	if time.Since(before) > time.Second {
		t.Fatal("foreground blocked behind background read")
	}
	mode.Store(1)
	a.resume(context.Background())
	<-entered
	need(t, a.pause())
	a.mu.Lock()
	pending := a.pending != nil
	a.mu.Unlock()
	if !pending {
		t.Fatal("unverified object lost after network error")
	}
	mode.Store(2)
	a.resume(context.Background())
	<-entered
	select {
	case <-a.failed:
	case <-time.After(time.Second):
		t.Fatal("corrupt snapshot was not reported")
	}
	if !errors.Is(a.pause(), ErrAudit) {
		t.Fatal("corruption did not remain faulted")
	}
}

func TestPipeIdleExpiryAndRelease(t *testing.T) {
	input, write := io.Pipe()
	read, output := io.Pipe()
	c := &pipeTestClient{input: write, output: read, next: 1, done: make(chan error, 1)}
	t.Cleanup(func() { write.Close(); read.Close() })
	var opens atomic.Int32
	var sessions []*waitingSession
	go func() {
		c.done <- servePipe(context.Background(), input, output, func(context.Context, OpenMode, []byte) (PipeSession, error) {
			s := &waitingSession{}
			sessions = append(sessions, s)
			opens.Add(1)
			return s, nil
		}, &pipeLifecycle{idle: 100 * time.Millisecond, pause: func() error { return nil }, resume: func(context.Context) {}})
		input.Close()
		output.Close()
	}()
	if c.request(t, PipeOpen, []byte{0})[0] != 0 {
		t.Fatal("open")
	}
	// A running transaction must not expire because there were no pipe requests.
	time.Sleep(150 * time.Millisecond)
	if c.request(t, PipeCheck, nil)[0] != 0 {
		t.Fatal("active session expired")
	}
	if c.request(t, PipeRelease, nil)[0] != 0 || !sessions[0].closed.Load() {
		t.Fatal("release kept lease")
	}
	if c.request(t, PipeWake, nil)[0] != 0 || c.request(t, PipeOpen, []byte{0})[0] != 0 {
		t.Fatal("retained helper could not reacquire")
	}
	if opens.Load() != 2 {
		t.Fatal("lease was reused across transactions")
	}
	c.request(t, PipeRelease, nil)
	c.finish(t, true)
}
