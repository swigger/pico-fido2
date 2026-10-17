package storage

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type pipeTestClient struct {
	input  io.WriteCloser
	output io.ReadCloser
	done   chan error
	next   uint64
	kill   func() error // Only the disposable child launched by this test.
}

// helperBinary builds the real helper, or uses PICO_FIDO_STORAGE_TEST_HELPER
// (absolute path of a prebuilt test helper) where no Go toolchain is on PATH,
// e.g. cross-compiled Windows test binaries run away from the build machine.
// Unix test helpers must be built with the pfstorage_testkey tag.
func helperBinary(t *testing.T) string {
	t.Helper()
	if prebuilt := os.Getenv("PICO_FIDO_STORAGE_TEST_HELPER"); prebuilt != "" {
		if !filepath.IsAbs(prebuilt) {
			t.Fatal("PICO_FIDO_STORAGE_TEST_HELPER must be absolute")
		}
		return prebuilt
	}
	exe := filepath.Join(t.TempDir(), helperTestBinary)
	build := exec.Command("go", append(append([]string{"build"}, helperTestBuildFlags...), "-trimpath", "-buildvcs=false", "-o", exe, "./cmd/relay-storage-helper")...)
	hideTestWindow(build)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("helper build: %v\n%s", err, output)
	}
	return exe
}

// Start the actual helper binary with OS pipes. Its profile and all backend data
// belong to this test's temporary directories and synthetic TLS servers.
func startHelperProcess(t *testing.T, profilePath, namespace string, mode ...string) *pipeTestClient {
	t.Helper()
	exe := helperBinary(t)
	command := "--pipe"
	if len(mode) != 0 {
		command = mode[0]
	}
	cmd := exec.Command(exe, command, namespace, profilePath)
	hideTestWindow(cmd)
	input, err := cmd.StdinPipe()
	need(t, err)
	output, err := cmd.StdoutPipe()
	need(t, err)
	need(t, cmd.Start())
	client := &pipeTestClient{input: input, output: output, next: 1, done: make(chan error, 1), kill: cmd.Process.Kill}
	processDone := make(chan struct{})
	go func() { client.done <- cmd.Wait(); close(processDone) }()
	t.Cleanup(func() {
		input.Close()
		output.Close()
		// Kill only this owned disposable helper if it failed to stop after pipe closure.
		select {
		case <-processDone:
		case <-time.After(2 * time.Second):
			_ = cmd.Process.Kill()
			<-processDone
		}
	})
	return client
}

// The helper refuses a regular file on stdin before reading a profile or frame.
func TestHelperRefusesNonPipeStdio(t *testing.T) {
	dir := t.TempDir()
	exe := helperBinary(t)
	input := filepath.Join(dir, "stdin")
	need(t, os.WriteFile(input, requestBytes(PipeOpen, 1, []byte{0}), 0600))
	file, err := os.Open(input)
	need(t, err)
	defer file.Close()
	cmd := exec.Command(exe, "--pipe", webdavSpace, filepath.Join(dir, "profile"))
	hideTestWindow(cmd)
	cmd.Stdin = file
	output, err := cmd.Output()
	if err == nil || len(output) != 0 {
		t.Fatal("helper served a non-pipe stdin")
	}
	usage := exec.Command(exe, "--profile-create")
	hideTestWindow(usage)
	if usage.Run() == nil {
		t.Fatal("removed --profile-create entry point still accepted")
	}
}

func startPipe(t *testing.T, factory PipeFactory) *pipeTestClient {
	t.Helper()
	input, write := io.Pipe()
	read, output := io.Pipe()
	client := &pipeTestClient{input: write, output: read, done: make(chan error, 1), next: 1}
	go func() {
		client.done <- ServePipe(context.Background(), input, output, factory)
		input.Close()
		output.Close()
	}()
	t.Cleanup(func() { write.Close(); read.Close() })
	return client
}
func requestBytes(op byte, id uint64, data []byte) []byte {
	header := make([]byte, 24)
	copy(header, pipeMagic)
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(data)))
	header[12] = op
	binary.LittleEndian.PutUint64(header[16:], id)
	return append(header, data...)
}
func (c *pipeTestClient) request(t *testing.T, op byte, data []byte) []byte {
	t.Helper()
	_, err := c.input.Write(requestBytes(op, c.next, data))
	need(t, err)
	header := make([]byte, 24)
	_, err = io.ReadFull(c.output, header)
	need(t, err)
	if string(header[:8]) != string(pipeMagic) || header[12] != op|0x80 || binary.LittleEndian.Uint64(header[16:]) != c.next {
		t.Fatal("pipe response scope")
	}
	length := binary.LittleEndian.Uint32(header[8:12])
	if length == 0 || length > pipeLimit {
		t.Fatal("pipe response bounds")
	}
	response := make([]byte, length)
	_, err = io.ReadFull(c.output, response)
	need(t, err)
	c.next++
	return response
}
func (c *pipeTestClient) finish(t *testing.T, success bool) {
	t.Helper()
	select {
	case err := <-c.done:
		if (err == nil) != success {
			t.Fatalf("unexpected pipe completion: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pipe did not release session")
	}
}

func TestPipeRealCloudRoundTrip(t *testing.T) {
	ctx := context.Background()
	fixture := startDAV(t)
	remote := davObjects(t, fixture)
	cfg := newConfig(t)
	server := start(t, cfg)
	t.Cleanup(server.Close)
	coordinator := client(t, cfg)
	factory := func(ctx context.Context, mode OpenMode, token []byte) (PipeSession, error) {
		return AcquireWithToken(ctx, coordinator, remote, webdavSpace, mode, token)
	}
	pipe := startPipe(t, factory)
	if got := pipe.request(t, PipeOpen, []byte{1}); len(got) != 9 || got[0] != 0 || binary.LittleEndian.Uint64(got[1:]) != 0 {
		t.Fatal("initial pipe open")
	}
	if got := pipe.request(t, PipeCommit, append(make([]byte, 8), blob(6)...)); len(got) != 9 || got[0] != 0 || binary.LittleEndian.Uint64(got[1:]) != 1 {
		t.Fatal("pipe commit")
	}
	if got := pipe.request(t, PipeCheck, nil); len(got) != 1 || got[0] != 0 {
		t.Fatal("pipe ownership check")
	}
	if got := pipe.request(t, PipeClose, nil); len(got) != 1 || got[0] != 0 {
		t.Fatal("pipe close")
	}
	pipe.finish(t, true)
	pipe = startPipe(t, factory)
	got := pipe.request(t, PipeOpen, []byte{0})
	if len(got) != 121 || got[0] != 0 || binary.LittleEndian.Uint64(got[1:9]) != 1 || got[len(got)-1] != 6 {
		t.Fatal("pipe reopen did not return committed cloud bytes")
	}
	pipe.input.Close()
	pipe.finish(t, false)
	// Parent EOF must release the distributed lock, allowing an independent opener.
	locked := acquire(t, ctx, coordinator, remote, webdavSpace, false)
	need(t, locked.Close())
	// The same live lock/head checks return a small cache acknowledgement.
	checksum := sha256.Sum256(blob(6))
	hint := make([]byte, 40)
	binary.LittleEndian.PutUint64(hint, 1)
	copy(hint[8:], checksum[:])
	pipe = startPipe(t, factory)
	got = pipe.request(t, PipeOpenCached, hint)
	if len(got) != 9 || got[0] != 0 || binary.LittleEndian.Uint64(got[1:]) != 1 {
		t.Fatal("cached open did not acknowledge the exact snapshot")
	}
	pipe.request(t, PipeClose, nil)
	pipe.finish(t, true)
	hint[8] ^= 1
	pipe = startPipe(t, factory)
	got = pipe.request(t, PipeOpenCached, hint)
	if len(got) != 121 || got[0] != 0 || got[len(got)-1] != 6 {
		t.Fatal("cache miss did not return the authoritative snapshot")
	}
	pipe.request(t, PipeClose, nil)
	pipe.finish(t, true)
}

type waitingSession struct {
	entered chan struct{}
	closed  atomic.Bool
}

func (s *waitingSession) Read(context.Context) ([]byte, uint64, error) { return blob(1), 1, nil }
func (s *waitingSession) Check(context.Context) error                  { return nil }
func (s *waitingSession) Commit(ctx context.Context, _ []byte, _ uint64) error {
	close(s.entered)
	<-ctx.Done()
	return ctx.Err()
}
func (s *waitingSession) Close() error { s.closed.Store(true); return nil }

func TestPipeParentExitCancelsInFlightWork(t *testing.T) {
	session := &waitingSession{entered: make(chan struct{})}
	pipe := startPipe(t, func(context.Context, OpenMode, []byte) (PipeSession, error) { return session, nil })
	if got := pipe.request(t, PipeOpen, []byte{0}); got[0] != 0 {
		t.Fatal("pipe open")
	}
	_, err := pipe.input.Write(requestBytes(PipeCommit, 2, append(make([]byte, 8), blob(2)...)))
	need(t, err)
	select {
	case <-session.entered:
	case <-time.After(time.Second):
		t.Fatal("commit not entered")
	}
	pipe.input.Close()
	pipe.output.Close()
	pipe.finish(t, false)
	if !session.closed.Load() {
		t.Fatal("parent exit leaked session")
	}
}

func TestPipeBoundsOrderingAndRedactedFailure(t *testing.T) {
	for _, mutate := range []func([]byte){
		func(b []byte) { b[0] ^= 1 }, func(b []byte) { b[13] = 1 }, func(b []byte) { b[16] = 2 },
		func(b []byte) { binary.LittleEndian.PutUint32(b[8:12], pipeLimit+1) }, func(b []byte) { b[12] = 99 },
	} {
		opened := false
		pipe := startPipe(t, func(context.Context, OpenMode, []byte) (PipeSession, error) {
			opened = true
			return nil, errors.New("should not open")
		})
		header := requestBytes(PipeOpen, 1, nil)
		mutate(header)
		_, _ = pipe.input.Write(header)
		pipe.finish(t, false)
		if opened {
			t.Fatal("malformed request opened storage")
		}
	}
	pipe := startPipe(t, func(context.Context, OpenMode, []byte) (PipeSession, error) {
		return nil, errors.New("fictional-secret-token-must-not-be-returned")
	})
	if got := pipe.request(t, PipeOpen, []byte{0}); len(got) != 1 || got[0] != 1 {
		t.Fatal("upstream secret leaked into IPC error")
	}
	pipe.finish(t, false)
}
