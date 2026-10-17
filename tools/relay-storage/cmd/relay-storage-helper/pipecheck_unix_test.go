//go:build unix

package main

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrivatePipeCheck(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if !isPrivatePipe(read) || !isPrivatePipe(write) {
		t.Fatal("anonymous pipe refused")
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	left, right := os.NewFile(uintptr(pair[0]), "left"), os.NewFile(uintptr(pair[1]), "right")
	defer left.Close()
	defer right.Close()
	if !isPrivatePipe(left) {
		t.Fatal("socketpair refused")
	}
	regular, err := os.Create(filepath.Join(t.TempDir(), "stdin"))
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	if isPrivatePipe(regular) {
		t.Fatal("regular file accepted")
	}
	if null, err := os.Open(os.DevNull); err == nil {
		defer null.Close()
		if isPrivatePipe(null) {
			t.Fatal("character device accepted")
		}
	}
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	if isPrivatePipe(dir) {
		t.Fatal("directory accepted")
	}
	closed, peer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	peer.Close()
	closed.Close()
	if isPrivatePipe(closed) {
		t.Fatal("closed descriptor accepted")
	}
}
