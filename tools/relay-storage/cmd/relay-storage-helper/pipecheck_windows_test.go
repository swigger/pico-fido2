package main

import (
	"os"
	"path/filepath"
	"testing"
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
			t.Fatal("NUL device accepted")
		}
	}
}
