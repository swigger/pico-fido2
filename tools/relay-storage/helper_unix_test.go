//go:build unix

package storage

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"os"
	"os/exec"
)

const helperTestBinary = "PicoFidoStorage-test"

// Unit tests never touch the user's keyring. One random key per test process is
// injected here and handed to helper binaries built with the test-only tag.
var helperTestBuildFlags = []string{"-tags", "pfstorage_testkey"}

var testProfileKey = func() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}()

func init() {
	profileKeySource = func(bool) ([]byte, error) { return bytes.Clone(testProfileKey), nil }
	if err := os.Setenv("PICO_FIDO_STORAGE_TEST_KEY", hex.EncodeToString(testProfileKey)); err != nil {
		panic(err)
	}
}

func hideTestWindow(*exec.Cmd) {}
