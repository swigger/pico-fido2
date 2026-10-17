//go:build unix && pfstorage_testkey

package storage

import (
	"encoding/hex"
	"errors"
	"os"
)

// Test-only key source for helper binaries built by the package tests with
// -tags pfstorage_testkey. Release builds (build.sh/build.ps1) never set this
// tag, so production helpers always use the OS keyring.
func init() {
	profileKeySource = func(bool) ([]byte, error) {
		key, err := hex.DecodeString(os.Getenv("PICO_FIDO_STORAGE_TEST_KEY"))
		if err != nil || len(key) != 32 {
			return nil, errors.New("test profile key unavailable")
		}
		return key, nil
	}
}
