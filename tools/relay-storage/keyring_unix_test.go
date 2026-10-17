//go:build unix

package storage

import (
	"bytes"
	"os"
	"testing"
)

// Opt-in: uses the real OS keyring of the current user (macOS Keychain or a
// Secret Service on the session D-Bus) and leaves the per-user profile key there,
// exactly as a first production profile creation would.
func TestKeyringProfileKey(t *testing.T) {
	if os.Getenv("PICO_FIDO_KEYRING_TEST") != "1" {
		t.Skip("set PICO_FIDO_KEYRING_TEST=1 to use the real OS keyring")
	}
	first, err := keyringProfileKey(true)
	need(t, err)
	second, err := keyringProfileKey(false)
	need(t, err)
	if len(first) != 32 || !bytes.Equal(first, second) {
		t.Fatal("keyring profile key did not persist")
	}
	withProfileKey(t, keyringProfileKey)
	config := profileFixture(t)
	path := t.TempDir() + "/profile" + profileExtension
	need(t, CreateProfile(path, config))
	profile, err := OpenProfile(path, config.Namespace)
	need(t, err)
	profile.Close()
}
