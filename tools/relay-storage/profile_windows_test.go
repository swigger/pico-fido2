package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// A reader without FILE_SHARE_DELETE makes MoveFileEx replacement fail.
func TestProtectedProfileFailedReplaceWindows(t *testing.T) {
	config := profileFixture(t)
	t.Run("failed token replace", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "profile.dpapi")
		need(t, CreateProfile(path, config))
		original, err := os.ReadFile(path)
		need(t, err)
		profile, err := OpenProfile(path, config.Namespace)
		need(t, err)
		t.Cleanup(profile.Close)
		name, err := windows.UTF16PtrFromString(path)
		need(t, err)
		blocker, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		need(t, err)
		next := mapsClone(config.Provider.Options)
		next["token"] = `{"access_token":"not-saved"}`
		if profile.SaveTokens(next) == nil {
			t.Fatal("failed profile replacement reported success")
		}
		need(t, windows.CloseHandle(blocker))
		if _, err := profile.Config(); err == nil {
			t.Fatal("faulted profile resumed")
		}
		if profile.SaveTokens(next) == nil {
			t.Fatal("faulted profile retried write")
		}
		profile.Close()
		after, err := os.ReadFile(path)
		need(t, err)
		if !bytes.Equal(original, after) {
			t.Fatal("failed replacement damaged original")
		}
		profile, err = OpenProfile(path, config.Namespace)
		need(t, err)
		defer profile.Close()
		loaded, err := profile.Config()
		need(t, err)
		if loaded.Provider.Options["token"] != config.Provider.Options["token"] {
			t.Fatal("failed write exposed new token")
		}
	})
}
