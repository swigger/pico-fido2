package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func profileFixture(t *testing.T) CloudProfile {
	t.Helper()
	ca := authority(t)
	cert, key := ca.leaf(t, "fixture-profile-user", false, false)
	return CloudProfile{Version: 1, Namespace: webdavSpace,
		Coordinator: CoordinatorConfig{Endpoints: []string{"https://coordinator.invalid:2379"}, CAPEM: ca.pem,
			ClientCertPEM: cert, ClientKeyPEM: key, ClusterID: "123456789abcdef0"},
		Provider: ProviderConfig{Provider: "drive", Root: "pico-fido2", Options: map[string]string{
			"token": `{"access_token":"fixture-access-token","refresh_token":"fixture-refresh-secret","token_type":"Bearer"}`}}}
}
func TestProtectedProfilePersistenceAndIdentity(t *testing.T) {
	config := profileFixture(t)
	path := filepath.Join(t.TempDir(), "profile.dpapi")
	need(t, CreateProfile(path, config))
	before, err := os.ReadFile(path)
	need(t, err)
	for _, secret := range []string{"fixture-access-token", "fixture-refresh-secret", "PRIVATE KEY", "coordinator.invalid"} {
		if bytes.Contains(before, []byte(secret)) {
			t.Fatal("plaintext profile secret on disk")
		}
	}
	profile, err := OpenProfile(path, config.Namespace)
	need(t, err)
	t.Cleanup(profile.Close)
	if second, err := OpenProfile(path, config.Namespace); err == nil {
		second.Close()
		t.Fatal("second profile writer acquired lock")
	}
	if CreateProfile(path, config) == nil {
		t.Fatal("existing profile overwritten")
	}
	loaded, err := profile.Config()
	need(t, err)
	if loaded.Coordinator.ClientKeyPEM != config.Coordinator.ClientKeyPEM {
		t.Fatal("protected client identity did not roundtrip")
	}
	loaded.Provider.Options["token"] = "changed outside profile"
	unmodified, err := profile.Config()
	need(t, err)
	if unmodified.Provider.Options["token"] != config.Provider.Options["token"] {
		t.Fatal("configuration accessor exposed mutable profile")
	}
	next := mapsClone(config.Provider.Options)
	next["token"] = `{"access_token":"new-fixture-token"}`
	need(t, profile.SaveTokens(next))
	profile.Close()
	profile, err = OpenProfile(path, config.Namespace)
	need(t, err)
	t.Cleanup(profile.Close)
	loaded, err = profile.Config()
	need(t, err)
	if loaded.Provider.Options["token"] != next["token"] {
		t.Fatal("refreshed OAuth token not durable")
	}
	profile.Close()
	if other, err := OpenProfile(path, "00000000000000000000000000000001"); err == nil {
		other.Close()
		t.Fatal("wrong profile namespace accepted")
	}
	// Even replacing the unencrypted marker cannot substitute another encrypted profile.
	need(t, os.WriteFile(path+".lock", []byte("PF2CLCK1"+"00000000000000000000000000000001"), 0600))
	if other, err := OpenProfile(path, "00000000000000000000000000000001"); err == nil {
		other.Close()
		t.Fatal("cross-profile ciphertext accepted")
	}
}

func TestProtectedProfileFailures(t *testing.T) {
	config := profileFixture(t)
	t.Run("tamper while locked", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "profile.dpapi")
		need(t, CreateProfile(path, config))
		profile, err := OpenProfile(path, config.Namespace)
		need(t, err)
		defer profile.Close()
		cipher, err := os.ReadFile(path)
		need(t, err)
		cipher[len(cipher)-1] ^= 1
		need(t, os.WriteFile(path, cipher, 0600))
		if profile.SaveTokens(config.Provider.Options) == nil {
			t.Fatal("external profile change not detected")
		}
		profile.Close()
		if other, err := OpenProfile(path, config.Namespace); err == nil {
			other.Close()
			t.Fatal("damaged profile accepted")
		}
	})
	t.Run("interrupted initialization resumes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "profile.dpapi")
		need(t, os.WriteFile(path+".lock", []byte("PF2CLCK1"+config.Namespace), 0600))
		need(t, profileCreatable(path, config.Namespace))
		need(t, CreateProfile(path, config))
		profile, err := OpenProfile(path, config.Namespace)
		need(t, err)
		profile.Close()
		if CreateProfile(path, config) == nil || profileCreatable(path, config.Namespace) == nil {
			t.Fatal("completed profile overwritten")
		}
	})
	t.Run("interrupted initialization of other marker", func(t *testing.T) {
		for name, marker := range map[string]string{
			"other namespace": "PF2CLCK1" + "00000000000000000000000000000001",
			"empty":           "",
			"partial":         "PF2CLCK1" + config.Namespace[:8],
			"trailing":        "PF2CLCK1" + config.Namespace + "x",
		} {
			path := filepath.Join(t.TempDir(), "profile.dpapi")
			need(t, os.WriteFile(path+".lock", []byte(marker), 0600))
			if CreateProfile(path, config) == nil || profileCreatable(path, config.Namespace) == nil {
				t.Fatalf("%s marker accepted for creation", name)
			}
			if other, err := OpenProfile(path, config.Namespace); err == nil {
				other.Close()
				t.Fatal("missing profile became defaults")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("missing profile created implicitly")
			}
		}
	})
	t.Run("interrupted initialization while locked", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "profile.dpapi")
		need(t, os.WriteFile(path+".lock", []byte("PF2CLCK1"+config.Namespace), 0600))
		holder, err := openProfileLock(path, false)
		need(t, err)
		if CreateProfile(path, config) == nil {
			t.Fatal("creation resumed without the exclusive lock")
		}
		holder.close()
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("locked creation published a profile")
		}
		need(t, CreateProfile(path, config))
	})
}
