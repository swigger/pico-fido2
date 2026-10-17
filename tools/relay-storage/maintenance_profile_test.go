package storage

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/rclone/rclone/fs/config/obscure"
)

func textPointer(s string) *string { return &s }

func TestMaintenancePatchCannotChangeStorageBinding(t *testing.T) {
	p := oauthProfileFixture(t, "onedrive")
	p.Provider.Options["token"] = `{"access_token":"fixture-old","refresh_token":"fixture-refresh"}`
	p.Provider.Options["drive_id"], p.Provider.Options["drive_type"] = "fixture-drive", "personal"
	for _, key := range []string{"drive_id", "drive_type", "region", "scope", "root_folder_id", "team_drive", "user", "url"} {
		other := p
		other.Provider.Options = mapsClone(p.Provider.Options)
		other.Provider.Options[key] = "different"
		if sameCloudBinding(p, other) {
			t.Fatalf("changed %s binding accepted", key)
		}
	}
	for _, change := range []func(*CloudProfile){
		func(c *CloudProfile) { c.Namespace = "00000000000000000000000000000001" },
		func(c *CloudProfile) { c.Provider.Provider = "drive" },
		func(c *CloudProfile) { c.Provider.Root = "another-root" },
		func(c *CloudProfile) { c.Coordinator.ClusterID = "0000000000000001" },
	} {
		other := p
		change(&other)
		if sameCloudBinding(p, other) {
			t.Fatal("changed storage identity accepted")
		}
	}
	next, err := maintenancePatch(p, ProfileMaintenance{Action: "oauth", ClientID: textPointer("replacement-public-client")})
	need(t, err)
	if next.Provider.Options["client_secret"] != "" || p.Provider.Options["client_secret"] == "" {
		t.Fatal("new client inherited old secret or mutated original")
	}
	if _, err := maintenancePatch(p, ProfileMaintenance{Action: "oauth", Secret: textPointer("mixed")}); err == nil {
		t.Fatal("mixed action accepted")
	}
	wrong := p.Coordinator
	wrong.ClusterID = "0000000000000001"
	if _, err := maintenancePatch(p, ProfileMaintenance{Action: "coordinator", Coordinator: &wrong}); err == nil {
		t.Fatal("coordinator replacement changed cluster")
	}
}

func TestMaintenanceProtocolRejectsWrongRolesAndMalformedPatches(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.dpapi")
	p := profileFixture(t)
	need(t, CreateProfile(path, p))
	before, err := os.ReadFile(path)
	need(t, err)
	for _, op := range []byte{PipeOpen, PipeOpenCached, PipeProfile, PipeEnrollStart, PipeEnrollAnswer, PipeEnrollPoll, PipeMaintain} {
		input, write := io.Pipe()
		read, output := io.Pipe()
		pipe := &pipeTestClient{input: write, output: read, done: make(chan error, 1), next: 1}
		go func() {
			pipe.done <- ServeMaintenance(context.Background(), input, output, path, webdavSpace)
			input.Close()
			output.Close()
		}()
		if reply := pipe.request(t, op, []byte(`{"action":"oauth","token":"fictional-secret-must-not-echo"}`)); !bytes.Equal(reply, []byte{1}) {
			t.Fatal("maintenance role/patch accepted or echoed")
		}
		pipe.finish(t, false)
		write.Close()
		read.Close()
	}
	after, err := os.ReadFile(path)
	need(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("invalid maintenance modified profile")
	}
	profile, err := OpenProfile(path, webdavSpace)
	need(t, err)
	profile.Close()
}

func testProfileMaintenance(t *testing.T, coordinator CoordinatorConfig, dav *davFixture, path string, ca fixtureCA) {
	t.Helper()
	ctx := context.Background()
	original, err := os.ReadFile(path)
	need(t, err)
	encode := func(p ProfileMaintenance) []byte { data, err := json.Marshal(p); need(t, err); return data }
	unchanged := func() {
		data, err := os.ReadFile(path)
		need(t, err)
		if !bytes.Equal(data, original) {
			t.Fatal("failed/canceled maintenance changed profile")
		}
	}
	patch := ProfileMaintenance{Action: "webdav", Secret: textPointer(davPassword)}
	for _, action := range []string{"cancel", "wrong-password", "occupied", "changed-profile"} {
		t.Run(action, func(t *testing.T) {
			request := patch
			if action == "wrong-password" {
				request.Secret = textPointer("fictional-incorrect-password")
			}
			session, reply, err := beginMaintenance(ctx, path, webdavSpace, encode(request))
			need(t, err)
			defer session.close()
			if reply[0] != enrollReview {
				t.Fatal("maintenance skipped review")
			}
			if second, err := OpenProfile(path, webdavSpace); err == nil {
				second.Close()
				t.Fatal("review did not retain local profile lock")
			}
			unchanged()
			answer := "save"
			if action == "cancel" {
				answer = "cancel"
			}
			if action == "occupied" {
				client, err := OpenCoordinator(ctx, coordinator)
				need(t, err)
				defer client.Close()
				remote := davObjects(t, dav)
				defer remote.Close()
				owner, err := Acquire(ctx, client, remote, webdavSpace, false)
				need(t, err)
				defer owner.Close()
			}
			if action == "changed-profile" {
				changed := bytes.Clone(original)
				changed[len(changed)-1] ^= 1
				need(t, os.WriteFile(path, changed, 0600))
			}
			if _, err := session.advance(answer); err == nil {
				t.Fatal("invalid maintenance succeeded")
			}
			session.close()
			if action == "changed-profile" {
				changed, err := os.ReadFile(path)
				need(t, err)
				if changed[len(changed)-1] != original[len(original)-1]^1 {
					t.Fatal("maintenance overwrote unexpected replacement")
				}
				need(t, os.WriteFile(path, original, 0600))
			}
			unchanged()
		})
	}
	// Exercise the production child and wire protocol through the explicit review.
	helper := startHelperProcess(t, path, webdavSpace, "--maintain-pipe")
	if reply := helper.request(t, PipeMaintain, encode(patch)); len(reply) < 2 || reply[0] != 0 || reply[1] != enrollReview {
		t.Fatal("maintenance child review")
	}
	if reply := helper.request(t, PipeEnrollAnswer, []byte("save")); !bytes.Equal(reply, []byte{0, enrollDone}) {
		t.Fatal("maintenance child save")
	}
	helper.finish(t, true)
	profile, err := OpenProfile(path, webdavSpace)
	need(t, err)
	saved, err := profile.Config()
	need(t, err)
	profile.Close()
	password, err := obscure.Reveal(saved.Provider.Options["pass"])
	need(t, err)
	if password != davPassword || saved.Coordinator.ClusterID != coordinator.ClusterID {
		t.Fatal("maintenance changed identity or lost password")
	}
	// An expired certificate remains unreadable to ordinary sessions, but can be
	// decoded under the maintenance lock and replaced after real TLS/RBAC checks.
	expired := saved
	expired.Coordinator.ClientCertPEM, expired.Coordinator.ClientKeyPEM = ca.leaf(t, "fixture", false, true)
	expired.Provider.Options = mapsClone(saved.Provider.Options)
	expired.Provider.Options["pass"], err = obscure.Obscure("fictional-expired-webdav-password")
	need(t, err)
	text, err := json.Marshal(expired)
	need(t, err)
	cipher, err := protectProfile(append(bytes.Clone(profileMagic), text...), webdavSpace)
	need(t, err)
	need(t, os.WriteFile(path, cipher, 0600))
	if ordinary, err := OpenProfile(path, webdavSpace); err == nil {
		ordinary.Close()
		t.Fatal("ordinary session accepted expired identity")
	}
	request := ProfileMaintenance{Action: "webdav", Secret: textPointer(davPassword), Coordinator: &coordinator}
	session, reply, err := beginMaintenance(ctx, path, webdavSpace, encode(request))
	need(t, err)
	if reply[0] != enrollReview {
		t.Fatal("expired identity replacement skipped review")
	}
	_, err = session.advance("save")
	need(t, err)
	session.close()
	profile, err = OpenProfile(path, webdavSpace)
	need(t, err)
	profile.Close()
	stored, err := os.ReadFile(path)
	need(t, err)
	if bytes.Contains(stored, []byte(davPassword)) || bytes.Contains(stored, []byte("PRIVATE KEY")) {
		t.Fatal("maintenance stored plaintext")
	}
	// Reauthorization cancellation holds and releases the same protected profile.
	oauth := oauthProfileFixture(t, "drive")
	oauth.Coordinator = coordinator
	oauth.Provider.Options["token"] = `{"access_token":"fixture-old","refresh_token":"fixture-refresh"}`
	oauthPath := filepath.Join(t.TempDir(), "existing-oauth.dpapi")
	need(t, CreateProfile(oauthPath, oauth))
	before, err := os.ReadFile(oauthPath)
	need(t, err)
	session, reply, err = beginMaintenance(ctx, oauthPath, webdavSpace, encode(ProfileMaintenance{Action: "oauth"}))
	need(t, err)
	if reply[0] != enrollBrowser {
		t.Fatal("reauthorization reused old token")
	}
	session.close()
	after, err := os.ReadFile(oauthPath)
	need(t, err)
	if !bytes.Equal(before, after) {
		t.Fatal("canceled reauthorization changed profile")
	}
	profile, err = OpenProfile(oauthPath, webdavSpace)
	need(t, err)
	profile.Close()
}
