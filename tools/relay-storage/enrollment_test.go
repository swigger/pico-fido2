package storage

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/config/configmap"
	"golang.org/x/oauth2"
)

// A test-only HTTPS CONNECT proxy supplies synthetic Microsoft Graph responses.
// Real rclone discovery still verifies its HTTPS hostname against this fixture CA.
// No production endpoint override or TLS bypass is introduced.
func graphProxy(t *testing.T) (string, string, *atomic.Int32) {
	t.Helper()
	ca := authority(t)
	cert := &x509.Certificate{SerialNumber: big.NewInt(77), DNSNames: []string{"graph.microsoft.com"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, ca.cert, &ca.key.PublicKey, ca.key)
	need(t, err)
	raw, err := x509.MarshalPKCS8PrivateKey(ca.key)
	need(t, err)
	pair, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}))
	need(t, err)
	caPath := filepath.Join(t.TempDir(), "graph-ca.pem")
	need(t, os.WriteFile(caPath, []byte(ca.pem), 0600))
	var mutex sync.Mutex
	var connections []net.Conn
	calls := new(atomic.Int32)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "graph.microsoft.com:443" {
			t.Error("unexpected proxy destination")
			http.Error(w, "denied", 403)
			return
		}
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		mutex.Lock()
		connections = append(connections, connection)
		mutex.Unlock()
		_, _ = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\n")
		secure := tls.Server(connection, &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12})
		defer secure.Close()
		reader := bufio.NewReader(secure)
		for {
			request, err := http.ReadRequest(reader)
			if err != nil {
				return
			}
			calls.Add(1)
			response := httptest.NewRecorder()
			response.Header().Set("Content-Type", "application/json")
			if request.Header.Get("Authorization") != "Bearer fictional-enrollment-access" {
				t.Error("Graph bearer token mismatch")
				response.WriteHeader(401)
			} else {
				switch request.URL.Path {
				case "/v1.0/me/drives":
					_, _ = io.WriteString(response, `{"value":[{"id":"fixture-drive","name":"Personal fixture","driveType":"personal"},{"id":"fixture-business","name":"Business fixture","driveType":"business"}]}`)
				case "/v1.0/me/drive":
					_, _ = io.WriteString(response, `{"id":"fixture-drive","name":"Personal fixture","driveType":"personal"}`)
				case "/v1.0/drives/fixture-drive/root":
					_, _ = io.WriteString(response, `{"id":"root","name":"Fixture root","webUrl":"https://example.invalid/fixture","parentReference":{"driveId":"fixture-drive","driveType":"personal"}}`)
				default:
					t.Errorf("unexpected Graph path %s", request.URL.Path)
					response.WriteHeader(404)
				}
			}
			request.Body.Close()
			result := response.Result()
			result.ContentLength = int64(response.Body.Len())
			if err := result.Write(secure); err != nil {
				return
			}
		}
	}))
	t.Cleanup(func() {
		proxy.Close()
		mutex.Lock()
		defer mutex.Unlock()
		for _, connection := range connections {
			connection.Close()
		}
	})
	return proxy.URL, caPath, calls
}

func oauthProfileFixture(t *testing.T, provider string) CloudProfile {
	p := profileFixture(t)
	p.Provider = ProviderConfig{Provider: provider, Root: "pico-fido2", Options: map[string]string{"client_id": "fictional-desktop-client", "client_secret": "fictional-desktop-secret"}}
	if provider == "drive" {
		p.Provider.Options["scope"] = "drive.file"
	} else {
		p.Provider.Options["region"] = "global"
	}
	return p
}

func TestRcloneEnrollmentDiscoveryAndProtectedSave(t *testing.T) {
	for _, provider := range []string{"drive", "onedrive"} {
		t.Run(provider, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			path := filepath.Join(t.TempDir(), "enrolled.dpapi")
			profile := oauthProfileFixture(t, provider)
			need(t, validateEnrollment(profile))
			session, err := newEnrollment(ctx, path, profile)
			need(t, err)
			defer session.close()
			var challenge atomic.Value
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if err := r.ParseForm(); err != nil {
					t.Error(err)
					http.Error(w, "bad", 400)
					return
				}
				hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
				if r.Form.Get("code") != "synthetic-code" || challenge.Load() != base64.RawURLEncoding.EncodeToString(hash[:]) {
					t.Error("enrollment PKCE mismatch")
					http.Error(w, "bad", 400)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{"access_token":"fictional-enrollment-access","refresh_token":"fictional-enrollment-refresh","token_type":"Bearer","expires_in":3600}`)
			}))
			defer server.Close()
			session.startGrant = func(ctx context.Context, config *oauth2.Config) (*browserGrant, error) {
				if config.ClientID != "fictional-desktop-client" || config.ClientSecret != "fictional-desktop-secret" || config.Endpoint.AuthStyle != oauth2.AuthStyleInParams {
					t.Fatal("upstream client override lost")
				}
				copy := *config
				copy.Endpoint.TokenURL = server.URL
				return beginBrowserGrant(ctx, &copy, server.Client())
			}
			var calls *atomic.Int32
			if provider == "onedrive" {
				proxy, ca, count := graphProxy(t)
				calls = count
				ci := fs.GetConfig(session.ctx)
				ci.HTTPProxy = proxy
				ci.CaCert = []string{ca}
			}
			reply, err := session.advance("")
			need(t, err)
			if len(reply) < 2 || reply[0] != enrollBrowser {
				t.Fatal("no browser enrollment stage")
			}
			authorization, err := url.Parse(session.grant.URL)
			need(t, err)
			query := authorization.Query()
			challenge.Store(query.Get("code_challenge"))
			if status, _ := callbackRequest(t, query.Get("redirect_uri"), url.Values{"state": {query.Get("state")}, "code": {"synthetic-code"}}, ""); status != 200 {
				t.Fatal("valid enrollment callback rejected")
			}
			for {
				reply, err = session.poll()
				need(t, err)
				if reply[0] != enrollWaiting {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("enrollment did not finish")
				case <-time.After(5 * time.Millisecond):
				}
			}
			for reply[0] == enrollQuestion {
				var answer string
				switch session.question.Name {
				case "config_change_team_drive":
					answer = "false"
				case "config_type":
					answer = "onedrive"
				case "config_driveid":
					answer = "fixture-drive"
				case "config_drive_ok":
					answer = "true"
				default:
					t.Fatalf("unexpected upstream enrollment question %s", session.question.Name)
				}
				if bytes.Contains(reply, []byte("fictional-enrollment-access")) || bytes.Contains(reply, []byte("fictional-enrollment-refresh")) {
					t.Fatal("token entered UI response")
				}
				reply, err = session.advance(answer)
				need(t, err)
			}
			if reply[0] != enrollReview {
				t.Fatal("enrollment skipped explicit save review")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("profile written before final review")
			}
			reply, err = session.advance("save")
			need(t, err)
			if !bytes.Equal(reply, []byte{enrollDone}) {
				t.Fatal("profile save did not complete")
			}
			protected, err := OpenProfile(path, profile.Namespace)
			need(t, err)
			saved, err := protected.Config()
			need(t, err)
			protected.Close()
			if !strings.Contains(saved.Provider.Options["token"], "fictional-enrollment-refresh") || saved.Provider.Provider != provider {
				t.Fatal("OAuth profile did not persist")
			}
			cipher, err := os.ReadFile(path)
			need(t, err)
			if bytes.Contains(cipher, []byte("fictional")) || bytes.Contains(cipher, []byte("PRIVATE KEY")) {
				t.Fatal("plaintext OAuth profile on disk")
			}
			if provider == "onedrive" && (saved.Provider.Options["drive_id"] != "fixture-drive" || saved.Provider.Options["drive_type"] != "personal" || calls.Load() != 3) {
				t.Fatal("actual rclone Graph discovery failed")
			}
			if _, err = session.advance("save"); err == nil {
				t.Fatal("completed enrollment replayed")
			}
		})
	}
}

func TestEnrollmentFinalReviewAndConcurrentProfileCreation(t *testing.T) {
	for _, action := range []string{"cancel", "concurrent-save"} {
		t.Run(action, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "profile.dpapi")
			p := oauthProfileFixture(t, "drive")
			session, err := newEnrollment(context.Background(), path, p)
			need(t, err)
			defer session.close()
			// Token exchange is covered separately; this injects an already
			// authorized result at the provider's completion boundary.
			session.configure = func(_ context.Context, _ string, mapper configmap.Mapper, _ fs.ConfigIn) (*fs.ConfigOut, error) {
				mapper.Set("token", `{"access_token":"fictional-access","refresh_token":"fictional-refresh"}`)
				return nil, nil
			}
			reply, err := session.advance("")
			need(t, err)
			if reply[0] != enrollReview {
				t.Fatal("save review missing")
			}
			answer := "cancel"
			var original []byte
			if action == "concurrent-save" {
				original = []byte("existing-profile-must-not-be-replaced")
				need(t, os.WriteFile(path, original, 0600))
				answer = "save"
			}
			if _, err := session.advance(answer); err == nil {
				t.Fatal("canceled or conflicting profile save succeeded")
			}
			data, err := os.ReadFile(path)
			if original == nil {
				if !os.IsNotExist(err) {
					t.Fatal("cancel wrote a profile")
				}
			} else if err != nil || !bytes.Equal(data, original) {
				t.Fatal("concurrently created profile changed")
			}
		})
	}
}

func TestEnrollmentPipeRejectsWrongRoleOrderAndBounds(t *testing.T) {
	start := func(t *testing.T) *pipeTestClient {
		input, write := io.Pipe()
		read, output := io.Pipe()
		client := &pipeTestClient{input: write, output: read, done: make(chan error, 1), next: 1}
		path := filepath.Join(t.TempDir(), "never-created.dpapi")
		go func() {
			client.done <- ServeEnrollment(context.Background(), input, output, path, webdavSpace)
			input.Close()
			output.Close()
		}()
		t.Cleanup(func() { write.Close(); read.Close() })
		return client
	}
	for _, op := range []byte{PipeOpen, PipeOpenCached, PipeRead, PipeCheck, PipeCommit, PipeProfile, PipeMaintain, PipeEnrollAnswer, PipeEnrollPoll, PipeEnrollStart} {
		pipe := start(t)
		if reply := pipe.request(t, op, []byte("fictional-secret-malformed-input")); !bytes.Equal(reply, []byte{1}) {
			t.Fatal("wrong-role/order request succeeded or echoed its body")
		}
		pipe.finish(t, false)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { binary.LittleEndian.PutUint32(b[8:12], profileLimit+1) },
		func(b []byte) { binary.LittleEndian.PutUint64(b[16:], 2) },
	} {
		pipe := start(t)
		header := requestBytes(PipeEnrollStart, 1, nil)
		mutate(header)
		_, _ = pipe.input.Write(header)
		pipe.finish(t, false)
	}
	pipe := start(t)
	pipe.input.Close()
	pipe.finish(t, false)
}

func TestEnrollmentInputBoundsAndRegionEndpoints(t *testing.T) {
	p := oauthProfileFixture(t, "drive")
	for _, field := range []string{"token", "auth_url", "token_url", "service_account_file", "command"} {
		bad := p
		bad.Provider.Options = mapsClone(p.Provider.Options)
		bad.Provider.Options[field] = "fixture"
		if validateEnrollment(bad) == nil {
			t.Fatal("unsafe enrollment option accepted")
		}
	}
	bad := p
	bad.Provider.Options = mapsClone(p.Provider.Options)
	delete(bad.Provider.Options, "client_id")
	if validateEnrollment(bad) == nil {
		t.Fatal("retiring shared Google client allowed")
	}
	for _, region := range []string{"global", "us", "de", "cn"} {
		p := oauthProfileFixture(t, "onedrive")
		p.Provider.Options["region"] = region
		session, err := newEnrollment(context.Background(), filepath.Join(t.TempDir(), "none.dpapi"), p)
		need(t, err)
		reply, err := session.advance("")
		need(t, err)
		if reply[0] != enrollBrowser {
			t.Fatal("region OAuth config failed")
		}
		session.close()
	}
	session, err := newEnrollment(context.Background(), filepath.Join(t.TempDir(), "none.dpapi"), p)
	need(t, err)
	session.close()
	if _, err := session.advance(""); err == nil {
		t.Fatal("canceled enrollment resumed")
	}
	if _, err := appendEnrollmentString(nil, strings.Repeat("x", 8193)); err == nil {
		t.Fatal("oversized UI string accepted")
	}
}

func testOAuthEnrollmentProtocol(t *testing.T, coordinator CoordinatorConfig) {
	t.Helper()
	p := oauthProfileFixture(t, "drive")
	p.Coordinator = coordinator
	path := filepath.Join(t.TempDir(), "oauth-profile.dpapi")
	encoded, err := json.Marshal(ProfileSetup{Profile: p})
	need(t, err)
	helper := startHelperProcess(t, path, p.Namespace, "--enroll-pipe")
	reply := helper.request(t, PipeEnrollStart, encoded)
	if len(reply) < 6 || reply[0] != 0 || reply[1] != enrollBrowser || int(binary.LittleEndian.Uint32(reply[2:6])) != len(reply)-6 {
		t.Fatal("actual helper OAuth browser stage invalid")
	}
	authorization, err := url.Parse(string(reply[6:]))
	need(t, err)
	if authorization.Host != "accounts.google.com" || authorization.Query().Get("code_challenge_method") != "S256" {
		t.Fatal("actual helper OAuth endpoint or PKCE invalid")
	}
	if reply := helper.request(t, PipeEnrollPoll, nil); !bytes.Equal(reply, []byte{0, enrollWaiting}) {
		t.Fatal("actual helper did not wait for browser")
	}
	if reply := helper.request(t, PipeClose, nil); !bytes.Equal(reply, []byte{0}) {
		t.Fatal("actual helper failed to cancel enrollment")
	}
	helper.finish(t, true)
	for _, name := range []string{path, path + ".lock"} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatal("canceled OAuth initialized a profile")
		}
	}
	client := &http.Client{Timeout: time.Second}
	if response, err := client.Get(authorization.Query().Get("redirect_uri")); err == nil {
		response.Body.Close()
		t.Fatal("closed helper left OAuth listener running")
	}
}
