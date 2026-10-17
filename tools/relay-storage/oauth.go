package storage

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rclone/rclone/fs/fshttp"
	"github.com/rclone/rclone/lib/oauthutil"
	"golang.org/x/oauth2"
)

var errEnrollment = errors.New("cloud enrollment failed or canceled")

// The OAuth implementation and token representation come from x/oauth2 and
// rclone. This small desktop adapter owns only the bounded loopback callback and
// lifecycle; it never handles the user's Google/Microsoft account password.
type browserGrant struct {
	URL    string
	cancel context.CancelFunc
	server *http.Server
	result chan grantResult
}
type grantResult struct {
	token *oauth2.Token
	err   error
}

func providerOAuthConfig(provider string, mapper *enrollmentMap, options *oauthutil.Options) (*oauth2.Config, error) {
	if options == nil || options.OAuth2Config == nil || options.OAuth2Config.ClientCredentialFlow {
		return nil, errEnrollment
	}
	config, _ := oauthutil.OverrideCredentials("pico-fido2-enrollment", mapper, options.OAuth2Config)
	allowed := map[string]bool{"accounts.google.com": true, "oauth2.googleapis.com": true}
	if provider == "onedrive" {
		allowed = map[string]bool{"login.microsoftonline.com": true, "login.microsoftonline.us": true,
			"login.microsoftonline.de": true, "login.chinacloudapi.cn": true}
	} else if provider != "drive" {
		return nil, errEnrollment
	}
	for _, endpoint := range []string{config.AuthURL, config.TokenURL} {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || !allowed[u.Host] || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return nil, errEnrollment
		}
	}
	redirect, err := url.Parse(config.RedirectURL)
	if err != nil || redirect.Scheme != "http" || (redirect.Hostname() != "localhost" && redirect.Hostname() != "127.0.0.1") ||
		redirect.Path != "/" || redirect.User != nil || redirect.RawQuery != "" || redirect.Fragment != "" {
		return nil, errEnrollment
	}
	result := config.MakeOauth2Config()
	// Both providers document form-encoded client credentials. Pin the style so
	// x/oauth2 never retries a rejected one-use code with different credentials.
	result.Endpoint.AuthStyle = oauth2.AuthStyleInParams
	return result, nil
}

func beginBrowserGrant(ctx context.Context, config *oauth2.Config, client *http.Client) (*browserGrant, error) {
	life, cancel := context.WithCancel(ctx)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		cancel()
		return nil, errEnrollment
	}
	cloned := *config
	redirect, err := url.Parse(cloned.RedirectURL)
	if err != nil {
		listener.Close()
		cancel()
		return nil, errEnrollment
	}
	redirect.Host = net.JoinHostPort(redirect.Hostname(), strings.Split(listener.Addr().String(), ":")[1])
	cloned.RedirectURL = redirect.String()
	stateBytes := make([]byte, 32)
	if _, err := rand.Read(stateBytes); err != nil {
		listener.Close()
		cancel()
		return nil, errEnrollment
	}
	state := base64.RawURLEncoding.EncodeToString(stateBytes)
	clear(stateBytes)
	verifier := oauth2.GenerateVerifier()
	grant := &browserGrant{cancel: cancel, result: make(chan grantResult, 1)}
	grant.URL = cloned.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("prompt", "consent"))
	codes := make(chan string, 1)
	var mutex sync.Mutex
	used := false
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		host, _, remoteErr := net.SplitHostPort(r.RemoteAddr)
		if remoteErr != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() || r.Host != redirect.Host ||
			r.Method != http.MethodGet || r.URL.Path != "/" || len(r.URL.RawQuery) > 16384 {
			http.Error(w, "Invalid authorization callback", http.StatusBadRequest)
			return
		}
		values, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil || len(values["state"]) != 1 || subtle.ConstantTimeCompare([]byte(values.Get("state")), []byte(state)) != 1 ||
			len(values["code"]) > 1 || len(values["error"]) > 1 {
			http.Error(w, "Invalid authorization callback", http.StatusBadRequest)
			return
		}
		code := values.Get("code")
		if (code == "") == (values.Get("error") == "") || len(code) > 4096 {
			http.Error(w, "Invalid authorization callback", http.StatusBadRequest)
			return
		}
		mutex.Lock()
		defer mutex.Unlock()
		if used {
			http.Error(w, "Authorization callback already received", http.StatusConflict)
			return
		}
		used = true
		select {
		case codes <- code:
		case <-life.Done():
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "Authorization received. Return to Pico FIDO. You may close this tab.")
	})
	grant.server = &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16384}
	go func() { _ = grant.server.Serve(listener) }()
	go func() {
		defer func() {
			// Let the callback's static response finish even when denial or a fast
			// token endpoint completes before its handler has returned.
			cleanup, done := context.WithTimeout(context.Background(), time.Second)
			defer done()
			_ = grant.server.Shutdown(cleanup)
			_ = grant.server.Close()
		}()
		var result grantResult
		select {
		case code := <-codes:
			if code == "" {
				result.err = errEnrollment
				break
			}
			exchange, done := context.WithTimeout(oauthutil.Context(life, client), 20*time.Second)
			result.token, result.err = cloned.Exchange(exchange, code, oauth2.VerifierOption(verifier))
			done()
			if result.err != nil || result.token == nil || result.token.AccessToken == "" || result.token.RefreshToken == "" || !result.token.Valid() {
				result = grantResult{err: errEnrollment}
			}
		case <-life.Done():
			result.err = errEnrollment
		}
		grant.result <- result
	}()
	return grant, nil
}
func (g *browserGrant) close() {
	if g != nil {
		g.cancel()
		_ = g.server.Close()
	}
}
func oauthHTTPClient(ctx context.Context) *http.Client {
	client := fshttp.NewClient(ctx)
	client.Timeout = 20 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errEnrollment }
	return client
}
