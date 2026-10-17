package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

func callbackRequest(t *testing.T, redirect string, values url.Values, host string) (int, string) {
	t.Helper()
	request, err := http.NewRequest("GET", redirect+"?"+values.Encode(), nil)
	need(t, err)
	if host != "" {
		request.Host = host
	}
	client := &http.Client{Timeout: 2 * time.Second}
	response, err := client.Do(request)
	need(t, err)
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	need(t, err)
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("callback response cache policy")
	}
	return response.StatusCode, string(body)
}
func TestBrowserOAuthPKCEStateAndCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var calls atomic.Int32
	exchanged := make(chan struct{}, 1)
	finish := make(chan struct{})
	var expected atomic.Value
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			http.Error(w, "bad", 400)
			return
		}
		hash := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		values := expected.Load().([2]string)
		if r.Form.Get("code") != "fictional-authorization-code" || r.Form.Get("grant_type") != "authorization_code" ||
			r.Form.Get("redirect_uri") != values[1] || base64.RawURLEncoding.EncodeToString(hash[:]) != values[0] {
			t.Error("PKCE exchange mismatch")
			http.Error(w, "bad", 400)
			return
		}
		exchanged <- struct{}{}
		select {
		case <-finish:
		case <-ctx.Done():
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"fictional-access","refresh_token":"fictional-refresh","token_type":"Bearer","expires_in":3600}`)
	}))
	defer server.Close()
	config := &oauth2.Config{ClientID: "fixture-desktop", ClientSecret: "fixture-client-secret", RedirectURL: "http://127.0.0.1:53682/",
		Endpoint: oauth2.Endpoint{AuthURL: "https://accounts.google.com/o/oauth2/auth", TokenURL: server.URL, AuthStyle: oauth2.AuthStyleInParams}, Scopes: []string{"fixture"}}
	grant, err := beginBrowserGrant(ctx, config, server.Client())
	need(t, err)
	defer grant.close()
	auth, err := url.Parse(grant.URL)
	need(t, err)
	params := auth.Query()
	state := params.Get("state")
	challenge := params.Get("code_challenge")
	redirect := params.Get("redirect_uri")
	expected.Store([2]string{challenge, redirect})
	if len(state) < 40 || len(challenge) < 40 || params.Get("code_challenge_method") != "S256" || params.Get("access_type") != "offline" || params.Get("response_type") != "code" {
		t.Fatal("OAuth request lacks PKCE/state/offline authorization")
	}
	for _, values := range []url.Values{{"state": {"wrong"}, "code": {"fictional-authorization-code"}}, {"state": {state, state}, "code": {"code"}},
		{"state": {state}, "code": {"one", "two"}}, {"state": {state}, "code": {"code"}, "error": {"denied"}}} {
		if status, _ := callbackRequest(t, redirect, values, ""); status != 400 {
			t.Fatal("invalid OAuth callback accepted")
		}
	}
	good := url.Values{"state": {state}, "code": {"fictional-authorization-code"}}
	if status, _ := callbackRequest(t, redirect, good, "evil.invalid"); status != 400 {
		t.Fatal("foreign callback Host accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid callback contacted token endpoint")
	}
	if status, body := callbackRequest(t, redirect, good, ""); status != 200 || strings.Contains(body, state) || strings.Contains(body, "fictional") {
		t.Fatal("callback status or code leakage")
	}
	select {
	case <-exchanged:
	case <-ctx.Done():
		t.Fatal("no token exchange")
	}
	if status, _ := callbackRequest(t, redirect, good, ""); status != 409 {
		t.Fatal("OAuth callback replay accepted")
	}
	close(finish)
	select {
	case result := <-grant.result:
		if result.err != nil || result.token.RefreshToken != "fictional-refresh" {
			t.Fatal("valid OAuth failed")
		}
	case <-ctx.Done():
		t.Fatal("OAuth exchange did not finish")
	}
	if calls.Load() != 1 {
		t.Fatal("authorization code exchanged repeatedly")
	}
	for _, denied := range []bool{false, true} {
		grant, err := beginBrowserGrant(ctx, config, server.Client())
		need(t, err)
		if denied {
			u, err := url.Parse(grant.URL)
			need(t, err)
			_, _ = callbackRequest(t, u.Query().Get("redirect_uri"), url.Values{"state": {u.Query().Get("state")}, "error": {"access_denied"}}, "")
		} else {
			grant.close()
		}
		select {
		case result := <-grant.result:
			if result.err == nil || result.token != nil {
				t.Fatal("canceled OAuth succeeded")
			}
		case <-ctx.Done():
			t.Fatal("OAuth cancellation blocked")
		}
		grant.close()
	}
	if calls.Load() != 1 {
		t.Fatal("denial or cancellation exchanged a code")
	}
}

func TestBrowserOAuthFailedExchangeDoesNotRetryOrFollowRedirect(t *testing.T) {
	var escaped atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped.Add(1)
		http.Error(w, "must not follow", 500)
	}))
	defer destination.Close()
	for _, mode := range []string{"rejected", "missing-refresh", "malformed", "redirect", "untrusted-tls"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var calls atomic.Int32
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Content-Type", "application/json")
				switch mode {
				case "redirect":
					http.Redirect(w, r, destination.URL, http.StatusTemporaryRedirect)
				case "missing-refresh":
					_, _ = io.WriteString(w, `{"access_token":"fictional-access","token_type":"Bearer","expires_in":3600}`)
				case "malformed":
					_, _ = io.WriteString(w, `{"access_token":`)
				default:
					http.Error(w, `{"error":"invalid_grant","error_description":"fictional-secret-must-not-leak"}`, 400)
				}
			}))
			defer server.Close()
			client := oauthHTTPClient(ctx)
			if mode != "untrusted-tls" {
				client.Transport = server.Client().Transport
			}
			config := &oauth2.Config{ClientID: "fixture", RedirectURL: "http://127.0.0.1/",
				Endpoint: oauth2.Endpoint{AuthURL: "https://accounts.google.com/o/oauth2/auth", TokenURL: server.URL, AuthStyle: oauth2.AuthStyleInParams}}
			grant, err := beginBrowserGrant(ctx, config, client)
			need(t, err)
			defer grant.close()
			auth, err := url.Parse(grant.URL)
			need(t, err)
			q := auth.Query()
			if status, _ := callbackRequest(t, q.Get("redirect_uri"), url.Values{"state": {q.Get("state")}, "code": {"fictional-code"}}, ""); status != 200 {
				t.Fatal("well-formed callback rejected")
			}
			select {
			case result := <-grant.result:
				if !errors.Is(result.err, errEnrollment) || result.token != nil {
					t.Fatal("failed exchange succeeded or leaked provider error")
				}
			case <-ctx.Done():
				t.Fatal("failed exchange blocked")
			}
			expected := int32(1)
			if mode == "untrusted-tls" {
				expected = 0
			}
			if calls.Load() != expected || escaped.Load() != 0 {
				t.Fatal("exchange retried, bypassed TLS, or followed a token redirect")
			}
		})
	}
}
