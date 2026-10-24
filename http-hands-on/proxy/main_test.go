package main

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"jwtproxy/internal/auth"
	"jwtproxy/internal/jwt"
)

// TestFullFlow drives the real handler the way a client would:
// no token → 401, login → token, token → request reaches the legacy service.
func TestFullFlow(t *testing.T) {
	legacy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hello "+r.Header.Get("X-Authenticated-User")+" from "+r.URL.Path)
	}))
	defer legacy.Close()

	upstream, _ := url.Parse(legacy.URL)
	cfg := config{UpstreamURL: upstream, Audience: "legacy-httpbin"}
	hash, _ := auth.HashPassword("s3cret", 1_000)
	users, _ := auth.NewUserStore(map[string]string{"amin": hash})
	tokens, _ := jwt.NewManager(jwt.Config{Key: make([]byte, 32), Issuer: "jwt-proxy", Audience: "legacy-httpbin", TTL: time.Minute})
	proxy := httptest.NewServer(newHandler(cfg, users, tokens, slog.New(slog.NewTextHandler(io.Discard, nil))))
	defer proxy.Close()

	// 1) Health check is public.
	if res := mustDo(t, "GET", proxy.URL+"/healthz", "", ""); res.StatusCode != 200 {
		t.Fatalf("/healthz = %d", res.StatusCode)
	}

	// 2) Without a token the legacy service is not reachable.
	if res := mustDo(t, "GET", proxy.URL+"/get", "", ""); res.StatusCode != 401 {
		t.Fatalf("no token: status %d, want 401", res.StatusCode)
	}

	// 3) Log in.
	res := mustDo(t, "POST", proxy.URL+"/auth/login", "", `{"username":"amin","password":"s3cret"}`)
	if res.StatusCode != 200 {
		t.Fatalf("login: status %d", res.StatusCode)
	}
	var login struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(res.Body).Decode(&login)

	// 4) With the token the request goes through.
	res = mustDo(t, "GET", proxy.URL+"/get", login.AccessToken, "")
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != 200 || string(body) != "hello amin from /get" {
		t.Fatalf("with token: status %d, body %q", res.StatusCode, body)
	}
}

func mustDo(t *testing.T, method, url, token, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { res.Body.Close() })
	return res
}

func TestLoadConfig(t *testing.T) {
	env := map[string]string{
		"UPSTREAM_URL": "http://httpbin:8081",
		"JWT_SECRET":   strings.Repeat("x", 48),
	}
	cfg, err := loadConfig(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("valid env rejected: %v", err)
	}
	if cfg.ListenAddr != ":8080" || cfg.TokenTTL != 15*time.Minute || cfg.UpstreamURL.Host != "httpbin:8081" {
		t.Errorf("unexpected defaults: %+v", cfg)
	}

	// Everything wrong at once: all problems are reported together.
	bad := map[string]string{"UPSTREAM_URL": "httpbin", "JWT_SECRET": "short", "TOKEN_TTL": "soon", "TLS_CERT_FILE": "cert.pem"}
	_, err = loadConfig(func(k string) string { return bad[k] })
	for _, want := range []string{"UPSTREAM_URL", "JWT_SECRET", "TOKEN_TTL", "TLS_KEY_FILE"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not mention %s", err, want)
		}
	}
}

func TestHashPasswordCommand(t *testing.T) {
	var out, errOut strings.Builder
	if code := hashPassword(strings.NewReader("s3cret\n"), &out, &errOut); code != 0 {
		t.Fatalf("exit code %d: %s", code, errOut.String())
	}
	if !auth.CheckPassword("s3cret", strings.TrimSpace(out.String())) {
		t.Error("printed hash does not match the password")
	}
}
