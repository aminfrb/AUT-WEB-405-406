package proxy

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

var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

// protectedProxy is the same chain main.go builds: JWT check, then proxy.
func protectedProxy(t *testing.T, backendURL string) (http.Handler, *jwt.Manager) {
	t.Helper()
	tokens, err := jwt.NewManager(jwt.Config{
		Key: make([]byte, 32), Issuer: "jwt-proxy", Audience: "legacy-httpbin", TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	target, _ := url.Parse(backendURL)
	return auth.RequireJWT(tokens, "legacy-httpbin", discardLogger)(New(target, discardLogger)), tokens
}

func TestProxyForwardsAndRewritesHeaders(t *testing.T) {
	// A fake legacy service that reports what it received.
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Collect the user header in every spelling, the way a CGI/PHP backend would see it.
		var users []string
		for name, values := range r.Header {
			if strings.EqualFold(strings.ReplaceAll(name, "_", "-"), UserHeader) {
				users = append(users, values...)
			}
		}
		json.NewEncoder(w).Encode(map[string]string{
			"path":          r.URL.RequestURI(),
			"host":          r.Host,
			"authorization": r.Header.Get("Authorization"),
			"user":          strings.Join(users, ","),
			"forwardedFor":  r.Header.Get("X-Forwarded-For"),
			"forwardedHost": r.Header.Get("X-Forwarded-Host"),
		})
	}))
	defer backend.Close()
	handler, tokens := protectedProxy(t, backend.URL)
	token, _, _ := tokens.Issue("amin")

	req := httptest.NewRequest("GET", "http://public.example/anything?x=1", nil)
	req.RemoteAddr = "203.0.113.7:51234"
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set(UserHeader, "admin")                   // spoofing attempt
	req.Header["X_authenticated_user"] = []string{"root"} // same attempt with underscores
	req.Header.Set("X-Forwarded-For", "10.10.10.10")      // spoofing attempt

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body %s)", rec.Code, rec.Body)
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{
		"path":          "/anything?x=1",  // path and query are kept
		"host":          "public.example", // public Host kept, so backend links point to the proxy
		"authorization": "",               // the token is not leaked to the backend
		"user":          "amin",           // only the identity from the token, in any spelling
		"forwardedFor":  "203.0.113.7",    // real client IP; the spoofed value is dropped
		"forwardedHost": "public.example",
	}
	for field, w := range want {
		if got[field] != w {
			t.Errorf("backend saw %s = %q, want %q", field, got[field], w)
		}
	}
}

func TestRequestWithoutTokenNeverReachesBackend(t *testing.T) {
	called := false
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer backend.Close()
	handler, _ := protectedProxy(t, backend.URL)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("DELETE", "/anything", nil))
	if rec.Code != http.StatusUnauthorized || called {
		t.Errorf("status = %d, backend called = %v; want 401 and no call", rec.Code, called)
	}
}

// The first part of a slow response must reach the client before the backend
// has finished, even when the backend declared a Content-Length.
func TestProxyStreamsWithoutBuffering(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "2")
		io.WriteString(w, "a")
		w.(http.Flusher).Flush()
		<-release // hold the second byte until the client has seen the first
		io.WriteString(w, "b")
	}))
	defer backend.Close()
	handler, tokens := protectedProxy(t, backend.URL)
	front := httptest.NewServer(handler)
	defer front.Close()
	// Deferred calls run in reverse order: release the backend first, so the
	// servers above can finish their open request and close.
	defer close(release)

	token, _, _ := tokens.Issue("amin")
	req, _ := http.NewRequest("GET", front.URL+"/drip", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	// The whole request runs in a goroutine: a buffering proxy would hold back
	// even the headers, and Do itself would block.
	first := make(chan byte, 1)
	go func() {
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		defer res.Body.Close()
		b := make([]byte, 1)
		if _, err := io.ReadFull(res.Body, b); err == nil {
			first <- b[0]
		}
	}()
	select {
	case b := <-first:
		if b != 'a' {
			t.Errorf("first byte = %q, want 'a'", b)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first byte did not arrive: the proxy is buffering the response")
	}
}

func TestProxyReturns504WhenBackendIsTooSlow(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release // never answer in time
	}))
	defer backend.Close()
	defer close(release) // runs first: lets the backend handler return so Close does not wait

	target, _ := url.Parse(backend.URL)
	rp := New(target, discardLogger)
	rp.Transport.(*http.Transport).ResponseHeaderTimeout = 50 * time.Millisecond // 30s in production

	rec := httptest.NewRecorder()
	rp.ServeHTTP(rec, httptest.NewRequest("GET", "/delay/10", nil))
	if rec.Code != http.StatusGatewayTimeout {
		t.Errorf("status = %d, want 504", rec.Code)
	}
}

func TestProxyReturns502WhenBackendIsDown(t *testing.T) {
	backend := httptest.NewServer(http.NotFoundHandler())
	backend.Close() // nothing is listening any more
	handler, tokens := protectedProxy(t, backend.URL)
	token, _, _ := tokens.Issue("amin")

	req := httptest.NewRequest("GET", "/get", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", rec.Code)
	}
}
