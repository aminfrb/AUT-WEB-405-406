package auth

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"jwtproxy/internal/jwt"
)

// Tests use a low iteration count; production hashes use DefaultIterations.
const testIterations = 1_000

var discardLogger = slog.New(slog.NewTextHandler(io.Discard, nil))

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := HashPassword(password, testIterations)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestPasswordHashing(t *testing.T) {
	h := mustHash(t, "correct horse")
	if !CheckPassword("correct horse", h) {
		t.Error("correct password rejected")
	}
	if CheckPassword("wrong horse", h) {
		t.Error("wrong password accepted")
	}
	if h2 := mustHash(t, "correct horse"); h2 == h {
		t.Error("two hashes of the same password are equal; salt is not random")
	}
	for _, bad := range []string{"", "plain-text", "md5$1$abc$def", "pbkdf2-sha256$x$c2FsdA$a2V5", "pbkdf2-sha256$0$c2FsdA$a2V5"} {
		if CheckPassword("anything", bad) {
			t.Errorf("CheckPassword accepted malformed hash %q", bad)
		}
	}
}

func TestUserStore(t *testing.T) {
	store, err := NewUserStore(map[string]string{"amin": mustHash(t, "s3cret")})
	if err != nil {
		t.Fatal(err)
	}
	if !store.Authenticate("amin", "s3cret") {
		t.Error("valid credentials rejected")
	}
	if store.Authenticate("amin", "nope") || store.Authenticate("ghost", "s3cret") {
		t.Error("invalid credentials accepted")
	}
	if _, err := NewUserStore(map[string]string{"x": "not-a-hash"}); err == nil {
		t.Error("store accepted a plain-text password")
	}
	if _, err := NewUserStore(nil); err == nil {
		t.Error("store accepted an empty user list")
	}
}

// --- login endpoint ---------------------------------------------------------

type fakeIssuer struct{}

func (fakeIssuer) Issue(subject string) (string, time.Time, error) {
	return "token-for-" + subject, time.Now().Add(15 * time.Minute), nil
}

func TestLoginHandler(t *testing.T) {
	store, _ := NewUserStore(map[string]string{"amin": mustHash(t, "s3cret")})
	handler := LoginHandler(store, fakeIssuer{}, "legacy-httpbin", discardLogger)

	tests := []struct {
		name, method, body string
		wantStatus         int
		wantError          string
	}{
		{"success", "POST", `{"username":"amin","password":"s3cret"}`, 200, ""},
		{"wrong password", "POST", `{"username":"amin","password":"x"}`, 401, "invalid_credentials"},
		{"unknown user", "POST", `{"username":"ghost","password":"s3cret"}`, 401, "invalid_credentials"},
		{"not json", "POST", `username=amin`, 400, "invalid_request"},
		{"missing password", "POST", `{"username":"amin"}`, 400, "invalid_request"},
		{"unknown field", "POST", `{"username":"amin","password":"s3cret","admin":true}`, 400, "invalid_request"},
		{"trailing data", "POST", `{"username":"amin","password":"s3cret"} garbage`, 400, "invalid_request"},
		{"too large", "POST", `{"username":"` + strings.Repeat("a", maxLoginBody) + `","password":"x"}`, 400, "invalid_request"},
		{"GET not allowed", "GET", "", 405, "method_not_allowed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, httptest.NewRequest(tt.method, "/auth/login", strings.NewReader(tt.body)))
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", rec.Code, tt.wantStatus, rec.Body)
			}
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("response is not JSON: %s", rec.Body)
			}
			if tt.wantError != "" && body["error"] != tt.wantError {
				t.Errorf("error = %v, want %q", body["error"], tt.wantError)
			}
			if tt.wantStatus == 401 && rec.Header().Get("WWW-Authenticate") == "" {
				t.Error("a 401 response must carry WWW-Authenticate (RFC 9110)")
			}
			if tt.wantStatus == 200 {
				if body["access_token"] != "token-for-amin" || body["token_type"] != "Bearer" {
					t.Errorf("unexpected token response: %v", body)
				}
				if rec.Header().Get("Cache-Control") != "no-store" {
					t.Error("token response must not be cacheable")
				}
			}
		})
	}
}

// --- middleware -------------------------------------------------------------

func TestRequireJWT(t *testing.T) {
	tokens, err := jwt.NewManager(jwt.Config{
		Key: []byte(strings.Repeat("s", 32)), Issuer: "jwt-proxy", Audience: "legacy-httpbin", TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	valid, _, _ := tokens.Issue("amin")
	// Same key, but a 1ns lifetime. "exp" is stored in whole seconds (rounded
	// down), so this token is already expired when it is issued.
	shortLived, _ := jwt.NewManager(jwt.Config{
		Key: []byte(strings.Repeat("s", 32)), Issuer: "jwt-proxy", Audience: "legacy-httpbin", TTL: time.Nanosecond,
	})
	expired, _, _ := shortLived.Issue("amin")

	// The protected handler reports which user the middleware let through.
	protected := RequireJWT(tokens, "legacy-httpbin", discardLogger)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			claims, _ := ClaimsFrom(r.Context())
			io.WriteString(w, claims.Subject)
		}))

	tests := []struct {
		name, authorization string
		wantStatus          int
		wantChallenge       string // substring expected in WWW-Authenticate
	}{
		{"valid token", "Bearer " + valid, 200, ""},
		{"scheme is case-insensitive", "bearer " + valid, 200, ""},
		{"no header", "", 401, `Bearer realm="legacy-httpbin"`},
		{"basic auth instead", "Basic YW1pbjpzM2NyZXQ=", 401, `Bearer realm="legacy-httpbin"`},
		{"empty token", "Bearer ", 401, `Bearer realm="legacy-httpbin"`},
		{"garbage token", "Bearer not.a.jwt", 401, `error="invalid_token", error_description="token invalid"`},
		{"tampered token", "Bearer " + valid[:len(valid)-2] + "xx", 401, `error="invalid_token"`},
		// The token's own "alg" text must not be echoed into the header.
		{"alg none", "Bearer eyJhbGciOiJub25lIn0.e30.", 401, `error_description="token invalid"`},
		{"expired token", "Bearer " + expired, 401, `error_description="token expired"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/get", nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}
			rec := httptest.NewRecorder()
			protected.ServeHTTP(rec, req)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if tt.wantStatus == 200 && rec.Body.String() != "amin" {
				t.Errorf("handler saw user %q, want amin", rec.Body)
			}
			if got := rec.Header().Get("WWW-Authenticate"); !strings.Contains(got, tt.wantChallenge) {
				t.Errorf("WWW-Authenticate = %q, want it to contain %q", got, tt.wantChallenge)
			}
		})
	}
}
