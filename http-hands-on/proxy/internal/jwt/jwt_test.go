package jwt

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const testKey = "test-secret-that-is-at-least-32-bytes-long"

// fixedNow is the moment every test pretends it is.
var fixedNow = time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)

func newTestManager(t *testing.T) *Manager {
	t.Helper()
	m, err := NewManager(Config{
		Key:      []byte(testKey),
		Issuer:   "jwt-proxy",
		Audience: "legacy-httpbin",
		TTL:      15 * time.Minute,
		Leeway:   30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return fixedNow }
	return m
}

// encodeRaw builds a token from arbitrary header/claims maps, so tests can
// create tokens our own Issue would never produce.
func encodeRaw(t *testing.T, m *Manager, hdr, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(hdr)
	c, _ := json.Marshal(claims)
	input := b64.EncodeToString(h) + "." + b64.EncodeToString(c)
	return input + "." + b64.EncodeToString(m.mac(input))
}

func validClaims() map[string]any {
	return map[string]any{
		"sub": "student",
		"iss": "jwt-proxy",
		"aud": "legacy-httpbin",
		"iat": fixedNow.Unix(),
		"exp": fixedNow.Add(time.Minute).Unix(),
	}
}

func TestIssueThenVerify(t *testing.T) {
	m := newTestManager(t)
	token, exp, err := m.Issue("student")
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Equal(fixedNow.Add(15 * time.Minute)) {
		t.Errorf("expiresAt = %v, want now+15m", exp)
	}
	claims, err := m.Verify(token)
	if err != nil {
		t.Fatalf("Verify(own token) = %v", err)
	}
	if claims.Subject != "student" || claims.ID == "" {
		t.Errorf("unexpected claims: %+v", claims)
	}
}

// Tokens made by another implementation (PyJWT 2.15) must verify too; this
// shows we follow the standard rather than just agreeing with ourselves.
func TestVerifyTokenFromPyJWT(t *testing.T) {
	m := newTestManager(t)
	vectors := map[string]string{
		"aud as string": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdHVkZW50IiwiaXNzIjoiand0LXByb3h5IiwiYXVkIjoibGVnYWN5LWh0dHBiaW4iLCJpYXQiOjE3NjEwMDAwMDAsIm5iZiI6MTc2MTAwMDAwMCwiZXhwIjo0MTAyNDQ0ODAwLCJqdGkiOiJweWp3dC12ZWN0b3IifQ.OEKvxPGWeUwHimid7WmkNEQYrIym-VpI6Q_l9eb6Kxc",
		"aud as array":  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzdHVkZW50IiwiaXNzIjoiand0LXByb3h5IiwiYXVkIjpbIm90aGVyLXNlcnZpY2UiLCJsZWdhY3ktaHR0cGJpbiJdLCJpYXQiOjE3NjEwMDAwMDAsIm5iZiI6MTc2MTAwMDAwMCwiZXhwIjo0MTAyNDQ0ODAwLCJqdGkiOiJweWp3dC12ZWN0b3IifQ.8RpVAXRs9BxnZzbSMT01bxkTAMSNkAT5_NQtQ1X-vfA",
	}
	for name, token := range vectors {
		t.Run(name, func(t *testing.T) {
			claims, err := m.Verify(token)
			if err != nil {
				t.Fatalf("Verify = %v", err)
			}
			if claims.Subject != "student" || claims.ID != "pyjwt-vector" {
				t.Errorf("unexpected claims: %+v", claims)
			}
		})
	}
}

func TestVerifyRejects(t *testing.T) {
	m := newTestManager(t)
	good := encodeRaw(t, m, map[string]any{"alg": "HS256", "typ": "JWT"}, validClaims())
	parts := strings.Split(good, ".")

	with := func(key string, value any) map[string]any {
		c := validClaims()
		if value == nil {
			delete(c, key)
		} else {
			c[key] = value
		}
		return c
	}
	hs256 := map[string]any{"alg": "HS256"}

	otherKey, _ := NewManager(Config{Key: []byte(strings.Repeat("k", 32)), Issuer: "jwt-proxy", Audience: "legacy-httpbin", TTL: time.Minute})

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"empty", "", ErrMalformed},
		{"two parts", parts[0] + "." + parts[1], ErrMalformed},
		{"garbage base64", "!!!." + parts[1] + "." + parts[2], ErrMalformed},
		{"padded base64", parts[0] + "=." + parts[1] + "." + parts[2], ErrMalformed},
		{"too long", strings.Repeat("a", maxTokenLength+1), ErrMalformed},
		// Valid token with a line break inside: base64 alone would ignore it.
		{"newline inside", parts[0] + "." + parts[1] + "." + parts[2][:5] + "\r\n" + parts[2][5:], ErrMalformed},
		// "alg":"none" with an empty signature is the textbook JWT attack.
		{"alg none", b64.EncodeToString([]byte(`{"alg":"none"}`)) + "." + parts[1] + ".", ErrAlgorithm},
		{"alg HS512", encodeRaw(t, m, map[string]any{"alg": "HS512"}, validClaims()), ErrAlgorithm},
		{"alg RS256", encodeRaw(t, m, map[string]any{"alg": "RS256"}, validClaims()), ErrAlgorithm},
		{"crit header", encodeRaw(t, m, map[string]any{"alg": "HS256", "crit": []string{"exp"}}, validClaims()), ErrMalformed},
		{"tampered payload", parts[0] + "." + b64.EncodeToString([]byte(`{"sub":"admin","iss":"jwt-proxy","aud":"legacy-httpbin","exp":4102444800}`)) + "." + parts[2], ErrSignature},
		{"signed with another key", func() string { tok, _, _ := otherKey.Issue("student"); return tok }(), ErrSignature},
		{"missing exp", encodeRaw(t, m, hs256, with("exp", nil)), ErrMalformed},
		{"expired beyond leeway", encodeRaw(t, m, hs256, with("exp", fixedNow.Add(-31*time.Second).Unix())), ErrExpired},
		{"not yet valid", encodeRaw(t, m, hs256, with("nbf", fixedNow.Add(time.Minute).Unix())), ErrNotYetValid},
		{"wrong issuer", encodeRaw(t, m, hs256, with("iss", "evil")), ErrIssuer},
		{"wrong audience", encodeRaw(t, m, hs256, with("aud", "another-service")), ErrAudience},
		{"no audience", encodeRaw(t, m, hs256, with("aud", nil)), ErrAudience},
		{"no subject", encodeRaw(t, m, hs256, with("sub", nil)), ErrMissingSubject},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := m.Verify(tt.token)
			if !errors.Is(err, tt.want) {
				t.Errorf("Verify() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestLeewayAcceptsSmallClockSkew(t *testing.T) {
	m := newTestManager(t)
	c := validClaims()
	c["exp"] = fixedNow.Add(-10 * time.Second).Unix() // expired 10s ago, leeway is 30s
	if _, err := m.Verify(encodeRaw(t, m, map[string]any{"alg": "HS256"}, c)); err != nil {
		t.Errorf("Verify() = %v, want nil inside leeway", err)
	}
}

func TestNewManagerValidatesConfig(t *testing.T) {
	ok := Config{Key: []byte(testKey), Issuer: "i", Audience: "a", TTL: time.Minute}
	bad := map[string]func(c *Config){
		"short key":   func(c *Config) { c.Key = []byte("short") },
		"no issuer":   func(c *Config) { c.Issuer = "" },
		"no audience": func(c *Config) { c.Audience = "" },
		"zero ttl":    func(c *Config) { c.TTL = 0 },
	}
	if _, err := NewManager(ok); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for name, mutate := range bad {
		c := ok
		mutate(&c)
		if _, err := NewManager(c); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
