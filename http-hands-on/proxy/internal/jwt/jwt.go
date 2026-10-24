// Package jwt implements the small part of JSON Web Tokens (RFC 7519) that the
// proxy needs: issuing and verifying tokens signed with HS256 (HMAC-SHA256,
// RFC 7518 §3.2).
//
// Only ONE algorithm is supported, and it is chosen by the server, never by the
// token. Trusting the "alg" field of an incoming token is the classic JWT bug
// ("alg": "none", or RS256→HS256 key confusion), so we reject anything else.
package jwt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Errors returned by Verify. Callers can tell them apart with errors.Is.
var (
	ErrMalformed      = errors.New("token is malformed")
	ErrAlgorithm      = errors.New("unexpected signing algorithm")
	ErrSignature      = errors.New("signature is invalid")
	ErrExpired        = errors.New("token has expired")
	ErrNotYetValid    = errors.New("token is not valid yet")
	ErrIssuer         = errors.New("unexpected issuer")
	ErrAudience       = errors.New("unexpected audience")
	ErrMissingSubject = errors.New("token has no subject")
)

const (
	algorithm = "HS256"

	// MinKeyLength is the shortest accepted secret. RFC 7518 §3.2 requires an
	// HS256 key to be at least as long as the hash output: 256 bits = 32 bytes.
	MinKeyLength = 32

	// maxTokenLength stops us from spending work on absurdly large inputs.
	maxTokenLength = 8 << 10 // 8 KiB
)

// JWTs use base64url without padding (RFC 7515 §2). Strict() also rejects
// non-canonical encodings, so one token cannot be written in two ways.
var b64 = base64.RawURLEncoding.Strict()

// header is the first, JOSE part of a token.
type header struct {
	Alg  string   `json:"alg"`
	Typ  string   `json:"typ,omitempty"`
	Crit []string `json:"crit,omitempty"`
}

// Audience is the "aud" claim. RFC 7519 §4.1.3 allows a single string or an
// array of strings, so it needs its own JSON decoding.
type Audience []string

// UnmarshalJSON accepts both "aud": "x" and "aud": ["x", "y"].
func (a *Audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = Audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return err
	}
	*a = many
	return nil
}

// MarshalJSON writes a single audience as a plain string, the common form.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// Claims are the registered claims (RFC 7519 §4.1) this service uses.
// Times are NumericDate values: whole seconds since the Unix epoch.
type Claims struct {
	Subject   string   `json:"sub"`
	Issuer    string   `json:"iss"`
	Audience  Audience `json:"aud"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf,omitempty"`
	ExpiresAt int64    `json:"exp"`
	ID        string   `json:"jti,omitempty"`
}

// Config holds everything needed to issue and verify tokens.
type Config struct {
	Key      []byte        // shared HMAC secret, at least MinKeyLength bytes
	Issuer   string        // "iss" we write into tokens and expect back
	Audience string        // "aud" we write into tokens and expect back
	TTL      time.Duration // lifetime of issued tokens
	Leeway   time.Duration // tolerated clock difference when checking exp/nbf
}

// Manager issues and verifies HS256 tokens.
type Manager struct {
	cfg Config
	now func() time.Time // replaced in tests to control the clock
}

// NewManager validates cfg and returns a ready Manager.
func NewManager(cfg Config) (*Manager, error) {
	if len(cfg.Key) < MinKeyLength {
		return nil, fmt.Errorf("jwt: key must be at least %d bytes, got %d", MinKeyLength, len(cfg.Key))
	}
	if cfg.Issuer == "" || cfg.Audience == "" {
		return nil, errors.New("jwt: issuer and audience must not be empty")
	}
	if cfg.TTL <= 0 {
		return nil, errors.New("jwt: TTL must be positive")
	}
	return &Manager{cfg: cfg, now: time.Now}, nil
}

// Issue creates a signed token for subject, valid from now until now+TTL.
func (m *Manager) Issue(subject string) (token string, expiresAt time.Time, err error) {
	now := m.now()
	expiresAt = now.Add(m.cfg.TTL)
	claims := Claims{
		Subject:   subject,
		Issuer:    m.cfg.Issuer,
		Audience:  Audience{m.cfg.Audience},
		IssuedAt:  now.Unix(),
		NotBefore: now.Unix(),
		ExpiresAt: expiresAt.Unix(),
		ID:        rand.Text(), // random 128-bit id, handy for logs and revocation
	}
	token, err = m.sign(claims)
	return token, expiresAt, err
}

// sign builds base64url(header) + "." + base64url(claims) + "." + base64url(HMAC).
func (m *Manager) sign(claims Claims) (string, error) {
	headerJSON, err := json.Marshal(header{Alg: algorithm, Typ: "JWT"})
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64.EncodeToString(headerJSON) + "." + b64.EncodeToString(claimsJSON)
	return signingInput + "." + b64.EncodeToString(m.mac(signingInput)), nil
}

// mac computes HMAC-SHA256 of the signing input with the shared secret.
func (m *Manager) mac(signingInput string) []byte {
	h := hmac.New(sha256.New, m.cfg.Key)
	h.Write([]byte(signingInput)) // hash.Hash.Write never returns an error
	return h.Sum(nil)
}

// Verify checks a token and returns its claims.
//
// The order is important: nothing in the payload is trusted until the
// signature has been checked, and the signature is checked only after we know
// the token claims to use our one allowed algorithm.
func (m *Manager) Verify(token string) (*Claims, error) {
	if len(token) > maxTokenLength {
		return nil, fmt.Errorf("%w: too long", ErrMalformed)
	}
	// Go's base64 decoder silently skips \r and \n, so check the alphabet
	// ourselves: a token may contain only base64url characters and dots.
	if strings.ContainsFunc(token, func(r rune) bool { return !isTokenChar(r) }) {
		return nil, fmt.Errorf("%w: invalid character", ErrMalformed)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: want 3 dot-separated parts, got %d", ErrMalformed, len(parts))
	}

	// 1) Header: only our fixed algorithm is acceptable.
	var h header
	if err := decodeSegment(parts[0], &h); err != nil {
		return nil, err
	}
	if h.Alg != algorithm {
		return nil, fmt.Errorf("%w: %q", ErrAlgorithm, h.Alg)
	}
	if h.Typ != "" && !strings.EqualFold(h.Typ, "JWT") {
		return nil, fmt.Errorf("%w: unexpected typ %q", ErrMalformed, h.Typ)
	}
	if len(h.Crit) > 0 {
		// RFC 7515 §4.1.11: we must reject extensions we do not understand.
		return nil, fmt.Errorf("%w: unsupported critical header", ErrMalformed)
	}

	// 2) Signature, compared in constant time so response timing leaks nothing.
	signature, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: bad signature encoding", ErrMalformed)
	}
	if !hmac.Equal(signature, m.mac(parts[0]+"."+parts[1])) {
		return nil, ErrSignature
	}

	// 3) Claims: we now know we issued this token; check it is still valid
	//    and that it was issued for this service.
	var c Claims
	if err := decodeSegment(parts[1], &c); err != nil {
		return nil, err
	}
	now := m.now()
	switch {
	case c.ExpiresAt == 0:
		return nil, fmt.Errorf("%w: missing exp claim", ErrMalformed)
	case !now.Before(time.Unix(c.ExpiresAt, 0).Add(m.cfg.Leeway)):
		return nil, ErrExpired
	case c.NotBefore != 0 && now.Before(time.Unix(c.NotBefore, 0).Add(-m.cfg.Leeway)):
		return nil, ErrNotYetValid
	case c.Issuer != m.cfg.Issuer:
		return nil, ErrIssuer
	case !slices.Contains(c.Audience, m.cfg.Audience):
		return nil, ErrAudience
	case c.Subject == "":
		return nil, ErrMissingSubject
	}
	return &c, nil
}

// isTokenChar reports whether r may appear in a compact JWT: A-Z a-z 0-9 - _ and "."
func isTokenChar(r rune) bool {
	return 'A' <= r && r <= 'Z' || 'a' <= r && r <= 'z' || '0' <= r && r <= '9' ||
		r == '-' || r == '_' || r == '.'
}

// decodeSegment base64url-decodes one token part and parses it as JSON.
func decodeSegment(segment string, v any) error {
	raw, err := b64.DecodeString(segment)
	if err != nil {
		return fmt.Errorf("%w: bad base64url", ErrMalformed)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("%w: bad JSON", ErrMalformed)
	}
	return nil
}
