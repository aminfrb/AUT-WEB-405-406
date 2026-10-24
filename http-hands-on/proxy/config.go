package main

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"jwtproxy/internal/jwt"
)

// config is read from environment variables (12-factor style), so the same
// image runs anywhere and secrets never live in the source code.
type config struct {
	ListenAddr  string   // LISTEN_ADDR, where the proxy listens
	UpstreamURL *url.URL // UPSTREAM_URL, the legacy service on the internal network
	JWTSecret   []byte   // JWT_SECRET, HMAC key, at least 32 bytes
	Issuer      string   // JWT_ISSUER
	Audience    string   // JWT_AUDIENCE, also used as the WWW-Authenticate realm
	TokenTTL    time.Duration
	UsersFile   string // USERS_FILE, JSON of username -> password hash
	TLSCertFile string // TLS_CERT_FILE + TLS_KEY_FILE: optional TLS termination
	TLSKeyFile  string
}

// loadConfig reads and validates the configuration. It reports every problem
// at once, so a misconfigured deployment can be fixed in one go.
func loadConfig(getenv func(string) string) (config, error) {
	get := func(key, fallback string) string {
		if v := getenv(key); v != "" {
			return v
		}
		return fallback
	}

	cfg := config{
		ListenAddr:  get("LISTEN_ADDR", ":8080"),
		JWTSecret:   []byte(getenv("JWT_SECRET")),
		Issuer:      get("JWT_ISSUER", "jwt-proxy"),
		Audience:    get("JWT_AUDIENCE", "legacy-httpbin"),
		UsersFile:   get("USERS_FILE", "/etc/jwt-proxy/users.json"),
		TLSCertFile: getenv("TLS_CERT_FILE"),
		TLSKeyFile:  getenv("TLS_KEY_FILE"),
	}
	var errs []error

	upstream, err := url.Parse(getenv("UPSTREAM_URL"))
	switch {
	case err != nil:
		errs = append(errs, fmt.Errorf("UPSTREAM_URL: %w", err))
	case upstream.Scheme != "http" && upstream.Scheme != "https", upstream.Host == "":
		errs = append(errs, errors.New("UPSTREAM_URL must look like http://host:port"))
	}
	cfg.UpstreamURL = upstream

	if len(cfg.JWTSecret) < jwt.MinKeyLength {
		errs = append(errs, fmt.Errorf("JWT_SECRET must be at least %d bytes (try: openssl rand -base64 48)", jwt.MinKeyLength))
	}

	cfg.TokenTTL, err = time.ParseDuration(get("TOKEN_TTL", "15m"))
	if err != nil || cfg.TokenTTL <= 0 {
		errs = append(errs, errors.New("TOKEN_TTL must be a positive duration such as 15m"))
	}

	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		errs = append(errs, errors.New("set both TLS_CERT_FILE and TLS_KEY_FILE, or neither"))
	}

	return cfg, errors.Join(errs...)
}

// tlsEnabled reports whether the proxy should terminate TLS itself.
func (c config) tlsEnabled() bool { return c.TLSCertFile != "" }
