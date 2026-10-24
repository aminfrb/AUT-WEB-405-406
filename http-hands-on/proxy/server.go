package main

import (
	"io"
	"log/slog"
	"net/http"
	"time"

	"jwtproxy/internal/auth"
	"jwtproxy/internal/jwt"
	"jwtproxy/internal/proxy"
)

// newHandler builds the routing table of the proxy:
//
//	GET  /healthz     public, for liveness checks
//	POST /auth/login  public, exchanges username+password for a JWT
//	*    /...         everything else needs a valid JWT and goes to the legacy service
func newHandler(cfg config, users *auth.UserStore, tokens *jwt.Manager, logger *slog.Logger) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "ok\n")
	})
	mux.Handle("/auth/login", auth.LoginHandler(users, tokens, cfg.Audience, logger))

	requireJWT := auth.RequireJWT(tokens, cfg.Audience, logger)
	mux.Handle("/", requireJWT(proxy.New(cfg.UpstreamURL, logger)))

	return accessLog(logger, mux)
}

// accessLog writes one log line per request: method, path, status, duration.
func accessLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
		)
	})
}

// statusRecorder remembers the status code a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK // Write without WriteHeader means 200
	}
	return r.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the real writer, so streaming
// (Flush) and protocol upgrades such as WebSocket (Hijack) still work.
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }
