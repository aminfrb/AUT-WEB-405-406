// Command jwt-proxy is a reverse proxy that puts JWT authentication in front
// of a legacy HTTP service that has no authentication of its own.
//
// Usage:
//
//	jwt-proxy                  run the proxy (configured by environment variables)
//	jwt-proxy hash-password    read a password from stdin, print its hash for users.json
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"jwtproxy/internal/auth"
	"jwtproxy/internal/jwt"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "hash-password" {
		os.Exit(hashPassword(os.Stdin, os.Stdout, os.Stderr))
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("proxy stopped", "err", err.Error())
		os.Exit(1)
	}
}

// run loads the configuration, starts the server and blocks until it stops.
func run(logger *slog.Logger) error {
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	users, err := auth.LoadUsers(cfg.UsersFile)
	if err != nil {
		return err
	}
	tokens, err := jwt.NewManager(jwt.Config{
		Key:      cfg.JWTSecret,
		Issuer:   cfg.Issuer,
		Audience: cfg.Audience,
		TTL:      cfg.TokenTTL,
		Leeway:   30 * time.Second,
	})
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: newHandler(cfg, users, tokens, logger),
		// Timeouts protect against slow or idle clients holding connections
		// open forever (e.g. the Slowloris attack).
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    64 << 10,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}

	// Stop gracefully on Ctrl+C or `docker stop` (SIGTERM).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		logger.Info("proxy listening", "addr", cfg.ListenAddr, "upstream", cfg.UpstreamURL.String(),
			"tls", cfg.tlsEnabled(), "users", users.Len())
		if cfg.tlsEnabled() {
			serveErr <- srv.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			serveErr <- srv.ListenAndServe()
		}
	}()

	select {
	case err := <-serveErr: // could not start, e.g. the port is in use
		return err
	case <-ctx.Done():
	}

	logger.Info("shutting down, waiting for open requests to finish")
	// 8s: finish before Docker's default 10s stop grace period ends in SIGKILL.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return err
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// hashPassword implements the `hash-password` sub-command.
func hashPassword(stdin io.Reader, stdout, stderr io.Writer) int {
	fmt.Fprintln(stderr, "Password (read from stdin):")
	line, err := bufio.NewReader(stdin).ReadString('\n')
	password := strings.TrimRight(line, "\r\n")
	if (err != nil && err != io.EOF) || password == "" {
		fmt.Fprintln(stderr, "error: no password given")
		return 1
	}
	hash, err := auth.HashPassword(password, auth.DefaultIterations)
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		return 1
	}
	fmt.Fprintln(stdout, hash)
	return 0
}
