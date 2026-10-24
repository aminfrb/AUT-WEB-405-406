package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"jwtproxy/internal/httpjson"
	"jwtproxy/internal/jwt"
)

// TokenVerifier checks a token (implemented by *jwt.Manager).
type TokenVerifier interface {
	Verify(token string) (*jwt.Claims, error)
}

// contextKey is unexported, so no other package can overwrite our value.
type contextKey struct{}

// ClaimsFrom returns the claims that RequireJWT stored on the request context.
func ClaimsFrom(ctx context.Context) (*jwt.Claims, bool) {
	claims, ok := ctx.Value(contextKey{}).(*jwt.Claims)
	return claims, ok
}

// RequireJWT lets a request through only if it carries a valid bearer token.
// Rejected requests get 401 and a WWW-Authenticate header (RFC 6750 §3).
func RequireJWT(verifier TokenVerifier, realm string, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok {
				// No credentials at all: RFC 6750 says to send no error code.
				w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer realm=%q", realm))
				httpjson.Error(w, http.StatusUnauthorized, "missing_token",
					"send the header: Authorization: Bearer <token> (get one from POST /auth/login)")
				return
			}

			claims, err := verifier.Verify(token)
			if err != nil {
				logger.Info("token rejected", "reason", err.Error(), "remote", r.RemoteAddr, "path", r.URL.Path)
				// The header gets a fixed text only: err may contain bytes from
				// the attacker's token, which must not be copied into a header.
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(
					"Bearer realm=%q, error=\"invalid_token\", error_description=%q", realm, describe(err)))
				httpjson.Error(w, http.StatusUnauthorized, "invalid_token", err.Error())
				return
			}

			// Store the claims so the proxy can pass the user name to the backend.
			ctx := context.WithValue(r.Context(), contextKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// describe turns a verification error into a short, fixed, header-safe text.
// An expired token is worth naming: the client should simply log in again.
func describe(err error) string {
	if errors.Is(err, jwt.ErrExpired) {
		return "token expired"
	}
	return "token invalid"
}

// bearerToken extracts <token> from "Bearer <token>". The scheme name is
// case-insensitive (RFC 9110 §11.1).
func bearerToken(header string) (string, bool) {
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}
