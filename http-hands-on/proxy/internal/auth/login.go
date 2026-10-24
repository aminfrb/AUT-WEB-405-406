package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"jwtproxy/internal/httpjson"
)

// maxLoginBody caps the request body; a login needs only a few dozen bytes.
const maxLoginBody = 4 << 10 // 4 KiB

// TokenIssuer creates a signed token for a user (implemented by *jwt.Manager).
type TokenIssuer interface {
	Issue(subject string) (token string, expiresAt time.Time, err error)
}

// tokenResponse uses the field names of an OAuth 2.0 token response
// (RFC 6749 §5.1), so standard clients already understand it.
type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"` // seconds
}

// LoginHandler serves POST /auth/login with body {"username": "...", "password": "..."}.
// On success it returns a JWT; the client sends it back as "Authorization: Bearer <token>".
// realm is the protection space named in the WWW-Authenticate header of a 401.
func LoginHandler(users *UserStore, issuer TokenIssuer, realm string, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			httpjson.Error(w, http.StatusMethodNotAllowed, "method_not_allowed", "use POST")
			return
		}

		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxLoginBody))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&req)
		if err == nil && decoder.Decode(&struct{}{}) != io.EOF {
			err = errors.New("unexpected data after the JSON object")
		}
		if err != nil || req.Username == "" || req.Password == "" {
			httpjson.Error(w, http.StatusBadRequest, "invalid_request",
				`body must be one JSON object: {"username": "...", "password": "..."}`)
			return
		}

		if !users.Authenticate(req.Username, req.Password) {
			logger.Warn("login failed", "user", req.Username, "remote", r.RemoteAddr)
			// RFC 9110 §15.5.2: every 401 must say how to authenticate.
			w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer realm=%q", realm))
			// One message for "no such user" and "wrong password", so the
			// response does not reveal which usernames exist.
			httpjson.Error(w, http.StatusUnauthorized, "invalid_credentials", "username or password is incorrect")
			return
		}

		token, expiresAt, err := issuer.Issue(req.Username)
		if err != nil {
			logger.Error("could not issue token", "err", err)
			httpjson.Error(w, http.StatusInternalServerError, "internal_error", "could not issue token")
			return
		}
		logger.Info("login succeeded", "user", req.Username, "remote", r.RemoteAddr)

		// A token is a credential: no browser or proxy cache may keep it.
		w.Header().Set("Cache-Control", "no-store")
		httpjson.Write(w, http.StatusOK, tokenResponse{
			AccessToken: token,
			TokenType:   "Bearer",
			ExpiresIn:   int64(time.Until(expiresAt).Round(time.Second).Seconds()),
		})
	})
}
