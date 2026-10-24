// Package proxy forwards authenticated requests to the legacy service.
package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"jwtproxy/internal/auth"
	"jwtproxy/internal/httpjson"
)

// UserHeader tells the legacy service which user the proxy authenticated.
const UserHeader = "X-Authenticated-User"

// New returns a reverse proxy that sends every request to target.
func New(target *url.URL, logger *slog.Logger) *httputil.ReverseProxy {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil                              // talk to the backend directly, ignore HTTP_PROXY variables
	transport.ResponseHeaderTimeout = 30 * time.Second // a hung backend must not hang the client forever

	return &httputil.ReverseProxy{
		Transport: transport,

		// Send every chunk to the client as soon as the backend writes it, so
		// slow or streamed responses arrive exactly as they would without the
		// proxy (by default only chunked and SSE responses are flushed early).
		FlushInterval: -1,

		// Rewrite builds the outgoing request (Out) from the incoming one (In).
		// Before calling it, ReverseProxy has already removed hop-by-hop headers
		// and any X-Forwarded-* headers the client tried to send.
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)  // scheme + host of the internal service
			pr.SetXForwarded() // X-Forwarded-For/Host/Proto: who the real client was

			// SetURL also sets the Host header to the internal address. Keep the
			// public one instead, so links and redirects the legacy service
			// builds from Host point to the proxy, not to "httpbin:8081".
			pr.Out.Host = pr.In.Host

			// The token has done its job at the edge. The legacy service does
			// not understand it and should never see the credential.
			pr.Out.Header.Del("Authorization")

			// Never trust an identity header that came from the internet;
			// only the proxy may set it, from a verified token.
			removeIdentityHeaders(pr.Out.Header)
			if claims, ok := auth.ClaimsFrom(pr.In.Context()); ok {
				pr.Out.Header.Set(UserHeader, claims.Subject)
			}
		},

		// Called when the backend cannot be reached or does not answer in time.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.Error("upstream request failed", "err", err.Error(), "path", r.URL.Path)
			if isTimeout(err) {
				httpjson.Error(w, http.StatusGatewayTimeout, "gateway_timeout", "the internal service did not answer in time")
				return
			}
			httpjson.Error(w, http.StatusBadGateway, "bad_gateway", "the internal service is not reachable")
		},
	}
}

// removeIdentityHeaders deletes every spelling of UserHeader. Many backends
// (CGI, PHP, Python WSGI, Ruby Rack) turn both "X-Authenticated-User" and
// "X_Authenticated_User" into the same variable HTTP_X_AUTHENTICATED_USER,
// so deleting only the dashed form would let a client smuggle in a fake user.
func removeIdentityHeaders(h http.Header) {
	for name := range h {
		if strings.EqualFold(strings.ReplaceAll(name, "_", "-"), UserHeader) {
			delete(h, name)
		}
	}
}

// isTimeout reports whether err means "the backend was too slow" (→ 504)
// rather than "the backend could not be reached" (→ 502).
func isTimeout(err error) bool {
	var netErr net.Error
	return errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout())
}
