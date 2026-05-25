package server

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"os"
	"strings"
)

const (
	authTokenEnvVar = "PROXY_AUTH_TOKEN"
	healthPath      = "/health"
)

// authMiddleware returns a middleware that requires a shared-secret bearer token
// matching PROXY_AUTH_TOKEN. The /health endpoint is exempt so platform
// healthchecks (e.g. Railway) work without credentials.
//
// If PROXY_AUTH_TOKEN is unset, the middleware is a passthrough no-op, which
// preserves the existing localhost-only workflow. A single warning is logged
// at startup in that case.
//
// The token may be provided either as `Authorization: Bearer <token>` or via
// the `x-api-key` header.
func authMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	expected := os.Getenv(authTokenEnvVar)
	if expected == "" {
		logger.Warn("PROXY_AUTH_TOKEN is not set; proxy auth is disabled (intended for local use only)")
		return next
	}

	expectedBytes := []byte(expected)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == healthPath {
			next.ServeHTTP(w, r)
			return
		}

		if !tokenMatches(r, expectedBytes) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"type":"authentication_error","message":"invalid or missing authentication token"}}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// tokenMatches reports whether the request carries a token equal to expected,
// using a constant-time comparison.
func tokenMatches(r *http.Request, expected []byte) bool {
	if h := r.Header.Get("Authorization"); h != "" {
		if token, ok := bearerToken(h); ok {
			if subtle.ConstantTimeCompare([]byte(token), expected) == 1 {
				return true
			}
		}
	}

	if h := r.Header.Get("x-api-key"); h != "" {
		if subtle.ConstantTimeCompare([]byte(h), expected) == 1 {
			return true
		}
	}

	return false
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(header string) (string, bool) {
	const prefix = "Bearer "
	if len(header) <= len(prefix) {
		return "", false
	}
	if !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	return header[len(prefix):], true
}
