package server

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// passthroughHandler is the protected handler under test. If a request reaches
// it, the middleware allowed it through.
var passthroughHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
})

func TestAuthMiddleware_NoTokenSet_IsPassthrough(t *testing.T) {
	t.Setenv(authTokenEnvVar, "")

	h := authMiddleware(newTestLogger(), passthroughHandler)

	for _, path := range []string{"/health", "/v1/messages", "/v1/messages/count_tokens"} {
		req := httptest.NewRequest(http.MethodPost, path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("path=%s: expected passthrough 200, got %d", path, rec.Code)
		}
	}
}

func TestAuthMiddleware_HealthAlwaysExempt(t *testing.T) {
	t.Setenv(authTokenEnvVar, "secret")
	h := authMiddleware(newTestLogger(), passthroughHandler)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected /health to bypass auth (200), got %d", rec.Code)
	}
}

func TestAuthMiddleware_MissingToken_Returns401JSON(t *testing.T) {
	t.Setenv(authTokenEnvVar, "secret")
	h := authMiddleware(newTestLogger(), passthroughHandler)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected JSON content type, got %q", ct)
	}
	if !strings.Contains(rec.Body.String(), `"authentication_error"`) {
		t.Fatalf("expected JSON error body, got %q", rec.Body.String())
	}
}

func TestAuthMiddleware_WrongToken_Returns401(t *testing.T) {
	t.Setenv(authTokenEnvVar, "secret")
	h := authMiddleware(newTestLogger(), passthroughHandler)

	cases := []struct {
		name   string
		header string
		value  string
	}{
		{"bearer-wrong", "Authorization", "Bearer wrong"},
		{"bearer-prefix-only", "Authorization", "Bearer "},
		{"bearer-no-prefix", "Authorization", "secret"},
		{"x-api-key-wrong", "x-api-key", "wrong"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
			req.Header.Set(c.header, c.value)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401, got %d", rec.Code)
			}
		})
	}
}

func TestAuthMiddleware_CorrectBearer_Allowed(t *testing.T) {
	t.Setenv(authTokenEnvVar, "secret")
	h := authMiddleware(newTestLogger(), passthroughHandler)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with correct bearer, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestAuthMiddleware_BearerCaseInsensitive(t *testing.T) {
	t.Setenv(authTokenEnvVar, "secret")
	h := authMiddleware(newTestLogger(), passthroughHandler)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("Authorization", "bearer secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with lowercase bearer scheme, got %d", rec.Code)
	}
}

func TestAuthMiddleware_XApiKey_Allowed(t *testing.T) {
	t.Setenv(authTokenEnvVar, "secret")
	h := authMiddleware(newTestLogger(), passthroughHandler)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("x-api-key", "secret")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with correct x-api-key, got %d body=%q", rec.Code, rec.Body.String())
	}
}
