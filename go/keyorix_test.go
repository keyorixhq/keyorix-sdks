package keyorix

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	c, err := New("https://example.com:8080", "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.baseURL != "https://example.com:8080" {
		t.Errorf("expected baseURL https://example.com:8080, got %s", c.baseURL)
	}
	if c.token != "test-token" {
		t.Errorf("expected token test-token, got %s", c.token)
	}
	if c.httpClient == nil {
		t.Error("expected httpClient to be set")
	}
}

func TestWithTimeout(t *testing.T) {
	c, err := New("https://example.com:8080", "test-token", WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.httpClient.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %s", c.httpClient.Timeout)
	}
}

func TestNew_defaults(t *testing.T) {
	c, err := New("https://example.com:8080", "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.httpClient.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %s", c.httpClient.Timeout)
	}
}

func TestNew_allowsLoopbackHTTP(t *testing.T) {
	cases := []string{
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	}
	for _, u := range cases {
		if _, err := New(u, "test-token"); err != nil {
			t.Errorf("New(%q) unexpected error: %v", u, err)
		}
	}
}

func TestNew_rejectsNonLoopbackHTTP(t *testing.T) {
	if _, err := New("http://example.com:8080", "test-token"); err == nil {
		t.Error("expected error for non-loopback http:// URL, got nil")
	}
}

func TestNew_rejectsNonHTTPScheme(t *testing.T) {
	cases := []string{
		"file:///etc/passwd",
		"ftp://example.com",
	}
	for _, u := range cases {
		if _, err := New(u, "test-token"); err == nil {
			t.Errorf("New(%q) expected error, got nil", u)
		}
	}
}

func TestLogin_rejectsNonLoopbackHTTP(t *testing.T) {
	_, err := Login(context.Background(), "http://example.com:8080", "user", "pass")
	if err == nil {
		t.Error("expected error for non-loopback http:// URL, got nil")
	}
}

func TestAPIError_ErrorOmitsBody(t *testing.T) {
	err := &APIError{StatusCode: 500, Body: "<html>internal stack trace here</html>"}
	msg := err.Error()
	if msg != "keyorix: server returned 500" {
		t.Errorf("expected generic message, got %q", msg)
	}
	if strings.Contains(msg, "stack trace") {
		t.Error("Error() must not embed the raw response body")
	}
	if err.Body != "<html>internal stack trace here</html>" {
		t.Error("Body field should still carry the raw response body for callers who opt in")
	}
}

// TestListSecrets_Deprecated_NeverCallsServer covers the v0.3.0 removal: the
// deprecated environment-only ListSecrets must return its migration error
// without ever making a request — no silent fallback to the old, unscoped
// behavior it used to have.
func TestListSecrets_Deprecated_NeverCallsServer(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.ListSecrets(context.Background(), "production"); err == nil {
		t.Fatal("expected an error")
	} else if !strings.Contains(err.Error(), "ListSecretsScoped") {
		t.Errorf("expected error to point callers at ListSecretsScoped, got: %v", err)
	}
	if called {
		t.Error("ListSecrets must not contact the server at all")
	}
}

// TestGetSecret_Deprecated_NeverCallsServer is the GetSecret counterpart.
func TestGetSecret_Deprecated_NeverCallsServer(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.GetSecret(context.Background(), "db-password", "production"); err == nil {
		t.Fatal("expected an error")
	} else if !strings.Contains(err.Error(), "GetSecretScoped") {
		t.Errorf("expected error to point callers at GetSecretScoped, got: %v", err)
	}
	if called {
		t.Error("GetSecret must not contact the server at all")
	}
}

func TestListSecretsScoped_wrapsServerErrorWithoutLeakingBody(t *testing.T) {
	const raw = "internal: secret_key=super-sensitive-detail"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/projects":
			w.Write([]byte(`{"data":{"projects":[{"ID":1,"Name":"proj"}]}}`))
		case "/api/v1/projects/1/environments":
			w.Write([]byte(`{"data":{"environments":[{"ID":1,"Name":"prod","ProjectID":1}]}}`))
		default:
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(raw))
		}
	}))
	defer srv.Close()

	c, err := New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = c.ListSecretsScoped(context.Background(), ProjectByName("proj"), EnvironmentByName("prod"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if strings.Contains(err.Error(), raw) {
		t.Errorf("err.Error() leaked the raw response body: %v", err)
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected *APIError, got %T", err)
	}
	if apiErr.Body != raw {
		t.Errorf("expected APIError.Body to carry the raw body, got %q", apiErr.Body)
	}
}
