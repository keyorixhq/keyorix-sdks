package keyorix

import (
	"context"
	"errors"
	"fmt"
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
			w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"proj"}]}}`))
		case "/api/v1/projects/1/environments":
			w.Write([]byte(`{"data":{"environments":[{"id":1,"name":"prod","project_id":1}]}}`))
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

// TestErrorForResponse_MapsStatusToTypedError proves every request path
// (not just one hand-picked call site) returns a typed error that
// errors.As can distinguish, for the three statuses callers most need to
// branch on. Exercised through ListProjects (a representative GET call);
// errorForResponse itself is what every other method funnels through too.
func TestErrorForResponse_MapsStatusToTypedError(t *testing.T) {
	cases := []struct {
		status int
		check  func(t *testing.T, err error)
	}{
		{http.StatusUnauthorized, func(t *testing.T, err error) {
			var authErr *AuthError
			if !errors.As(err, &authErr) {
				t.Fatalf("expected *AuthError, got %T (%v)", err, err)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
				t.Errorf("expected Unwrap to reach *APIError with StatusCode 401, got %+v", apiErr)
			}
		}},
		{http.StatusForbidden, func(t *testing.T, err error) {
			var forbidden *ForbiddenError
			if !errors.As(err, &forbidden) {
				t.Fatalf("expected *ForbiddenError, got %T (%v)", err, err)
			}
		}},
		{http.StatusNotFound, func(t *testing.T, err error) {
			var notFound *NotFoundError
			if !errors.As(err, &notFound) {
				t.Fatalf("expected *NotFoundError, got %T (%v)", err, err)
			}
		}},
	}

	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			c, err := New(srv.URL, "test-token")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			_, err = c.ListProjects(context.Background())
			if err == nil {
				t.Fatal("expected an error")
			}
			tc.check(t, err)
		})
	}
}

// A value read the secret's own state refuses (server ERRMAP-1): 409 with a
// secret-state code is a *SecretUnavailableError carrying that Code; a schedule
// refusal stays a *ForbiddenError (callers already handle it) but says what it is.
// Neither error text echoes the server's body.
func TestErrorForResponse_SecretReadRefusals(t *testing.T) {
	for _, tc := range []struct {
		status      int
		code, want  string
		unavailable bool
	}{
		{http.StatusConflict, CodeSecretExpired, "has expired", true},
		{http.StatusConflict, CodeSecretSuspended, "is suspended", true},
		{http.StatusConflict, CodeSecretMaxReadsExhausted, "maximum number of reads", true},
		{http.StatusForbidden, CodeSecretAccessOutsideSchedule, "outside its access schedule", false},
		{http.StatusConflict, "ConflictError", "server returned 409", false},
	} {
		t.Run(tc.code, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprintf(w, `{"success":false,"code":%d,"error":%q,"message":"SERVER-TEXT"}`, tc.status, tc.code)
			}))
			defer srv.Close()
			c, err := New(srv.URL, "test-token")
			if err != nil {
				t.Fatal(err)
			}
			_, err = c.GetSecretByRef(context.Background(), "p/e/n")
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "SERVER-TEXT") {
				t.Fatalf("error %v: want text %q and no server text", err, tc.want)
			}
			var unavailable *SecretUnavailableError
			if errors.As(err, &unavailable) != tc.unavailable {
				t.Fatalf("errors.As(*SecretUnavailableError) = %v, want %v (%T)", !tc.unavailable, tc.unavailable, err)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Code != tc.code {
				t.Fatalf("APIError.Code = %+v, want %q", apiErr, tc.code)
			}
			if tc.status == http.StatusForbidden {
				var forbidden *ForbiddenError
				if !errors.As(err, &forbidden) {
					t.Fatalf("a schedule refusal must stay a *ForbiddenError, got %T", err)
				}
			}
		})
	}
}
