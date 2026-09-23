package keyorix

import (
	"context"
	"encoding/json"
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

func TestListSecrets_wrapsServerErrorWithoutLeakingBody(t *testing.T) {
	const raw = "internal: secret_key=super-sensitive-detail"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(raw))
	}))
	defer srv.Close()

	c, err := New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = c.ListSecrets(context.Background(), "")
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

// TestListSecrets_NeverSendsEnvironmentQueryParam_FiltersClientSide covers the
// keyorix-sdks#35 fix: the server now returns 400 for a bare `environment`
// name query parameter (keyorix#2013), so ListSecrets must never send it, and
// must instead filter the (unscoped) response client-side by the
// environment_name field every secret already carries.
func TestListSecrets_NeverSendsEnvironmentQueryParam_FiltersClientSide(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("environment") != "" {
			t.Errorf("must never send the rejected 'environment' name query param, got %q", r.URL.RawQuery)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"secrets":[
			{"ID":1,"Name":"db-pass","Type":"password","ProjectID":1,"environment_name":"production","CreatedAt":"2026-01-01T00:00:00Z"},
			{"ID":2,"Name":"api-key","Type":"generic","ProjectID":1,"environment_name":"staging","CreatedAt":"2026-01-01T00:00:00Z"}
		]}}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	secrets, err := c.ListSecrets(context.Background(), "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 1 || secrets[0].Name != "db-pass" {
		t.Errorf("expected exactly the production secret, got %+v", secrets)
	}

	all, err := c.ListSecrets(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("expected both secrets for empty environment filter, got %d", len(all))
	}
}

// newInProjectTestServer stands up a mock server backing ListSecretsInProject/
// GetSecretInProject: one environment ("production", ID 7) in project
// projectID, and one secret ("db-pass") in that environment. It records every
// query string sent to /api/v1/secrets in *gotQueries.
func newInProjectTestServer(t *testing.T, projectID uint, gotQueries *[]string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(fmt.Sprintf("/api/v1/projects/%d/environments", projectID), func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":7,"ProjectID":1,"Name":"production"}]}}`))
	})
	mux.HandleFunc("/api/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		*gotQueries = append(*gotQueries, r.URL.RawQuery)
		if r.URL.Query().Get("environment") != "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"data":{"secrets":[
			{"ID":42,"Name":"db-pass","Type":"password","ProjectID":1,"environment_name":"production","CreatedAt":"2026-01-01T00:00:00Z"}
		]}}`))
	})
	mux.HandleFunc("/api/v1/secrets/42", func(w http.ResponseWriter, r *http.Request) {
		payload, _ := json.Marshal(map[string]interface{}{"data": map[string]string{"value": "s3cr3t"}})
		_, _ = w.Write(payload)
	})
	return httptest.NewServer(mux)
}

// TestListSecretsInProject_ResolvesEnvironmentNameToID_SendsRealFilters: the
// disambiguated variant must resolve "production" to its numeric ID within
// the given project (via ListEnvironments) and send project_id+environment_id
// -- the filters the server actually honors -- not the rejected name param.
func TestListSecretsInProject_ResolvesEnvironmentNameToID_SendsRealFilters(t *testing.T) {
	var gotQueries []string
	srv := newInProjectTestServer(t, 1, &gotQueries)
	defer srv.Close()

	c, err := New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	secrets, err := c.ListSecretsInProject(context.Background(), 1, "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 1 || secrets[0].Name != "db-pass" {
		t.Errorf("expected the db-pass secret, got %+v", secrets)
	}

	if len(gotQueries) != 1 {
		t.Fatalf("expected exactly one request to /api/v1/secrets, got %d", len(gotQueries))
	}
	q := gotQueries[0]
	if !strings.Contains(q, "project_id=1") {
		t.Errorf("expected project_id=1 in query %q", q)
	}
	if !strings.Contains(q, "environment_id=7") {
		t.Errorf("expected environment_id=7 (resolved from name) in query %q", q)
	}
	if strings.Contains(q, "environment=production") {
		t.Errorf("must not send the rejected bare environment name filter, got %q", q)
	}
}

// TestListSecretsInProject_UnknownEnvironmentName_ReturnsClearError: an
// environment name that doesn't exist in the given project must fail with a
// clear, actionable error rather than silently returning an unscoped list.
func TestListSecretsInProject_UnknownEnvironmentName_ReturnsClearError(t *testing.T) {
	var gotQueries []string
	srv := newInProjectTestServer(t, 1, &gotQueries)
	defer srv.Close()

	c, err := New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = c.ListSecretsInProject(context.Background(), 1, "nonexistent-env")
	if err == nil {
		t.Fatal("expected an error for an unknown environment name")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("expected a 'not found' error, got %v", err)
	}
	if len(gotQueries) != 0 {
		t.Errorf("must not call /api/v1/secrets when the environment name can't be resolved, got %d calls", len(gotQueries))
	}
}

// TestGetSecretInProject_HappyPath exercises the full resolve-then-fetch path.
func TestGetSecretInProject_HappyPath(t *testing.T) {
	var gotQueries []string
	srv := newInProjectTestServer(t, 1, &gotQueries)
	defer srv.Close()

	c, err := New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	value, err := c.GetSecretInProject(context.Background(), 1, "db-pass", "production")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if value != "s3cr3t" {
		t.Errorf("expected s3cr3t, got %q", value)
	}
}
