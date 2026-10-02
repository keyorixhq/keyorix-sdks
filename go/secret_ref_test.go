package keyorix

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestGetSecretByRef_DidNotExistBeforeThisFix is the red/green proof for the
// new single-round-trip ref path. Before this fix, GetSecretByRef/GetSecretIn
// did not exist: this file fails to compile against the pre-fix keyorix.go
// (confirmed via `git stash` — see reports/SESSION-K.md). After the fix, a
// fake server exposing only GET /api/v1/secrets/value?ref= — not
// /api/v1/secrets or /api/v1/projects, which GetSecretScoped would need —
// proves the ref path never calls either.
func TestGetSecretByRef_DidNotExistBeforeThisFix(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/secrets/value" {
			t.Fatalf("unexpected request path %s (GetSecretByRef must only call /api/v1/secrets/value)", r.URL.Path)
		}
		if got, want := r.URL.Query().Get("ref"), "my-project/production/db-password"; got != want {
			t.Fatalf("ref = %q, want %q", got, want)
		}
		_, _ = w.Write([]byte(`{"success":true,"data":{"value":"s3cr3t"}}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL, "machine-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got, err := c.GetSecretByRef(context.Background(), "my-project/production/db-password")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "s3cr3t" {
		t.Fatalf("value = %q, want %q", got, "s3cr3t")
	}
}

func TestGetSecretByRef_EscapesRefAndRoundTripsSlashesInName(t *testing.T) {
	const ref = "my project/prod env/path/to/secret" // spaces + a name with slashes

	var gotRawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		if got := r.URL.Query().Get("ref"); got != ref {
			t.Fatalf("decoded ref = %q, want %q", got, ref)
		}
		_, _ = w.Write([]byte(`{"success":true,"data":{"value":"v"}}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.GetSecretByRef(context.Background(), ref); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The handler above proves the ROUND TRIP decodes correctly; this proves
	// what we actually sent on the wire was escaped, not sent literally.
	if gotRawQuery == "ref="+ref {
		t.Fatalf("ref was sent unescaped on the wire: %s", gotRawQuery)
	}
}

func TestGetSecretIn_BuildsRefFromParts(t *testing.T) {
	var gotRef string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRef = r.URL.Query().Get("ref")
		_, _ = w.Write([]byte(`{"success":true,"data":{"value":"v"}}`))
	}))
	defer srv.Close()

	c, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.GetSecretIn(context.Background(), "proj", "env", "name"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "proj/env/name"; gotRef != want {
		t.Fatalf("ref = %q, want %q", gotRef, want)
	}
}

// TestGetSecretByRef_ErrorMapping reuses the typed errors from errorForResponse
// (AuthError/ForbiddenError/NotFoundError, added in #40) rather than a second
// error set — a 400 (malformed ref) has no dedicated type, same as every
// other call site that funnels through errorForResponse.
func TestGetSecretByRef_ErrorMapping(t *testing.T) {
	cases := []struct {
		status int
		check  func(t *testing.T, err error)
	}{
		{http.StatusBadRequest, func(t *testing.T, err error) {
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusBadRequest {
				t.Fatalf("expected *APIError with StatusCode 400, got %T (%v)", err, err)
			}
			var authErr *AuthError
			var forbidden *ForbiddenError
			var notFound *NotFoundError
			if errors.As(err, &authErr) || errors.As(err, &forbidden) || errors.As(err, &notFound) {
				t.Fatalf("400 should not map to a typed 401/403/404 error, got %T", err)
			}
		}},
		{http.StatusUnauthorized, func(t *testing.T, err error) {
			var authErr *AuthError
			if !errors.As(err, &authErr) {
				t.Fatalf("expected *AuthError, got %T (%v)", err, err)
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
		t.Run(fmt.Sprintf("%d", tc.status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"error":"X","message":"server said no","code":` + fmt.Sprint(tc.status) + `}`))
			}))
			defer srv.Close()

			c, err := New(srv.URL, "tok")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			_, err = c.GetSecretByRef(context.Background(), "p/e/n")
			if err == nil {
				t.Fatal("expected an error")
			}
			tc.check(t, err)
		})
	}
}
