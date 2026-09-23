package keyorix

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// scopedTestServer simulates a server holding two projects (proj-a id=10,
// proj-b id=20), each with its own "prod" environment (ids 101 and 201 —
// environment names are unique per project, not globally) and its own
// secret named "db-password" (ids 1 and 2). Project proj-b's "prod" also
// holds a second secret literally named "ambiguous-secret" twice (ids 3 and
// 4) to exercise the ambiguous-match case.
func scopedTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"ID":10,"Name":"proj-a"},{"ID":20,"Name":"proj-b"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/10/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":101,"Name":"prod","ProjectID":10}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/20/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":201,"Name":"prod","ProjectID":20}]}}`))
	})
	mux.HandleFunc("/api/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		switch {
		case q.Get("project_id") == "10" && q.Get("environment_id") == "101":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"ID":1,"Name":"db-password"}]}}`))
		case q.Get("project_id") == "20" && q.Get("environment_id") == "201":
			_, _ = w.Write([]byte(`{"data":{"secrets":[` +
				`{"ID":2,"Name":"db-password"},` +
				`{"ID":3,"Name":"ambiguous-secret"},` +
				`{"ID":4,"Name":"ambiguous-secret"}` +
				`]}}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	mux.HandleFunc("/api/v1/secrets/1", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"value":"secret-a"}}`))
	})
	mux.HandleFunc("/api/v1/secrets/2", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"value":"secret-b"}}`))
	})
	return httptest.NewServer(mux)
}

func TestListSecretsScoped_TableMatrix(t *testing.T) {
	srv := scopedTestServer(t)
	defer srv.Close()
	c, err := New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	cases := []struct {
		name    string
		project ProjectRef
		env     EnvironmentRef
		wantIDs []uint
		wantErr bool
	}{
		{"by name, proj-a/prod", ProjectByName("proj-a"), EnvironmentByName("prod"), []uint{1}, false},
		{"by name, proj-b/prod", ProjectByName("proj-b"), EnvironmentByName("prod"), []uint{2, 3, 4}, false},
		{"by id, proj-a/prod", ProjectByID(10), EnvironmentByID(101), []uint{1}, false},
		{"by id, proj-b/prod", ProjectByID(20), EnvironmentByID(201), []uint{2, 3, 4}, false},
		{"unknown project", ProjectByName("ghost"), EnvironmentByName("prod"), nil, true},
		{"unknown environment", ProjectByName("proj-a"), EnvironmentByName("ghost"), nil, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			secrets, err := c.ListSecretsScoped(context.Background(), tc.project, tc.env)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(secrets) != len(tc.wantIDs) {
				t.Fatalf("expected %d secrets, got %d (%+v)", len(tc.wantIDs), len(secrets), secrets)
			}
			for i, id := range tc.wantIDs {
				if secrets[i].ID != id {
					t.Errorf("secret[%d]: expected ID %d, got %d", i, id, secrets[i].ID)
				}
			}
		})
	}
}

func TestGetSecretScoped_TableMatrix(t *testing.T) {
	srv := scopedTestServer(t)
	defer srv.Close()
	c, err := New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Run("proj-a resolves its own db-password", func(t *testing.T) {
		val, err := c.GetSecretScoped(context.Background(), "db-password", ProjectByName("proj-a"), EnvironmentByName("prod"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if val != "secret-a" {
			t.Errorf("expected secret-a, got %q", val)
		}
	})

	t.Run("proj-b resolves its own db-password, not proj-a's", func(t *testing.T) {
		val, err := c.GetSecretScoped(context.Background(), "db-password", ProjectByName("proj-b"), EnvironmentByName("prod"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if val != "secret-b" {
			t.Errorf("expected secret-b, got %q", val)
		}
	})

	t.Run("missing name -> SecretNotFoundError", func(t *testing.T) {
		_, err := c.GetSecretScoped(context.Background(), "does-not-exist", ProjectByName("proj-a"), EnvironmentByName("prod"))
		var notFound *SecretNotFoundError
		if !errors.As(err, &notFound) {
			t.Fatalf("expected *SecretNotFoundError, got %T (%v)", err, err)
		}
	})

	t.Run("ambiguous name -> AmbiguousSecretError listing both IDs", func(t *testing.T) {
		_, err := c.GetSecretScoped(context.Background(), "ambiguous-secret", ProjectByName("proj-b"), EnvironmentByName("prod"))
		var ambiguous *AmbiguousSecretError
		if !errors.As(err, &ambiguous) {
			t.Fatalf("expected *AmbiguousSecretError, got %T (%v)", err, err)
		}
		if len(ambiguous.IDs) != 2 || ambiguous.IDs[0] != 3 || ambiguous.IDs[1] != 4 {
			t.Errorf("expected IDs [3 4], got %v", ambiguous.IDs)
		}
	})
}

// TestResolveProject_CachesAcrossCalls proves the second lookup by name never
// re-hits GET /api/v1/projects.
func TestResolveProject_CachesAcrossCalls(t *testing.T) {
	var projectListCalls int
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		projectListCalls++
		_, _ = w.Write([]byte(`{"data":{"projects":[{"ID":10,"Name":"proj-a"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/10/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"ID":101,"Name":"prod","ProjectID":10}]}}`))
	})
	mux.HandleFunc("/api/v1/secrets", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"secrets":[]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ctx := context.Background()
	if _, err := c.ListSecretsScoped(ctx, ProjectByName("proj-a"), EnvironmentByName("prod")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.ListSecretsScoped(ctx, ProjectByName("proj-a"), EnvironmentByName("prod")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if projectListCalls != 1 {
		t.Errorf("expected GET /api/v1/projects to be called once (cached thereafter), got %d calls", projectListCalls)
	}
}

// TestResolveProject_ByIDNeverListsProjects proves an ID-based ref skips
// project/environment resolution round trips entirely.
func TestResolveProject_ByIDNeverListsProjects(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		t.Error("must not call GET /api/v1/projects when given ProjectByID")
	})
	mux.HandleFunc("/api/v1/projects/10/environments", func(w http.ResponseWriter, _ *http.Request) {
		t.Error("must not call the environments route when given EnvironmentByID")
	})
	mux.HandleFunc("/api/v1/secrets", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"secrets":[]}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := New(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.ListSecretsScoped(context.Background(), ProjectByID(10), EnvironmentByID(101)); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
