package keyorix

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestListSecretsScoped_FollowsAllPages is the pagination regression proof.
// Before this fix, ListSecretsScoped sent no page/page_size params at all, so
// it only ever got the server's default first page (page_size 20) — a scope
// with more secrets than that was silently truncated with no error. RED
// (pre-fix, reproduced via git stash — see reports/SESSION-K.md): this fixture
// serves 1 secret per page across 2 pages, and the pre-fix client only ever
// requests page 1, returning 1 secret instead of 2. GREEN (this fix): it
// requests every page the server reports and returns both.
func TestListSecretsScoped_FollowsAllPages(t *testing.T) {
	var sawPages []string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":1,"name":"proj"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/1/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"id":1,"name":"prod","project_id":1}]}}`))
	})
	mux.HandleFunc("/api/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.URL.Query().Get("project_id"), "1"; got != want {
			t.Fatalf("project_id = %q, want %q", got, want)
		}
		if got, want := r.URL.Query().Get("environment_id"), "1"; got != want {
			t.Fatalf("environment_id = %q, want %q", got, want)
		}
		page := r.URL.Query().Get("page")
		sawPages = append(sawPages, page)
		if page == "2" {
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"id":2,"name":"b"}],"total_pages":2}}`))
			return
		}
		_, _ = w.Write([]byte(`{"data":{"secrets":[{"id":1,"name":"a"}],"total_pages":2}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c, err := New(srv.URL, "tok")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	secrets, err := c.ListSecretsScoped(context.Background(), ProjectByName("proj"), EnvironmentByName("prod"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(secrets) != 2 {
		t.Fatalf("got %d secrets, want 2 (one from each page): %+v", len(secrets), secrets)
	}
	if len(sawPages) != 2 || sawPages[0] != "1" || sawPages[1] != "2" {
		t.Fatalf("pages requested = %v, want [1 2]", sawPages)
	}
}
