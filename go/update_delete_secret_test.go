package keyorix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const rotatedValue = "s3cr3t-rotated-value"

func TestUpdateSecretByID_SendsPutWithValueAndDecodesMetadata(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"data":{"id":7,"name":"db","type":"generic","project_id":3}}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "tok")

	s, err := c.UpdateSecretByID(context.Background(), 7, rotatedValue)
	if err != nil {
		t.Fatalf("UpdateSecretByID: %v", err)
	}
	if gotMethod != http.MethodPut || gotPath != "/api/v1/secrets/7" || gotAuth != "Bearer tok" {
		t.Errorf("request = %s %s auth %q", gotMethod, gotPath, gotAuth)
	}
	if gotBody != `{"value":"`+rotatedValue+`"}` {
		t.Errorf("body = %s", gotBody)
	}
	if s.ID != 7 || s.Name != "db" || s.ProjectID != 3 {
		t.Errorf("decoded %+v", s)
	}
}

func TestUpdateSecretByID_EmptyValueIsRejectedWithoutARequest(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	defer srv.Close()
	c, _ := New(srv.URL, "tok")

	if _, err := c.UpdateSecretByID(context.Background(), 7, ""); err == nil {
		t.Fatal("empty value accepted, want an error (the server would silently write nothing)")
	}
	if called {
		t.Error("an empty value still reached the server")
	}
}

func TestUpdateSecretByID_ErrorsNeverCarryTheValue(t *testing.T) {
	// A server that echoes request content in its error message, raw and
	// JSON-escaped (the quote forces an escape).
	const tricky = `pa"ss` + rotatedValue
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(status)
			_, _ = fmt.Fprintf(w, `{"error":"X","message":"bad value %s / escaped pa\"ss%s"}`, tricky, rotatedValue)
		}))
		c, _ := New(srv.URL, "tok")
		_, err := c.UpdateSecretByID(context.Background(), 7, tricky)
		srv.Close()
		if err == nil {
			t.Fatalf("status %d: want an error", status)
		}
		var api *APIError
		if !errors.As(err, &api) {
			t.Fatalf("status %d: %T does not unwrap to *APIError", status, err)
		}
		if strings.Contains(err.Error(), rotatedValue) || strings.Contains(api.Body, rotatedValue) {
			t.Errorf("status %d: value leaked: error %q body %q", status, err.Error(), api.Body)
		}
	}
}

func TestUpdateSecretByID_TypedErrors(t *testing.T) {
	cases := map[int]func(error) bool{
		http.StatusUnauthorized: func(e error) bool { var t *AuthError; return errors.As(e, &t) },
		http.StatusForbidden:    func(e error) bool { var t *ForbiddenError; return errors.As(e, &t) },
		http.StatusNotFound:     func(e error) bool { var t *NotFoundError; return errors.As(e, &t) },
	}
	for status, is := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(status) }))
		c, _ := New(srv.URL, "tok")
		_, uerr := c.UpdateSecretByID(context.Background(), 1, "v")
		_, derr := c.DeleteSecretByID(context.Background(), 1)
		srv.Close()
		if !is(uerr) {
			t.Errorf("update %d: got %T", status, uerr)
		}
		if !is(derr) {
			t.Errorf("delete %d: got %T", status, derr)
		}
	}
}

func TestUpdateSecretRequest_FormattingRedactsTheValue(t *testing.T) {
	r := updateSecretRequest{Value: rotatedValue}
	for _, got := range []string{fmt.Sprintf("%v", r), fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", r), fmt.Sprintf("%s", r), fmt.Sprintf("%v", &r)} {
		if strings.Contains(got, rotatedValue) {
			t.Errorf("formatted request leaks the value: %s", got)
		}
	}
}

func TestDeleteSecretByID_ReturnsPurgeDateWhenSent(t *testing.T) {
	var gotMethod, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.Header().Set("Keyorix-Purge-At", "2026-11-30T14:56:16Z")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "tok")

	at, err := c.DeleteSecretByID(context.Background(), 9)
	if err != nil {
		t.Fatalf("DeleteSecretByID: %v", err)
	}
	if gotMethod != http.MethodDelete || gotPath != "/api/v1/secrets/9" {
		t.Errorf("request = %s %s", gotMethod, gotPath)
	}
	if at == nil || at.UTC().Format("2006-01-02T15:04:05Z") != "2026-11-30T14:56:16Z" {
		t.Errorf("purge date = %v", at)
	}
}

func TestDeleteSecretByID_NoPurgeDateIsNotAnError(t *testing.T) {
	for _, header := range []string{"", "not-a-date"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if header != "" {
				w.Header().Set("Keyorix-Purge-At", header)
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		c, _ := New(srv.URL, "tok")
		at, err := c.DeleteSecretByID(context.Background(), 9)
		srv.Close()
		if err != nil || at != nil {
			t.Errorf("header %q: got (%v, %v), want (nil, nil): the delete itself succeeded", header, at, err)
		}
	}
}

func TestUpdateAndDeleteSecret_ResolveByNameAndRefuseAmbiguity(t *testing.T) {
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/secrets":
			_, _ = w.Write([]byte(`{"data":{"secrets":[{"id":1,"name":"dup"},{"id":2,"name":"dup"},{"id":3,"name":"solo"}],"total_pages":1}}`))
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/secrets/3":
			_, _ = w.Write([]byte(`{"data":{"id":3,"name":"solo"}}`))
		case r.Method == http.MethodDelete && r.URL.Path == "/api/v1/secrets/3":
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	defer srv.Close()
	c, _ := New(srv.URL, "tok")
	ctx := context.Background()
	p, e := ProjectByID(1), EnvironmentByID(1)

	if s, err := c.UpdateSecret(ctx, p, e, "solo", "v"); err != nil || s.ID != 3 {
		t.Errorf("UpdateSecret solo = %+v, %v", s, err)
	}
	if _, err := c.DeleteSecret(ctx, p, e, "solo"); err != nil {
		t.Errorf("DeleteSecret solo: %v", err)
	}
	var amb *AmbiguousSecretError
	if _, err := c.UpdateSecret(ctx, p, e, "dup", "v"); !errors.As(err, &amb) {
		t.Errorf("UpdateSecret dup: got %T, want *AmbiguousSecretError", err)
	}
	if _, err := c.DeleteSecret(ctx, p, e, "dup"); !errors.As(err, &amb) {
		t.Errorf("DeleteSecret dup: got %T, want *AmbiguousSecretError", err)
	}
	var nf *SecretNotFoundError
	if _, err := c.UpdateSecret(ctx, p, e, "ghost", "v"); !errors.As(err, &nf) {
		t.Errorf("UpdateSecret ghost: got %T, want *SecretNotFoundError", err)
	}
	for _, call := range calls {
		if call == "PUT /api/v1/secrets/1" || call == "PUT /api/v1/secrets/2" || call == "DELETE /api/v1/secrets/1" || call == "DELETE /api/v1/secrets/2" {
			t.Errorf("an ambiguous name still wrote: %s", call)
		}
	}
}
