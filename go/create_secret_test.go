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
)

const createSecretValue = "s3cr3t-value-must-not-leak"

// createSecretServer answers POST /api/v1/secrets with the given status and
// body, recording the decoded request body.
func createSecretServer(t *testing.T, status int, respBody string, got *map[string]any) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if got != nil {
			_ = json.NewDecoder(r.Body).Decode(got)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(respBody))
	})
	mux.HandleFunc("/api/v1/projects", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"projects":[{"id":10,"name":"proj-a"}]}}`))
	})
	mux.HandleFunc("/api/v1/projects/10/environments", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"environments":[{"id":101,"name":"prod","project_id":10}]}}`))
	})
	return httptest.NewServer(mux)
}

func TestCreateSecret_SendsScopedBodyAndParsesNode(t *testing.T) {
	var got map[string]any
	srv := createSecretServer(t, http.StatusCreated,
		`{"data":{"id":7,"name":"db-password","project_id":10,"environment_id":101,"type":"generic"}}`, &got)
	defer srv.Close()
	c, _ := New(srv.URL, "test-token")

	s, err := c.CreateSecret(context.Background(), ProjectByName("proj-a"), EnvironmentByName("prod"),
		"db-password", createSecretValue, WithSecretDescription("note"))
	if err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if s.ID != 7 || s.Name != "db-password" || s.ProjectID != 10 || s.Type != "generic" {
		t.Errorf("unexpected secret %+v", s)
	}
	want := map[string]any{"name": "db-password", "value": createSecretValue, "project_id": 10.0,
		"environment_id": 101.0, "type": "generic", "description": "note"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("request %s = %v, want %v", k, got[k], v)
		}
	}
}

func TestCreateSecret_ByIDMakesNoResolutionCall(t *testing.T) {
	var got map[string]any
	srv := createSecretServer(t, http.StatusCreated, `{"data":{"id":1,"name":"n"}}`, &got)
	defer srv.Close()
	c, _ := New(srv.URL, "test-token")
	if _, err := c.CreateSecret(context.Background(), ProjectByID(3), EnvironmentByID(4), "n", "v", WithSecretType("password")); err != nil {
		t.Fatalf("CreateSecret: %v", err)
	}
	if got["project_id"] != 3.0 || got["environment_id"] != 4.0 || got["type"] != "password" {
		t.Errorf("unexpected request %v", got)
	}
}

func TestCreateSecret_DuplicateNameIsTyped(t *testing.T) {
	srv := createSecretServer(t, http.StatusConflict,
		`{"success":false,"error":"ConflictError","message":"Secret with this name already exists","code":409}`, nil)
	defer srv.Close()
	c, _ := New(srv.URL, "test-token")
	_, err := c.CreateSecret(context.Background(), ProjectByID(10), EnvironmentByID(101), "dup", createSecretValue)
	var exists *SecretAlreadyExistsError
	if !errors.As(err, &exists) {
		t.Fatalf("got %T (%v), want *SecretAlreadyExistsError", err, err)
	}
	var api *APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusConflict {
		t.Errorf("does not unwrap to a 409 *APIError: %v", err)
	}
}

func TestCreateSecret_UnauthenticatedIsAuthError(t *testing.T) {
	srv := createSecretServer(t, http.StatusUnauthorized, `{"error":"Unauthorized"}`, nil)
	defer srv.Close()
	c, _ := New(srv.URL, "test-token")
	_, err := c.CreateSecret(context.Background(), ProjectByID(10), EnvironmentByID(101), "n", createSecretValue)
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("got %T (%v), want *AuthError", err, err)
	}
}

// A server (or proxy) that echoes the request into its error body must not be
// able to put the value into the returned error, raw or JSON-escaped.
func TestCreateSecret_ValueNeverAppearsInErrors(t *testing.T) {
	value := "pa\"ss\nword-" + createSecretValue
	escaped, _ := json.Marshal(value)
	for _, status := range []int{http.StatusBadRequest, http.StatusConflict, http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		body := fmt.Sprintf(`{"error":"ValidationError","message":"bad value %s / %s"}`, escaped[1:len(escaped)-1], value)
		srv := createSecretServer(t, status, body, nil)
		c, _ := New(srv.URL, "test-token")
		_, err := c.CreateSecret(context.Background(), ProjectByID(10), EnvironmentByID(101), "n", value)
		srv.Close()
		if err == nil {
			t.Fatalf("status %d: want an error", status)
		}
		if strings.Contains(err.Error(), createSecretValue) {
			t.Errorf("status %d: error text leaks the value: %q", status, err.Error())
		}
		var api *APIError
		if errors.As(err, &api) && strings.Contains(api.Body, createSecretValue) {
			t.Errorf("status %d: APIError.Body leaks the value: %q", status, api.Body)
		}
	}
}

func TestCreateSecretRequest_FormattingRedactsValue(t *testing.T) {
	r := createSecretRequest{Name: "n", Value: createSecretValue, ProjectID: 1, EnvironmentID: 2, Type: "generic"}
	for _, s := range []string{fmt.Sprint(r), fmt.Sprintf("%v", r), fmt.Sprintf("%+v", r), fmt.Sprintf("%#v", r), fmt.Sprint(&r)} {
		if strings.Contains(s, createSecretValue) {
			t.Errorf("formatted request leaks the value: %q", s)
		}
	}
}

func TestCreateSecret_ResolutionFailureNamesNoValue(t *testing.T) {
	srv := createSecretServer(t, http.StatusCreated, `{}`, nil)
	defer srv.Close()
	c, _ := New(srv.URL, "test-token")
	_, err := c.CreateSecret(context.Background(), ProjectByName("nope"), EnvironmentByName("prod"), "n", createSecretValue)
	if err == nil || strings.Contains(err.Error(), createSecretValue) {
		t.Errorf("want a project-not-found error without the value, got %v", err)
	}
}
