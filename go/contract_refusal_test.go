package keyorix

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// TestContract_SuspendedSecretIsTyped suspends a secret on a real server and reads it
// through the SDK: the 409 SecretSuspended refusal must come back as
// *SecretUnavailableError carrying the server's code, not a bare *APIError.
// (503 audit_unavailable cannot be provoked on a healthy server; the fake-server
// test in audit_unavailable_test.go covers it with the real body shape.)
func TestContract_SuspendedSecretIsTyped(t *testing.T) {
	serverURL := contractServerURL(t)
	token := seedAdminSession(t, serverURL)
	client, err := New(serverURL, token)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	projects, err := client.ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	var projectID uint
	for _, p := range projects {
		if p.Name == "default" {
			projectID = p.ID
		}
	}
	envs, err := client.ListEnvironments(ctx, projectID)
	if err != nil {
		t.Fatalf("ListEnvironments: %v", err)
	}
	var devEnvID uint
	for _, e := range envs {
		if e.Name == "development" {
			devEnvID = e.ID
		}
	}
	if projectID == 0 || devEnvID == 0 {
		t.Fatal("default project / development environment not found")
	}

	name := fmt.Sprintf("contract-suspended-%d", time.Now().UnixNano())
	seedSecret(t, serverURL, token, projectID, devEnvID, name, "suspended-contract-value")
	secrets, err := client.ListSecretsScoped(ctx, ProjectByID(projectID), EnvironmentByID(devEnvID))
	if err != nil {
		t.Fatalf("ListSecretsScoped: %v", err)
	}
	var id uint
	for _, s := range secrets {
		if s.Name == name {
			id = s.ID
		}
	}
	if id == 0 {
		t.Fatalf("seeded secret %q not found", name)
	}

	authedJSON(t, http.MethodPost, fmt.Sprintf("%s/api/v1/secrets/%d/suspend", serverURL, id), token, map[string]string{"reason": "contract test"}, nil)

	_, err = client.GetSecretScoped(ctx, name, ProjectByID(projectID), EnvironmentByID(devEnvID))
	var ue *SecretUnavailableError
	if !errors.As(err, &ue) {
		t.Fatalf("read of a suspended secret: err = %v (%T), want *SecretUnavailableError", err, err)
	}
	if ue.StatusCode != http.StatusConflict || ue.Code != CodeSecretSuspended {
		t.Errorf("status/code = %d/%q, want 409/%q", ue.StatusCode, ue.Code, CodeSecretSuspended)
	}

	authedJSON(t, http.MethodPost, fmt.Sprintf("%s/api/v1/secrets/%d/resume", serverURL, id), token, nil, nil)
	if v, err := client.GetSecretScoped(ctx, name, ProjectByID(projectID), EnvironmentByID(devEnvID)); err != nil || v != "suspended-contract-value" {
		t.Errorf("read after resume: value=%q err=%v", v, err)
	}
}
