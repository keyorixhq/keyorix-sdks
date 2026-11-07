package keyorix

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// secretVersionNumbers lists a secret's version numbers over raw HTTP (the SDK
// has no version-listing method; the update response carries no version, so the
// contract test reads the server's own version list to prove an update wrote a
// new version).
func secretVersionNumbers(t *testing.T, serverURL, token string, id uint) []int {
	t.Helper()
	var data struct {
		Versions []struct {
			VersionNumber int
		} `json:"versions"`
	}
	authedJSON(t, http.MethodGet, fmt.Sprintf("%s/api/v1/secrets/%d/versions", serverURL, id), token, nil, &data)
	nums := make([]int, 0, len(data.Versions))
	for _, v := range data.Versions {
		nums = append(nums, v.VersionNumber)
	}
	return nums
}

// trickyValue is a rotated value a generated password or a PEM could be: it
// needs JSON escaping on the way in and decoding on the way out.
const trickyValue = "line1\nline2 \"quoted\" back\\slash\ttab é ends-with-backslash\\"

// TestContract_UpdateDeleteSecret drives UpdateSecret and DeleteSecret against
// a real keyorix-server: update writes a new version whose value is readable,
// and delete is a soft delete (gone from a get, listed in the deleted listing
// with the purge date the delete returned).
func TestContract_UpdateDeleteSecret(t *testing.T) {
	serverURL := contractServerURL(t)
	token := seedAdminSession(t, serverURL)
	client, err := New(serverURL, token)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	projects, err := client.ListProjects(ctx)
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	var projectID, devEnvID uint
	for _, p := range projects {
		if p.Name == "default" {
			projectID = p.ID
		}
	}
	envs, err := client.ListEnvironments(ctx, projectID)
	if err != nil {
		t.Fatalf("ListEnvironments: %v", err)
	}
	for _, e := range envs {
		if e.Name == "development" {
			devEnvID = e.ID
		}
	}
	if projectID == 0 || devEnvID == 0 {
		t.Fatal("default project / development environment not found")
	}
	project, env := ProjectByID(projectID), EnvironmentByID(devEnvID)

	name := fmt.Sprintf("contract-upd-del-%d", time.Now().UnixNano())
	seedSecret(t, serverURL, token, projectID, devEnvID, name, "value-one")
	live, err := client.ListSecretsScoped(ctx, project, env)
	if err != nil {
		t.Fatalf("ListSecretsScoped: %v", err)
	}
	var id uint
	for _, s := range live {
		if s.Name == name {
			id = s.ID
		}
	}
	if id == 0 {
		t.Fatalf("seeded secret %q not found", name)
	}
	if got := secretVersionNumbers(t, serverURL, token, id); len(got) != 1 {
		t.Fatalf("freshly created secret has versions %v, want exactly one", got)
	}

	t.Run("UpdateSecret writes a new version and the new value is readable", func(t *testing.T) {
		updated, err := client.UpdateSecret(ctx, project, env, name, "value-two")
		if err != nil {
			t.Fatalf("UpdateSecret: %v", err)
		}
		if updated.ID != id || updated.Name != name {
			t.Errorf("UpdateSecret returned %+v, want id %d name %q", updated, id, name)
		}
		got, err := client.GetSecretScoped(ctx, name, project, env)
		if err != nil {
			t.Fatalf("GetSecretScoped: %v", err)
		}
		if got != "value-two" {
			t.Errorf("value after update = %q, want %q", got, "value-two")
		}
		if v := secretVersionNumbers(t, serverURL, token, id); len(v) != 2 || v[0] != 2 {
			t.Errorf("versions after one update = %v, want two with the newest numbered 2", v)
		}

		// By ID, the primitive the scoped call wraps: a third version.
		if _, err := client.UpdateSecretByID(ctx, id, "value-three"); err != nil {
			t.Fatalf("UpdateSecretByID: %v", err)
		}
		got, err = client.GetSecretScoped(ctx, name, project, env)
		if err != nil {
			t.Fatalf("GetSecretScoped: %v", err)
		}
		if got != "value-three" {
			t.Errorf("value after second update = %q, want %q", got, "value-three")
		}
		if v := secretVersionNumbers(t, serverURL, token, id); len(v) != 3 || v[0] != 3 {
			t.Errorf("versions after two updates = %v, want three with the newest numbered 3", v)
		}

		// A rotated value with quotes, backslashes, a newline and a tab must read back byte for byte.
		if _, err := client.UpdateSecretByID(ctx, id, trickyValue); err != nil {
			t.Fatalf("UpdateSecretByID(tricky value): %v", err)
		}
		got, err = client.GetSecretScoped(ctx, name, project, env)
		if err != nil {
			t.Fatalf("GetSecretScoped: %v", err)
		}
		if got != trickyValue {
			t.Errorf("value after update = %q, want %q", got, trickyValue)
		}
	})

	t.Run("UpdateSecret and DeleteSecret by a zero-grant token are forbidden (403)", func(t *testing.T) {
		machineClient, err := New(serverURL, createMachineToken(t, serverURL, token, projectID))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, err = machineClient.UpdateSecretByID(ctx, id, "attacker-value")
		var forbidden *ForbiddenError
		if !errors.As(err, &forbidden) {
			t.Errorf("UpdateSecretByID with a zero-grant token: got %T (%v), want *ForbiddenError", err, err)
		}
		_, err = machineClient.DeleteSecretByID(ctx, id)
		if !errors.As(err, &forbidden) {
			t.Errorf("DeleteSecretByID with a zero-grant token: got %T (%v), want *ForbiddenError", err, err)
		}
		// Neither call changed anything.
		if got, err := client.GetSecretScoped(ctx, name, project, env); err != nil || got != trickyValue {
			t.Errorf("secret after refused calls = %q, %v; want it unchanged", got, err)
		}
	})

	t.Run("DeleteSecret soft-deletes and returns the purge date", func(t *testing.T) {
		purgeAt, err := client.DeleteSecret(ctx, project, env, name)
		if err != nil {
			t.Fatalf("DeleteSecret: %v", err)
		}
		if purgeAt == nil {
			t.Fatal("DeleteSecret returned no purge date, want one (the server sends Keyorix-Purge-At)")
		}
		if d := time.Until(*purgeAt); d < 29*24*time.Hour || d > 31*24*time.Hour {
			t.Errorf("purge date %v is not ~30 days out (retention_days=30)", purgeAt)
		}

		_, err = client.GetSecretScoped(ctx, name, project, env)
		var notFound *SecretNotFoundError
		if !errors.As(err, &notFound) {
			t.Errorf("GetSecretScoped after delete: got %T (%v), want *SecretNotFoundError", err, err)
		}

		deleted, err := client.ListDeletedSecrets(ctx, project)
		if err != nil {
			t.Fatalf("ListDeletedSecrets: %v", err)
		}
		var listed *Secret
		for i := range deleted {
			if deleted[i].ID == id {
				listed = &deleted[i]
			}
		}
		if listed == nil {
			t.Fatalf("deleted secret %d not in ListDeletedSecrets (%d entries)", id, len(deleted))
		}
		if listed.PurgeAt == nil {
			t.Fatal("deleted listing has nil PurgeAt")
		}
		if diff := listed.PurgeAt.Sub(*purgeAt); diff < -2*time.Second || diff > 2*time.Second {
			t.Errorf("DeleteSecret purge date %v and listed PurgeAt %v differ by %v", purgeAt, listed.PurgeAt, diff)
		}
	})

	t.Run("a deleted secret is a 404 for update and delete", func(t *testing.T) {
		var notFound *NotFoundError
		if _, err := client.UpdateSecretByID(ctx, id, "late"); !errors.As(err, &notFound) {
			t.Errorf("UpdateSecretByID after delete: got %T (%v), want *NotFoundError", err, err)
		}
		if _, err := client.DeleteSecretByID(ctx, id); !errors.As(err, &notFound) {
			t.Errorf("DeleteSecretByID after delete: got %T (%v), want *NotFoundError", err, err)
		}
		var snf *SecretNotFoundError
		if _, err := client.UpdateSecret(ctx, project, env, name, "late"); !errors.As(err, &snf) {
			t.Errorf("UpdateSecret by name after delete: got %T (%v), want *SecretNotFoundError", err, err)
		}
		if _, err := client.DeleteSecret(ctx, project, env, name); !errors.As(err, &snf) {
			t.Errorf("DeleteSecret by name after delete: got %T (%v), want *SecretNotFoundError", err, err)
		}
	})
}
