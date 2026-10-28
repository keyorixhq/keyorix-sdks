package keyorix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// Contract tests exercise this SDK's public API against a REAL, running
// keyorix-server -- not a mock -- to prove the SDK's wire-format assumptions
// (struct field tags, envelope shapes) still match the actual API on
// keyorixhq/keyorix's main branch. Every case here is green on main today
// (verified against a local keyorix-server built from main, 2026-09-25); its
// purpose is to go RED the moment a server-side change (e.g. a wire-format
// migration to snake_case for a type this SDK parses) lands without a
// matching SDK update, rather than the drift being discovered by a customer's
// silently-empty field. See keyorix-sdks BACKLOG.md and the keyorix repo's
// SDKS track report for the current compatibility status this pins.
//
// Skipped unless KEYORIX_CONTRACT_SERVER_URL is set (same "skip when absent,
// real failure when present" convention as keyorix's own pg-gated tests) --
// this needs a real server, which CI provides via a pinned keyorix-server
// image (see .github/workflows/contract.yml) and a local run can provide via
// `go run ./server` from a keyorix checkout (see CONTRIBUTING.md).
//
// The server is expected to be freshly bootstrapped (no admin yet) so this
// test can claim the bootstrap token itself and know the exact resulting
// state (one "default" project, three environments) -- it does not assume
// any other seeding. KEYORIX_CONTRACT_BOOTSTRAP_TOKEN must match the
// server's configured KEYORIX_BOOTSTRAP_TOKEN.
func contractServerURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("KEYORIX_CONTRACT_SERVER_URL")
	if url == "" {
		t.Skip("KEYORIX_CONTRACT_SERVER_URL not set -- skipping contract test (needs a real keyorix-server)")
	}
	return url
}

// seedAdminSession bootstraps a fresh server (idempotent -- a second run
// against an already-initialized server just logs in instead) and returns a
// valid session token, via raw HTTP: /system/init and /auth/login are not
// part of this SDK's own public surface (Login is, and is used for the
// second call), so bootstrap must go directly over HTTP.
func seedAdminSession(t *testing.T, serverURL string) string {
	t.Helper()
	bootstrapToken := os.Getenv("KEYORIX_CONTRACT_BOOTSTRAP_TOKEN")
	if bootstrapToken == "" {
		t.Fatal("KEYORIX_CONTRACT_BOOTSTRAP_TOKEN must be set alongside KEYORIX_CONTRACT_SERVER_URL")
	}

	body, _ := json.Marshal(map[string]string{
		"username":        "contract-admin",
		"email":           "contract-admin@example.com",
		"password":        "ContractTestPassw0rd!",
		"bootstrap_token": bootstrapToken,
	})
	resp, err := http.Post(serverURL+"/system/init", "application/json", bytes.NewReader(body)) //nolint:gosec // serverURL is the operator-supplied contract-test target, not attacker input
	if err != nil {
		t.Fatalf("POST /system/init: %v", err)
	}
	defer resp.Body.Close()
	// 200/201 (first boot) or 200 with already_initialized=true (idempotent
	// re-run) are both fine; anything else (e.g. a rejected bootstrap token)
	// is not.
	if resp.StatusCode >= 300 {
		t.Fatalf("POST /system/init: unexpected status %d", resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	token, err := Login(ctx, serverURL, "contract-admin", "ContractTestPassw0rd!")
	if err != nil {
		t.Fatalf("Login after bootstrap: %v", err)
	}
	return token
}

// seedSecret creates a secret directly over HTTP (CreateSecret is not part of
// this SDK's public surface -- it is read-only for secret values) so the
// read-path methods under test (ListSecretsScoped/GetSecretScoped) have a
// real, known secret to find.
func seedSecret(t *testing.T, serverURL, token string, projectID, environmentID uint, name, value string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"name":           name,
		"value":          value,
		"project_id":     projectID,
		"environment_id": environmentID,
		"type":           "generic",
	})
	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/v1/secrets", bytes.NewReader(body)) //nolint:gosec // serverURL is the operator-supplied contract-test target, not attacker input
	if err != nil {
		t.Fatalf("build create-secret request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authBearer+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/v1/secrets: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Fatalf("POST /api/v1/secrets: unexpected status %d", resp.StatusCode)
	}
}

// createPAT mints a personal access token for the caller identified by
// adminToken, via raw HTTP (PAT issuance is not part of this SDK's public
// surface). Returns the plaintext token.
func createPAT(t *testing.T, serverURL, adminToken, name string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"name": name})
	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/v1/auth/tokens", bytes.NewReader(body)) //nolint:gosec // serverURL is the operator-supplied contract-test target, not attacker input
	if err != nil {
		t.Fatalf("build create-PAT request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authBearer+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /api/v1/auth/tokens: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Fatalf("POST /api/v1/auth/tokens: unexpected status %d", resp.StatusCode)
	}
	var result struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode create-PAT response: %v", err)
	}
	if result.Data.Token == "" {
		t.Fatal("create-PAT response had no token")
	}
	return result.Data.Token
}

// createMachineToken creates a fresh machine identity in projectID and issues
// it a token, via raw HTTP (neither is part of this SDK's public surface).
// Returns the plaintext token. A brand-new machine identity holds no roles,
// so this token authenticates but is not authorized for anything yet --
// exactly the shape needed to prove authentication succeeds independently of
// authorization.
func createMachineToken(t *testing.T, serverURL, adminToken string, projectID uint) string {
	t.Helper()
	idBody, _ := json.Marshal(map[string]any{
		"name":          fmt.Sprintf("contract-test-machine-%d", time.Now().UnixNano()),
		"identity_type": "service",
	})
	idReq, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/api/v1/projects/%d/machine-identities", serverURL, projectID), bytes.NewReader(idBody)) //nolint:gosec // serverURL is the operator-supplied contract-test target, not attacker input
	if err != nil {
		t.Fatalf("build create-machine-identity request: %v", err)
	}
	idReq.Header.Set("Content-Type", "application/json")
	idReq.Header.Set("Authorization", authBearer+adminToken)
	idResp, err := http.DefaultClient.Do(idReq)
	if err != nil {
		t.Fatalf("POST machine-identities: %v", err)
	}
	defer idResp.Body.Close()
	if idResp.StatusCode >= 300 {
		t.Fatalf("POST machine-identities: unexpected status %d", idResp.StatusCode)
	}
	var idResult struct {
		Data struct {
			MachineIdentity struct {
				ID uint `json:"id"`
			} `json:"machine_identity"`
		} `json:"data"`
	}
	if err := json.NewDecoder(idResp.Body).Decode(&idResult); err != nil {
		t.Fatalf("decode create-machine-identity response: %v", err)
	}
	machineID := idResult.Data.MachineIdentity.ID
	if machineID == 0 {
		t.Fatal("create-machine-identity response had no id")
	}

	tokBody, _ := json.Marshal(map[string]any{"name": "contract-test-machine-token"})
	tokReq, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("%s/api/v1/projects/%d/machine-identities/%d/tokens", serverURL, projectID, machineID), bytes.NewReader(tokBody)) //nolint:gosec // serverURL is the operator-supplied contract-test target, not attacker input
	if err != nil {
		t.Fatalf("build issue-machine-token request: %v", err)
	}
	tokReq.Header.Set("Content-Type", "application/json")
	tokReq.Header.Set("Authorization", authBearer+adminToken)
	tokResp, err := http.DefaultClient.Do(tokReq)
	if err != nil {
		t.Fatalf("POST machine-identities tokens: %v", err)
	}
	defer tokResp.Body.Close()
	if tokResp.StatusCode >= 300 {
		t.Fatalf("POST machine-identities tokens: unexpected status %d", tokResp.StatusCode)
	}
	var tokResult struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(tokResp.Body).Decode(&tokResult); err != nil {
		t.Fatalf("decode issue-machine-token response: %v", err)
	}
	if tokResult.Data.Token == "" {
		t.Fatal("issue-machine-token response had no token")
	}
	return tokResult.Data.Token
}

func TestContract_FullClientSurface(t *testing.T) {
	serverURL := contractServerURL(t)
	token := seedAdminSession(t, serverURL)

	client, err := New(serverURL, token)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	t.Run("Health", func(t *testing.T) {
		if err := client.Health(ctx); err != nil {
			t.Fatalf("Health: %v", err)
		}
	})

	var defaultProjectID uint
	t.Run("ListProjects finds the bootstrap-seeded default project", func(t *testing.T) {
		projects, err := client.ListProjects(ctx)
		if err != nil {
			t.Fatalf("ListProjects: %v", err)
		}
		for _, p := range projects {
			if p.Name == "default" {
				defaultProjectID = p.ID
			}
		}
		if defaultProjectID == 0 {
			t.Fatalf("expected a 'default' project among %d projects, found none", len(projects))
		}
	})

	t.Run("ListEnvironments returns the three bootstrap-seeded environments", func(t *testing.T) {
		if defaultProjectID == 0 {
			t.Skip("default project not found (see ListProjects subtest)")
		}
		envs, err := client.ListEnvironments(ctx, defaultProjectID)
		if err != nil {
			t.Fatalf("ListEnvironments: %v", err)
		}
		want := map[string]bool{"development": false, "staging": false, "production": false}
		for _, e := range envs {
			if e.ProjectID != defaultProjectID {
				t.Errorf("environment %q has ProjectID %d, want %d", e.Name, e.ProjectID, defaultProjectID)
			}
			if _, ok := want[e.Name]; ok {
				want[e.Name] = true
			}
		}
		for name, found := range want {
			if !found {
				t.Errorf("expected environment %q, not found", name)
			}
		}
	})

	var createdProjectID uint
	t.Run("CreateProject round-trips name/description", func(t *testing.T) {
		name := fmt.Sprintf("contract-test-project-%d", time.Now().UnixNano())
		p, err := client.CreateProject(ctx, name, "created by the Go SDK contract test")
		if err != nil {
			t.Fatalf("CreateProject: %v", err)
		}
		if p.Name != name {
			t.Errorf("CreateProject: got Name %q, want %q", p.Name, name)
		}
		if p.Description != "created by the Go SDK contract test" {
			t.Errorf("CreateProject: got Description %q, want the description passed in", p.Description)
		}
		if p.ID == 0 {
			t.Error("CreateProject: got ID 0, want a nonzero project ID")
		}
		createdProjectID = p.ID
	})

	t.Run("GetSecretScoped/ListSecretsScoped round-trip a seeded secret's value", func(t *testing.T) {
		if defaultProjectID == 0 {
			t.Skip("default project not found (see ListProjects subtest)")
		}
		envs, err := client.ListEnvironments(ctx, defaultProjectID)
		if err != nil {
			t.Fatalf("ListEnvironments: %v", err)
		}
		var devEnvID uint
		for _, e := range envs {
			if e.Name == "development" {
				devEnvID = e.ID
			}
		}
		if devEnvID == 0 {
			t.Fatal("expected a 'development' environment, found none")
		}

		secretName := fmt.Sprintf("contract-test-secret-%d", time.Now().UnixNano())
		secretValue := "contract-test-value-do-not-use"
		seedSecret(t, serverURL, token, defaultProjectID, devEnvID, secretName, secretValue)

		secrets, err := client.ListSecretsScoped(ctx, ProjectByID(defaultProjectID), EnvironmentByName("development"))
		if err != nil {
			t.Fatalf("ListSecretsScoped: %v", err)
		}
		var found bool
		for _, s := range secrets {
			if s.Name == secretName {
				found = true
				if s.ProjectID != defaultProjectID {
					t.Errorf("secret %q: got ProjectID %d, want %d", secretName, s.ProjectID, defaultProjectID)
				}
			}
		}
		if !found {
			t.Fatalf("ListSecretsScoped: seeded secret %q not found among %d secrets", secretName, len(secrets))
		}

		got, err := client.GetSecretScoped(ctx, secretName, ProjectByID(defaultProjectID), EnvironmentByName("development"))
		if err != nil {
			t.Fatalf("GetSecretScoped: %v", err)
		}
		if got != secretValue {
			t.Errorf("GetSecretScoped: got value %q, want %q", got, secretValue)
		}
	})

	t.Run("New works transparently with a PAT, not just a session token", func(t *testing.T) {
		pat := createPAT(t, serverURL, token, "contract-test-pat")
		patClient, err := New(serverURL, pat)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := patClient.ListProjects(ctx); err != nil {
			t.Errorf("ListProjects with a PAT: %v (expected success -- a PAT presents identically to a session token)", err)
		}
	})

	t.Run("ListProjects succeeds with an empty list for a zero-grant token", func(t *testing.T) {
		if defaultProjectID == 0 {
			t.Skip("default project not found (see ListProjects subtest)")
		}
		machineToken := createMachineToken(t, serverURL, token, defaultProjectID)
		machineClient, err := New(serverURL, machineToken)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		// A brand-new machine identity holds no roles. List routes are
		// filtered by permission, so it authenticates and gets an EMPTY 200
		// (not AuthError, not ForbiddenError).
		got, err := machineClient.ListProjects(ctx)
		if err != nil {
			t.Fatalf("ListProjects with a zero-grant token: %v (want success with an empty list)", err)
		}
		if len(got) != 0 {
			t.Errorf("ListProjects with a zero-grant token: got %d projects, want 0", len(got))
		}
	})

	t.Run("GET /projects/{id} with a zero-grant token is forbidden (403)", func(t *testing.T) {
		if defaultProjectID == 0 {
			t.Skip("default project not found (see ListProjects subtest)")
		}
		machineToken := createMachineToken(t, serverURL, token, defaultProjectID)
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/projects/%d", serverURL, defaultProjectID), nil) //nolint:gosec // serverURL is the operator-supplied contract-test target, not attacker input
		if err != nil {
			t.Fatalf("build get-project request: %v", err)
		}
		req.Header.Set("Authorization", authBearer+machineToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("GET /api/v1/projects/%d: %v", defaultProjectID, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("GET /api/v1/projects/%d with a zero-grant token: got status %d, want 403", defaultProjectID, resp.StatusCode)
		}
	})

	t.Run("ListProjects with a bad token is rejected (401)", func(t *testing.T) {
		badClient, err := New(serverURL, "not-a-valid-token")
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		_, err = badClient.ListProjects(ctx)
		var authErr *AuthError
		if !errors.As(err, &authErr) {
			t.Errorf("ListProjects with a bad token: got %T (%v), want *AuthError", err, err)
		}
	})

	t.Run("WithTimeout is actually enforced against a slow server", func(t *testing.T) {
		slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			time.Sleep(200 * time.Millisecond)
			w.Write([]byte(`{"data":{"projects":[]}}`))
		}))
		defer slow.Close()
		slowClient, err := New(slow.URL, "test-token", WithTimeout(10*time.Millisecond))
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, err := slowClient.ListProjects(ctx); err == nil {
			t.Error("expected a timeout error from a 10ms client against a 200ms-slow server, got nil")
		}
	})

	_ = createdProjectID // exercised for its assertions above; no further use
}

// authedJSON performs an authenticated JSON request over raw HTTP (user
// administration and secret deletion are not part of this SDK's
// public surface) and decodes the response envelope's `data` into out (when
// non-nil). Any status >= 300 fails the test.
func authedJSON(t *testing.T, method, url, token string, in, out any) {
	t.Helper()
	var rdr *bytes.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, rdr) //nolint:gosec // url is the operator-supplied contract-test target, not attacker input
	if err != nil {
		t.Fatalf("build %s %s: %v", method, url, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", authBearer+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		t.Fatalf("%s %s: unexpected status %d", method, url, resp.StatusCode)
	}
	if out != nil {
		var env struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
			t.Fatalf("decode %s %s: %v", method, url, err)
		}
		if err := json.Unmarshal(env.Data, out); err != nil {
			t.Fatalf("decode data of %s %s: %v", method, url, err)
		}
	}
}

func TestContract_DeletedSecretPurgeAt(t *testing.T) {
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

	name := fmt.Sprintf("contract-purge-%d", time.Now().UnixNano())
	seedSecret(t, serverURL, token, projectID, devEnvID, name, "v")
	live, err := client.ListSecretsScoped(ctx, ProjectByID(projectID), EnvironmentByID(devEnvID))
	if err != nil {
		t.Fatalf("ListSecretsScoped: %v", err)
	}
	var id uint
	for _, s := range live {
		if s.Name == name {
			id = s.ID
			if s.PurgeAt != nil {
				t.Errorf("live secret has PurgeAt %v, want nil", s.PurgeAt)
			}
		}
	}
	if id == 0 {
		t.Fatalf("seeded secret %q not found", name)
	}
	authedJSON(t, http.MethodDelete, fmt.Sprintf("%s/api/v1/secrets/%d", serverURL, id), token, nil, nil)

	deleted, err := client.ListDeletedSecrets(ctx, ProjectByID(projectID))
	if err != nil {
		t.Fatalf("ListDeletedSecrets: %v", err)
	}
	for _, s := range deleted {
		if s.ID != id {
			continue
		}
		if s.PurgeAt == nil {
			t.Fatal("soft-deleted secret has nil PurgeAt")
		}
		if d := time.Until(*s.PurgeAt); d < 29*24*time.Hour || d > 31*24*time.Hour {
			t.Errorf("PurgeAt %v is not ~30 days out (retention_days=30)", s.PurgeAt)
		}
		return
	}
	t.Fatalf("soft-deleted secret %d not in ListDeletedSecrets (%d entries)", id, len(deleted))
}
