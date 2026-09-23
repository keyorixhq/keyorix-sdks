// Package keyorix provides a Go client for the Keyorix secrets manager API.
//
// Quick start:
//
//	client, err := keyorix.New("https://your-server:8443", "your-session-token")
//	secret, err := client.GetSecret(ctx, "db-password", "production")
package keyorix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const authBearer = "Bearer "

// Client is a Keyorix API client.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client

	// cacheMu guards projectCache/envCache. Populated lazily by
	// resolveProject/resolveEnvironment and never invalidated for the
	// lifetime of the Client — a project/environment rename mid-process is
	// expected to be rare enough that a fresh Client is the right way to
	// pick it up, not a cache-expiry policy.
	cacheMu      sync.RWMutex
	projectCache map[string]uint          // lowercased project name -> ID
	envCache     map[uint]map[string]uint // project ID -> lowercased environment name -> ID
}

// Secret represents a secret returned by the API.
type Secret struct {
	ID          uint      `json:"ID"`
	Name        string    `json:"Name"`
	Type        string    `json:"Type"`
	ProjectID   uint      `json:"ProjectID"`
	Environment string    `json:"environment_name"`
	CreatedAt   time.Time `json:"CreatedAt"`
}

// Project represents a Keyorix project.
type Project struct {
	ID          uint      `json:"ID"`
	Name        string    `json:"Name"`
	Description string    `json:"Description"`
	CreatedAt   time.Time `json:"CreatedAt"`
}

// Environment represents an environment scoped to a project.
type Environment struct {
	ID        uint   `json:"ID"`
	ProjectID uint   `json:"ProjectID"`
	Name      string `json:"Name"`
}

// SecretValue contains the decrypted value of a secret.
type SecretValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// APIError represents a non-2xx response from the Keyorix server. Error()
// deliberately omits the raw response body: it's server-controlled content
// that this SDK's own README quick-start passes straight to log.Fatal(err),
// and an unconditional relay into that path is exactly how untrusted content
// ends up verbatim in application logs. Callers who need the body for their
// own (redacted) logging can read the Body field directly.
type APIError struct {
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("keyorix: server returned %d", e.StatusCode)
}

// SecretNotFoundError is returned by GetSecretScoped when no secret in the
// given project+environment scope has the requested name.
type SecretNotFoundError struct {
	Name        string
	ProjectRef  ProjectRef
	Environment EnvironmentRef
}

func (e *SecretNotFoundError) Error() string {
	return fmt.Sprintf("keyorix: secret %q not found in project %s, environment %s", e.Name, e.ProjectRef, e.Environment)
}

// AmbiguousSecretError is returned by GetSecretScoped when more than one
// secret in the given project+environment scope has the requested name.
// GetSecretScoped never guesses which one was meant — IDs lists every match
// so the caller can disambiguate (e.g. via ListSecretsScoped).
type AmbiguousSecretError struct {
	Name        string
	ProjectRef  ProjectRef
	Environment EnvironmentRef
	IDs         []uint
}

func (e *AmbiguousSecretError) Error() string {
	return fmt.Sprintf("keyorix: secret %q is ambiguous in project %s, environment %s: matches IDs %v", e.Name, e.ProjectRef, e.Environment, e.IDs)
}

// ProjectRef identifies a project by name or by numeric ID. Construct one
// with ProjectByName or ProjectByID.
type ProjectRef struct {
	name string
	id   uint
	byID bool
}

// ProjectByName references a project by name, resolved to an ID (and cached)
// on first use.
func ProjectByName(name string) ProjectRef { return ProjectRef{name: name} }

// ProjectByID references a project directly by its numeric ID — no
// resolution round trip is made.
func ProjectByID(id uint) ProjectRef { return ProjectRef{id: id, byID: true} }

func (r ProjectRef) String() string {
	if r.byID {
		return fmt.Sprintf("id=%d", r.id)
	}
	return fmt.Sprintf("name=%q", r.name)
}

// EnvironmentRef identifies an environment (within some project) by name or
// by numeric ID. Construct one with EnvironmentByName or EnvironmentByID.
type EnvironmentRef struct {
	name string
	id   uint
	byID bool
}

// EnvironmentByName references an environment by name, resolved to an ID
// (and cached) on first use — scoped to whatever project it's resolved
// against, since environment names are unique per project, not globally.
func EnvironmentByName(name string) EnvironmentRef { return EnvironmentRef{name: name} }

// EnvironmentByID references an environment directly by its numeric ID — no
// resolution round trip is made.
func EnvironmentByID(id uint) EnvironmentRef { return EnvironmentRef{id: id, byID: true} }

func (r EnvironmentRef) String() string {
	if r.byID {
		return fmt.Sprintf("id=%d", r.id)
	}
	return fmt.Sprintf("name=%q", r.name)
}

// Option configures the client.
type Option func(*Client)

// WithHTTPClient sets a custom HTTP client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) { c.httpClient = hc }
}

// WithTimeout sets the HTTP timeout.
func WithTimeout(d time.Duration) Option {
	return func(c *Client) { c.httpClient.Timeout = d }
}

// validateServerURL rejects any scheme other than https, and allows http only
// for loopback hosts (localhost/127.0.0.0/8/::1) for local dev. A bearer token
// and every secret value would otherwise be sent/received in cleartext, and an
// unrestricted scheme (e.g. file://) would let a caller-influenced serverURL
// reach something other than an HTTP server entirely.
func validateServerURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("keyorix: invalid server URL %q: %w", rawURL, err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("keyorix: server URL %q must use https:// (http:// is only allowed for localhost/loopback)", rawURL)
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// New creates a new Keyorix client.
// serverURL is the base URL of your Keyorix server and must use https://
// (http:// is only accepted for localhost/loopback).
// token is a session token obtained via the login endpoint or keyorix CLI.
func New(serverURL, token string, opts ...Option) (*Client, error) {
	if err := validateServerURL(serverURL); err != nil {
		return nil, err
	}
	c := &Client{
		baseURL: serverURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// Login authenticates with username and password and returns a session token.
// Use this to obtain a token programmatically instead of hardcoding one.
// serverURL must use https:// (http:// is only accepted for localhost/loopback).
func Login(ctx context.Context, serverURL, username, password string) (string, error) {
	if err := validateServerURL(serverURL); err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, serverURL+"/auth/login", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("keyorix: failed to create login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("keyorix: login request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", &APIError{StatusCode: resp.StatusCode, Body: string(respBody)}
	}

	var result struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("keyorix: failed to parse login response: %w", err)
	}
	if result.Data.Token == "" {
		return "", fmt.Errorf("keyorix: no token in login response")
	}

	return result.Data.Token, nil
}

// GetSecret is deprecated: an environment name is only unique within one
// project, not globally, so scoping by environment alone can silently
// resolve to another project's same-named secret. Removed in
// keyorix-sdks v0.3.0 — this now always returns an error without ever
// contacting the server (no silent fallback to the old, unscoped behavior).
//
// Deprecated: use GetSecretScoped(ctx, name, project, environment) instead.
func (c *Client) GetSecret(_ context.Context, _, _ string) (string, error) {
	return "", fmt.Errorf("keyorix: GetSecret(ctx, name, environment) was removed in keyorix-sdks v0.3.0 (an environment name is only unique within one project, not globally) — use GetSecretScoped(ctx, name, project, environment) instead")
}

// ListSecrets is deprecated: an environment name is only unique within one
// project, not globally, so scoping by environment alone can silently
// return secrets from every project the caller can read. Removed in
// keyorix-sdks v0.3.0 — this now always returns an error without ever
// contacting the server (no silent fallback to the old, unscoped behavior).
//
// Deprecated: use ListSecretsScoped(ctx, project, environment) instead.
func (c *Client) ListSecrets(_ context.Context, _ string) ([]Secret, error) {
	return nil, fmt.Errorf("keyorix: ListSecrets(ctx, environment) was removed in keyorix-sdks v0.3.0 (an environment name is only unique within one project, not globally) — use ListSecretsScoped(ctx, project, environment) instead")
}

// GetSecretScoped returns the plaintext value of the secret named name
// within project+environment. name is matched exactly (case-sensitive)
// among the secrets in that scope.
//
// Returns *SecretNotFoundError if no secret in scope has that name, or
// *AmbiguousSecretError if more than one does — it never guesses.
func (c *Client) GetSecretScoped(ctx context.Context, name string, project ProjectRef, environment EnvironmentRef) (string, error) {
	secrets, err := c.ListSecretsScoped(ctx, project, environment)
	if err != nil {
		return "", err
	}

	var matches []Secret
	for _, s := range secrets {
		if s.Name == name {
			matches = append(matches, s)
		}
	}
	switch len(matches) {
	case 0:
		return "", &SecretNotFoundError{Name: name, ProjectRef: project, Environment: environment}
	case 1:
		return c.getSecretValue(ctx, matches[0].ID)
	default:
		ids := make([]uint, len(matches))
		for i, m := range matches {
			ids[i] = m.ID
		}
		return "", &AmbiguousSecretError{Name: name, ProjectRef: project, Environment: environment, IDs: ids}
	}
}

// ListSecretsScoped returns every secret within project+environment visible
// to the authenticated user. project and environment may each be given by
// name (resolved to an ID and cached on this Client) or by ID directly.
func (c *Client) ListSecretsScoped(ctx context.Context, project ProjectRef, environment EnvironmentRef) ([]Secret, error) {
	projectID, err := c.resolveProject(ctx, project)
	if err != nil {
		return nil, err
	}
	envID, err := c.resolveEnvironment(ctx, projectID, environment)
	if err != nil {
		return nil, err
	}

	endpoint := fmt.Sprintf("%s/api/v1/secrets?project_id=%d&environment_id=%d", c.baseURL, projectID, envID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("keyorix: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", authBearer+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keyorix: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("keyorix: unauthorized — check your token")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var result struct {
		Data struct {
			Secrets []Secret `json:"secrets"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("keyorix: failed to parse response: %w", err)
	}

	return result.Data.Secrets, nil
}

// resolveProject resolves ref to a project ID, using (and populating) the
// Client's cache when ref is given by name. An ID ref resolves with no
// network call.
func (c *Client) resolveProject(ctx context.Context, ref ProjectRef) (uint, error) {
	if ref.byID {
		return ref.id, nil
	}
	key := strings.ToLower(ref.name)

	c.cacheMu.RLock()
	if id, ok := c.projectCache[key]; ok {
		c.cacheMu.RUnlock()
		return id, nil
	}
	c.cacheMu.RUnlock()

	projects, err := c.ListProjects(ctx)
	if err != nil {
		return 0, err
	}

	c.cacheMu.Lock()
	if c.projectCache == nil {
		c.projectCache = make(map[string]uint, len(projects))
	}
	for _, p := range projects {
		c.projectCache[strings.ToLower(p.Name)] = p.ID
	}
	id, ok := c.projectCache[key]
	c.cacheMu.Unlock()

	if !ok {
		return 0, fmt.Errorf("keyorix: project %q not found", ref.name)
	}
	return id, nil
}

// resolveEnvironment resolves ref to an environment ID within projectID,
// using (and populating) the Client's per-project cache when ref is given
// by name. An ID ref resolves with no network call.
func (c *Client) resolveEnvironment(ctx context.Context, projectID uint, ref EnvironmentRef) (uint, error) {
	if ref.byID {
		return ref.id, nil
	}
	key := strings.ToLower(ref.name)

	c.cacheMu.RLock()
	if envs, ok := c.envCache[projectID]; ok {
		if id, ok := envs[key]; ok {
			c.cacheMu.RUnlock()
			return id, nil
		}
	}
	c.cacheMu.RUnlock()

	envs, err := c.ListEnvironments(ctx, projectID)
	if err != nil {
		return 0, err
	}

	c.cacheMu.Lock()
	if c.envCache == nil {
		c.envCache = make(map[uint]map[string]uint)
	}
	byName := c.envCache[projectID]
	if byName == nil {
		byName = make(map[string]uint, len(envs))
		c.envCache[projectID] = byName
	}
	for _, e := range envs {
		byName[strings.ToLower(e.Name)] = e.ID
	}
	id, ok := byName[key]
	c.cacheMu.Unlock()

	if !ok {
		return 0, fmt.Errorf("keyorix: environment %q not found in project id=%d", ref.name, projectID)
	}
	return id, nil
}

// getSecretValue fetches the decrypted value for a secret by ID.
func (c *Client) getSecretValue(ctx context.Context, secretID uint) (string, error) {
	endpoint := fmt.Sprintf("%s/api/v1/secrets/%d?include_value=true", c.baseURL, secretID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("keyorix: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", authBearer+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("keyorix: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", &APIError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var result struct {
		Data struct {
			Value string `json:"value"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("keyorix: failed to parse response: %w", err)
	}

	return result.Data.Value, nil
}

// Health checks if the server is reachable and healthy.
func (c *Client) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return fmt.Errorf("keyorix: failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("keyorix: server unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("keyorix: server unhealthy (HTTP %d)", resp.StatusCode)
	}
	return nil
}

// ListProjects returns all projects visible to the authenticated user.
func (c *Client) ListProjects(ctx context.Context) ([]Project, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/v1/projects", nil)
	if err != nil {
		return nil, fmt.Errorf("keyorix: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", authBearer+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keyorix: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var result struct {
		Data struct {
			Projects []Project `json:"projects"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("keyorix: failed to parse response: %w", err)
	}
	return result.Data.Projects, nil
}

// CreateProject creates a new project and seeds default environments.
func (c *Client) CreateProject(ctx context.Context, name, description string) (*Project, error) {
	body, _ := json.Marshal(map[string]string{"name": name, "description": description})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/v1/projects", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("keyorix: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", authBearer+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keyorix: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var result struct {
		Data Project `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("keyorix: failed to parse response: %w", err)
	}
	return &result.Data, nil
}

// ListEnvironments returns all environments for a given project.
func (c *Client) ListEnvironments(ctx context.Context, projectID uint) ([]Environment, error) {
	endpoint := fmt.Sprintf("%s/api/v1/projects/%d/environments", c.baseURL, projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("keyorix: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", authBearer+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keyorix: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, &APIError{StatusCode: resp.StatusCode, Body: string(body)}
	}

	var result struct {
		Data struct {
			Environments []Environment `json:"environments"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("keyorix: failed to parse response: %w", err)
	}
	return result.Data.Environments, nil
}
