// Package keyorix provides a Go client for the Keyorix secrets manager API.
//
// Quick start:
//
//	client := keyorix.New("http://your-server:8080", "your-session-token")
//	secret, err := client.GetSecret(ctx, "db-password", "production")
package keyorix

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client is a Keyorix API client.
type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

// Secret represents a secret returned by the API.
type Secret struct {
	ID          uint      `json:"ID"`
	Name        string    `json:"Name"`
	Type        string    `json:"Type"`
	Environment string    `json:"environment_name"`
	Namespace   string    `json:"namespace_name"`
	CreatedAt   time.Time `json:"CreatedAt"`
}

// SecretValue contains the decrypted value of a secret.
type SecretValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
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

// New creates a new Keyorix client.
// serverURL is the base URL of your Keyorix server (e.g. "http://localhost:8080").
// token is a session token obtained via the login endpoint or keyorix CLI.
func New(serverURL, token string, opts ...Option) *Client {
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
	return c
}

// Login authenticates with username and password and returns a session token.
// Use this to obtain a token programmatically instead of hardcoding one.
func Login(ctx context.Context, serverURL, username, password string) (string, error) {
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
		return "", fmt.Errorf("keyorix: login failed (HTTP %d): %s", resp.StatusCode, string(respBody))
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

// GetSecret retrieves the value of a secret by name and environment.
// Returns the plaintext secret value.
func (c *Client) GetSecret(ctx context.Context, name, environment string) (string, error) {
	secrets, err := c.ListSecrets(ctx, environment)
	if err != nil {
		return "", err
	}

	for _, s := range secrets {
		if s.Name == name {
			return c.getSecretValue(ctx, s.ID)
		}
	}

	return "", fmt.Errorf("keyorix: secret %q not found in environment %q", name, environment)
}

// ListSecrets returns all secrets visible to the authenticated user.
// Pass environment as "production", "staging", or "development".
// Pass empty string to list all environments.
func (c *Client) ListSecrets(ctx context.Context, environment string) ([]Secret, error) {
	endpoint := c.baseURL + "/api/v1/secrets"
	if environment != "" {
		endpoint += "?environment=" + url.QueryEscape(environment)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("keyorix: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

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
		return nil, fmt.Errorf("keyorix: server returned %d: %s", resp.StatusCode, string(body))
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

// getSecretValue fetches the decrypted value for a secret by ID.
func (c *Client) getSecretValue(ctx context.Context, secretID uint) (string, error) {
	endpoint := fmt.Sprintf("%s/api/v1/secrets/%d?include_value=true", c.baseURL, secretID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("keyorix: failed to create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("keyorix: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("keyorix: server returned %d: %s", resp.StatusCode, string(body))
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
