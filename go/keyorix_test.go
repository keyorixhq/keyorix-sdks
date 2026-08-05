package keyorix

import (
	"context"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	c, err := New("https://example.com:8080", "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.baseURL != "https://example.com:8080" {
		t.Errorf("expected baseURL https://example.com:8080, got %s", c.baseURL)
	}
	if c.token != "test-token" {
		t.Errorf("expected token test-token, got %s", c.token)
	}
	if c.httpClient == nil {
		t.Error("expected httpClient to be set")
	}
}

func TestWithTimeout(t *testing.T) {
	c, err := New("https://example.com:8080", "test-token", WithTimeout(5*time.Second))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.httpClient.Timeout != 5*time.Second {
		t.Errorf("expected timeout 5s, got %s", c.httpClient.Timeout)
	}
}

func TestNew_defaults(t *testing.T) {
	c, err := New("https://example.com:8080", "test-token")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.httpClient.Timeout != 30*time.Second {
		t.Errorf("expected default timeout 30s, got %s", c.httpClient.Timeout)
	}
}

func TestNew_allowsLoopbackHTTP(t *testing.T) {
	cases := []string{
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	}
	for _, u := range cases {
		if _, err := New(u, "test-token"); err != nil {
			t.Errorf("New(%q) unexpected error: %v", u, err)
		}
	}
}

func TestNew_rejectsNonLoopbackHTTP(t *testing.T) {
	if _, err := New("http://example.com:8080", "test-token"); err == nil {
		t.Error("expected error for non-loopback http:// URL, got nil")
	}
}

func TestNew_rejectsNonHTTPScheme(t *testing.T) {
	cases := []string{
		"file:///etc/passwd",
		"ftp://example.com",
	}
	for _, u := range cases {
		if _, err := New(u, "test-token"); err == nil {
			t.Errorf("New(%q) expected error, got nil", u)
		}
	}
}

func TestLogin_rejectsNonLoopbackHTTP(t *testing.T) {
	_, err := Login(context.Background(), "http://example.com:8080", "user", "pass")
	if err == nil {
		t.Error("expected error for non-loopback http:// URL, got nil")
	}
}
