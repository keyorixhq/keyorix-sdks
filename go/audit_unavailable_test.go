package keyorix

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// The real body the server sends when a mutation's audit row cannot be recorded:
// 503 with the stable code audit_unavailable (server/http/handlers/audit_unavailable.go).
const auditUnavailableBody = `{"success":false,"code":503,"error":"audit_unavailable","message":"The change was refused because the audit log is unavailable. Nothing was changed; retry later."}`

func TestCreateSecret_AuditUnavailableIsTyped(t *testing.T) {
	srv := createSecretServer(t, http.StatusServiceUnavailable, auditUnavailableBody, nil)
	defer srv.Close()
	c, _ := New(srv.URL, "test-token")

	_, err := c.CreateSecret(context.Background(), ProjectByID(10), EnvironmentByID(101), "n", createSecretValue)

	var ae *AuditUnavailableError
	if !errors.As(err, &ae) {
		t.Fatalf("err = %v (%T), want *AuditUnavailableError", err, err)
	}
	if ae.StatusCode != http.StatusServiceUnavailable || ae.Code != CodeAuditUnavailable {
		t.Errorf("status/code = %d/%q", ae.StatusCode, ae.Code)
	}
	var api *APIError
	if !errors.As(err, &api) {
		t.Errorf("AuditUnavailableError must unwrap to *APIError")
	}
	if strings.Contains(err.Error(), createSecretValue) {
		t.Errorf("error leaks the secret value: %v", err)
	}
}

// A 503 that is not the audit refusal (a load balancer, a storage outage) must stay
// a plain *APIError, not be mistaken for a refused-and-unchanged mutation.
func TestCreateSecret_Other503StaysGeneric(t *testing.T) {
	srv := createSecretServer(t, http.StatusServiceUnavailable, `{"success":false,"code":503,"error":"storage_unavailable","message":"x"}`, nil)
	defer srv.Close()
	c, _ := New(srv.URL, "test-token")

	_, err := c.CreateSecret(context.Background(), ProjectByID(10), EnvironmentByID(101), "n", createSecretValue)

	var ae *AuditUnavailableError
	if errors.As(err, &ae) {
		t.Fatalf("storage_unavailable must not be typed as AuditUnavailableError: %v", err)
	}
	var api *APIError
	if !errors.As(err, &api) || api.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("err = %v, want *APIError 503", err)
	}
}
