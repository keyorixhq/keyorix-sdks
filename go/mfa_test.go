package keyorix

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func TestLogin_MFAChallengeIsTyped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{"mfa_required":true,"mfa_challenge":"chal-1","totp_available":true,"webauthn_available":true}}`))
	}))
	defer srv.Close()

	token, err := Login(context.Background(), srv.URL, "u", "p")
	var mfa *MFARequiredError
	if !errors.As(err, &mfa) {
		t.Fatalf("got %v, want *MFARequiredError", err)
	}
	if token != "" || mfa.Challenge != "chal-1" || !mfa.TOTPAvailable || !mfa.WebAuthnAvailable {
		t.Fatalf("unexpected %+v / token %q", mfa, token)
	}
	if got := mfa.Methods(); !reflect.DeepEqual(got, []string{"totp", "webauthn"}) {
		t.Fatalf("Methods() = %v", got)
	}
}

func TestLogin_NoTokenNoChallengeIsStillGeneric(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer srv.Close()

	_, err := Login(context.Background(), srv.URL, "u", "p")
	var mfa *MFARequiredError
	if err == nil || errors.As(err, &mfa) {
		t.Fatalf("got %v, want a generic no-token error", err)
	}
}

func TestVerifyMFA_ReturnsSessionAndSendsChallengeAndCode(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/mfa/verify" || r.Method != http.MethodPost {
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		_, _ = w.Write([]byte(`{"data":{"token":"sess"}}`))
	}))
	defer srv.Close()

	token, err := VerifyMFA(context.Background(), srv.URL, "chal-1", "123456")
	if err != nil || token != "sess" {
		t.Fatalf("got (%q, %v)", token, err)
	}
	if got["mfa_challenge"] != "chal-1" || got["code"] != "123456" {
		t.Fatalf("request body = %v", got)
	}
}

func TestVerifyMFA_WrongCodeIsAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"Unauthorized"}`))
	}))
	defer srv.Close()

	_, err := VerifyMFA(context.Background(), srv.URL, "c", "000000")
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("got %v, want *AuthError", err)
	}
}

func TestVerifyMFA_RejectsNonLoopbackHTTP(t *testing.T) {
	if _, err := VerifyMFA(context.Background(), "http://example.com", "c", "1"); err == nil {
		t.Fatal("expected a URL validation error")
	}
}
