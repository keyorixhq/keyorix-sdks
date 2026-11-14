package keyorix

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP is defined over HMAC-SHA1; this is the test-side code generator
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// totpCode computes the RFC 6238 code (HMAC-SHA1, 6 digits, 30 s step) for a base32
// secret at the given time, so the test can enrol and complete TOTP without a
// dependency.
func totpCode(t *testing.T, base32Secret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimRight(base32Secret, "=")))
	if err != nil {
		t.Fatalf("decode TOTP secret: %v", err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30)) //nolint:gosec // a post-1970 time is never negative
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", n%1_000_000)
}

// TestContract_MFALoginAndCompletion drives the whole second-factor path against a
// real server: a separate user (the shared contract-admin must stay MFA-free for
// the other suites) enrols TOTP, then Login returns *MFARequiredError and
// VerifyMFA turns the challenge plus a code into a working session.
func TestContract_MFALoginAndCompletion(t *testing.T) {
	serverURL := contractServerURL(t)
	adminToken := seedAdminSession(t, serverURL)

	username := fmt.Sprintf("contract-mfa-%d", time.Now().UnixNano())
	const password = "ContractMfaPassw0rd!"
	authedJSON(t, "POST", serverURL+"/api/v1/users", adminToken, map[string]any{
		"username":     username,
		"email":        username + "@example.com",
		"display_name": "Contract MFA user",
		"password":     password,
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Before enrolment a plain login returns a session.
	token, err := Login(ctx, serverURL, username, password)
	if err != nil {
		t.Fatalf("Login before MFA enrolment: %v", err)
	}

	var enrol struct {
		Secret string `json:"secret"`
	}
	authedJSON(t, "POST", serverURL+"/api/v1/auth/mfa/enroll", token, nil, &enrol)
	if enrol.Secret == "" {
		t.Fatal("enroll returned no TOTP secret")
	}
	authedJSON(t, "POST", serverURL+"/api/v1/auth/mfa/activate", token, map[string]string{
		"code":     totpCode(t, enrol.Secret, time.Now()),
		"password": password,
	}, nil)

	// After enrolment Login must return the typed error, not "no token in login response".
	loginChallenge := func() *MFARequiredError {
		t.Helper()
		tok, err := Login(ctx, serverURL, username, password)
		var mfa *MFARequiredError
		if !errors.As(err, &mfa) {
			t.Fatalf("Login on an MFA account: token=%q err=%v (%T), want *MFARequiredError", tok, err, err)
		}
		return mfa
	}

	mfa := loginChallenge()
	if mfa.Challenge == "" || !mfa.TOTPAvailable {
		t.Fatalf("challenge = %+v, want a challenge id with TOTP available", mfa)
	}
	if got := mfa.Methods(); len(got) == 0 || got[0] != "totp" {
		t.Errorf("Methods() = %v, want totp first", got)
	}

	// A wrong code is a typed auth failure, not a session.
	if tok, err := VerifyMFA(ctx, serverURL, mfa.Challenge, "000000"); err == nil || tok != "" {
		t.Fatalf("VerifyMFA with a wrong code: token=%q err=%v, want an error", tok, err)
	} else {
		var ae *AuthError
		if !errors.As(err, &ae) {
			t.Errorf("wrong code: err = %v (%T), want *AuthError", err, err)
		}
	}

	// The correct code completes the login with a session that really works. A fresh
	// challenge is used, and the next time step: the activation consumed this one.
	mfa = loginChallenge()
	sessionToken, err := VerifyMFA(ctx, serverURL, mfa.Challenge, totpCode(t, enrol.Secret, time.Now().Add(30*time.Second)))
	if err != nil {
		t.Fatalf("VerifyMFA with a correct code: %v", err)
	}
	if sessionToken == "" {
		t.Fatal("VerifyMFA returned an empty session token")
	}
	c, err := New(serverURL, sessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Health(ctx); err != nil {
		t.Fatalf("Health with the MFA session: %v", err)
	}
	if _, err := c.ListProjects(ctx); err != nil {
		t.Fatalf("ListProjects with the MFA session: %v", err)
	}
}
