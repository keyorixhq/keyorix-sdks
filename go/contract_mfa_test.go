package keyorix

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP is defined over HMAC-SHA1; this is the test-side code generator
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// Contract tests for the MFA login flow and the typed secret-read refusals,
// against a real keyorix-server (see contract_test.go for the harness).
// scripts/contract_bootstrap.py creates the "contract-mfa-go" account (MFA
// enrolled, seed exported as KEYORIX_CONTRACT_MFA_SEED_GO) and the four
// refusal fixtures. MFA stays enforced throughout.

const (
	contractMFAUser     = "contract-mfa-go"
	contractMFAPassword = "ContractMfaUserPassw0rd!"
)

// totpCode is the RFC 6238 code (HMAC-SHA1, 30 s step, 6 digits) the server
// validates. Test-only: the SDK never generates codes.
func totpCode(t *testing.T, seed string, at time.Time) string {
	t.Helper()
	seed = strings.ToUpper(seed)
	if pad := len(seed) % 8; pad != 0 {
		seed += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(seed)
	if err != nil {
		t.Fatalf("decode TOTP seed: %v", err)
	}
	mac := hmac.New(sha1.New, key) //nolint:gosec // see import
	var step [8]byte
	binary.BigEndian.PutUint64(step[:], uint64(at.Unix()/30)) //nolint:gosec // positive timestamp
	mac.Write(step[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1000000)
}

func TestContract_LoginOnMFAAccountReturnsTypedChallengeAndCompletes(t *testing.T) {
	serverURL := contractServerURL(t)
	seed := os.Getenv("KEYORIX_CONTRACT_MFA_SEED_GO")
	if seed == "" {
		t.Fatal("KEYORIX_CONTRACT_MFA_SEED_GO must be set (run scripts/contract_bootstrap.py)")
	}
	ctx := context.Background()

	token, err := Login(ctx, serverURL, contractMFAUser, contractMFAPassword)
	var mfa *MFARequiredError
	if !errors.As(err, &mfa) {
		t.Fatalf("Login on an MFA account: got (%q, %v), want *MFARequiredError", "<token redacted>", err)
	}
	if token != "" {
		t.Fatal("Login returned a token alongside the MFA challenge")
	}
	if mfa.Challenge == "" {
		t.Fatal("MFARequiredError carries no challenge id")
	}
	if got := mfa.Methods(); len(got) != 1 || got[0] != "totp" {
		t.Fatalf("Methods() = %v, want [totp]", got)
	}

	// A wrong code is an AuthError. The challenge may not survive the wrong
	// guess, so the real completion below starts from a fresh login.
	if _, err := VerifyMFA(ctx, serverURL, mfa.Challenge, "000000"); err == nil {
		t.Fatal("VerifyMFA accepted a wrong code")
	} else {
		var authErr *AuthError
		if !errors.As(err, &authErr) {
			t.Fatalf("VerifyMFA with a wrong code: %v, want *AuthError", err)
		}
	}

	_, err = Login(ctx, serverURL, contractMFAUser, contractMFAPassword)
	if !errors.As(err, &mfa) {
		t.Fatalf("second Login: %v, want *MFARequiredError", err)
	}
	session, err := VerifyMFA(ctx, serverURL, mfa.Challenge, totpCode(t, seed, time.Now()))
	if err != nil {
		t.Fatalf("VerifyMFA with a valid TOTP code: %v", err)
	}
	if session == "" {
		t.Fatal("VerifyMFA returned an empty session token")
	}

	// The session authenticates: an account with no roles may see nothing or
	// be refused, but must not be treated as unauthenticated.
	client, err := New(serverURL, session)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := client.ListProjects(ctx); err != nil {
		var authErr *AuthError
		if errors.As(err, &authErr) {
			t.Fatalf("session from VerifyMFA was rejected as unauthenticated: %v", err)
		}
	}
}

// TestContract_SecretReadRefusals reads the four fixture secrets
// (contract_bootstrap.py creates them through the API) as the admin and checks
// each refusal maps to the SDK's typed error with the server's stable code, and
// that the secret value never appears in the error.
func TestContract_SecretReadRefusals(t *testing.T) {
	serverURL := contractServerURL(t)
	client, err := New(serverURL, seedAdminSession(t, serverURL))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	cases := []struct {
		secret string
		code   string
		status int
	}{
		{"contract-refused-suspended", CodeSecretSuspended, 409},
		{"contract-refused-expired", CodeSecretExpired, 409},
		{"contract-refused-max-reads", CodeSecretMaxReadsExhausted, 409},
		{"contract-refused-schedule", CodeSecretAccessOutsideSchedule, 403},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			value, err := client.GetSecretIn(ctx, "default", "development", tc.secret)
			if err == nil {
				t.Fatal("read of a refused secret succeeded")
			}
			if value != "" {
				t.Fatal("a refused read returned a value")
			}
			var api *APIError
			if !errors.As(err, &api) || api.StatusCode != tc.status || api.Code != tc.code {
				t.Fatalf("got %v (APIError %+v), want status %d code %s", err, api, tc.status, tc.code)
			}
			if tc.status == 409 {
				var typed *SecretUnavailableError
				if !errors.As(err, &typed) {
					t.Fatalf("got %T, want *SecretUnavailableError", err)
				}
			} else {
				var typed *ForbiddenError
				if !errors.As(err, &typed) {
					t.Fatalf("got %T, want *ForbiddenError", err)
				}
			}
			if strings.Contains(err.Error(), "must-not-leak") || strings.Contains(api.Body, "must-not-leak") {
				t.Fatal("the secret value leaked into the refusal")
			}
		})
	}
}
