//go:build integration

package keyorix_test

import (
	"context"
	"fmt"
	"os"
	"testing"

	keyorix "github.com/keyorixhq/keyorix-go"
)

func TestIntegration_Login(t *testing.T) {
	server := os.Getenv("KEYORIX_SERVER")
	if server == "" {
		server = "http://localhost:8080"
	}

	ctx := context.Background()
	token, err := keyorix.Login(ctx, server, "admin", "Admin123!")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
	fmt.Printf("✅ Login OK, token: %s...\n", token[:8])

	client := keyorix.New(server, token)

	// Health check
	if err := client.Health(ctx); err != nil {
		t.Fatalf("Health check failed: %v", err)
	}
	fmt.Println("✅ Health OK")

	// List secrets
	secrets, err := client.ListSecrets(ctx, "production")
	if err != nil {
		t.Fatalf("ListSecrets failed: %v", err)
	}
	fmt.Printf("✅ ListSecrets OK — %d secrets in production\n", len(secrets))
	for _, s := range secrets {
		fmt.Printf("   - %s (%s)\n", s.Name, s.Type)
	}
}
