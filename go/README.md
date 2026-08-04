# keyorix-go

Official Go SDK for [Keyorix](https://keyorix.com) — lightweight on-premise secrets manager.

## Install

```bash
go get github.com/keyorixhq/keyorix-go
```

## Quick start

```go
package main

import (
    "context"
    "fmt"
    "log"

    keyorix "github.com/keyorixhq/keyorix-go"
)

func main() {
    ctx := context.Background()

    // Option 1: use a token directly
    client := keyorix.New("http://your-server:8080", "your-session-token")

    // Option 2: log in with username/password
    token, err := keyorix.Login(ctx, "http://your-server:8080", "admin", "your-password")
    if err != nil {
        log.Fatal(err)
    }
    client = keyorix.New("http://your-server:8080", token)

    // Get a secret value
    dbPassword, err := client.GetSecret(ctx, "db-password", "production")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("DB password:", dbPassword)

    // List all secrets in an environment
    secrets, err := client.ListSecrets(ctx, "production")
    if err != nil {
        log.Fatal(err)
    }
    for _, s := range secrets {
        fmt.Printf("  %s (%s)\n", s.Name, s.Type)
    }
}
```

## API

### `keyorix.New(serverURL, token string, opts ...Option) *Client`
Creates a new client. Get a token via `keyorix.Login()` or from the Keyorix CLI:
```bash
keyorix connect http://your-server --username admin --password your-password
# Token is saved in ~/.keyorix/cli.yaml
```

### `keyorix.Login(ctx, serverURL, username, password string) (string, error)`
Authenticates and returns a session token. Use this to avoid hardcoding tokens.

### `client.GetSecret(ctx, name, environment string) (string, error)`
Returns the plaintext value of a secret by name and environment.

### `client.ListSecrets(ctx, environment string) ([]Secret, error)`
Returns all secrets visible to the authenticated user. Pass empty string for all environments.

### `client.Health(ctx) error`
Checks if the server is reachable. Returns nil if healthy.

### Options
```go
keyorix.New(url, token,
    keyorix.WithTimeout(10 * time.Second),
    keyorix.WithHTTPClient(myHTTPClient),
)
```

## Environment variables pattern

```go
token := os.Getenv("KEYORIX_TOKEN")
server := os.Getenv("KEYORIX_SERVER")
if token == "" || server == "" {
    log.Fatal("KEYORIX_TOKEN and KEYORIX_SERVER must be set")
}
client := keyorix.New(server, token)
```

## Requirements

- Go 1.21+
- Keyorix server v0.1.0+

## License

AGPL-3.0 — see [LICENSE](LICENSE)
