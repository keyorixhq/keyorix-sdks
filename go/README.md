# Go SDK

Official Go SDK for [Keyorix](https://keyorix.com) — lightweight on-premise secrets manager.

## Install

```bash
go get github.com/keyorixhq/keyorix-sdks/go
```

## Quick start

```go
package main

import (
    "context"
    "fmt"
    "log"

    keyorix "github.com/keyorixhq/keyorix-sdks/go"
)

func main() {
    ctx := context.Background()

    // Option 1: use a token directly
    client, err := keyorix.New("https://your-server:8443", "your-session-token")
    if err != nil {
        log.Fatal(err)
    }

    // Option 2: log in with username/password
    token, err := keyorix.Login(ctx, "https://your-server:8443", "admin", "your-password")
    if err != nil {
        log.Fatal(err)
    }
    client, err = keyorix.New("https://your-server:8443", token)
    if err != nil {
        log.Fatal(err)
    }

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

### `keyorix.New(serverURL, token string, opts ...Option) (*Client, error)`
Creates a new client. `serverURL` must use `https://` (`http://` is only accepted
for localhost/loopback). Get a token via `keyorix.Login()` or from the Keyorix CLI:
```bash
keyorix connect https://your-server --username admin --password your-password
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
client, err := keyorix.New(url, token,
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
client, err := keyorix.New(server, token)
if err != nil {
    log.Fatal(err)
}
```

## Requirements

- Go 1.21+
- Keyorix server v0.1.0+

## License

Apache-2.0 — see the [repository root LICENSE](../LICENSE)
