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

    // Get a secret value — scoped to a project + environment, since an
    // environment name is only unique within one project, not globally.
    dbPassword, err := client.GetSecretScoped(ctx, "db-password",
        keyorix.ProjectByName("my-project"), keyorix.EnvironmentByName("production"))
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("DB password:", dbPassword)

    // List all secrets in a project's environment
    secrets, err := client.ListSecretsScoped(ctx,
        keyorix.ProjectByName("my-project"), keyorix.EnvironmentByName("production"))
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

### `client.GetSecretScoped(ctx, name string, project ProjectRef, environment EnvironmentRef) (string, error)`
Returns the plaintext value of a secret by name, within one project's environment.
`name` is matched exactly among the secrets in that scope: zero matches returns
`*SecretNotFoundError`, more than one returns `*AmbiguousSecretError` (listing every
matching ID) — it never guesses.

### `client.ListSecretsScoped(ctx, project ProjectRef, environment EnvironmentRef) ([]Secret, error)`
Returns every secret within one project's environment.

`project`/`environment` are each either `keyorix.ProjectByName("name")` /
`keyorix.EnvironmentByName("name")` (resolved to an ID via the server and cached on
the `Client` for its lifetime) or `keyorix.ProjectByID(id)` / `keyorix.EnvironmentByID(id)`
(no resolution round trip).

### `client.Health(ctx) error`
Checks if the server is reachable. Returns nil if healthy.

### Deprecated: `client.GetSecret`/`client.ListSecrets` (environment-only)
Removed in v0.3.0. An environment name is only unique within one project, not
globally, so scoping by environment alone could silently resolve to another
project's same-named secret. These now always return an error without contacting
the server — use `GetSecretScoped`/`ListSecretsScoped` instead.

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

## Compatibility

See [`../COMPATIBILITY.md`](../COMPATIBILITY.md) for the current
known-compatible server versions and per-endpoint coverage — verified by
[`../.github/workflows/contract.yml`](../.github/workflows/contract.yml)
against a real keyorix-server, not asserted by hand.

## License

Apache-2.0 — see the [repository root LICENSE](../LICENSE)
