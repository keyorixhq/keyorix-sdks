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
    "os"

    keyorix "github.com/keyorixhq/keyorix-sdks/go"
)

func main() {
    ctx := context.Background()

    // Recommended for apps: a machine identity token, not a user password.
    // Issue one via `keyorix machine token issue <name|id>` (or the web
    // UI's Project -> Machine Identities -> Issue Token), then load it
    // from your app's secret store / env var -- never hardcode it.
    client, err := keyorix.New("https://your-server:8443", os.Getenv("KEYORIX_TOKEN"))
    if err != nil {
        log.Fatal(err)
    }

    // A personal access token (PAT) works exactly the same way -- pass it
    // as the token to keyorix.New. Password login (below) is for humans at
    // a terminal, not for baking into an application.
    //
    //   token, err := keyorix.Login(ctx, "https://your-server:8443", "admin", "your-password")
    //   client, err = keyorix.New("https://your-server:8443", token)

    // Get a secret value, identified entirely by name — one round trip,
    // resolved and authorized server-side. No project/environment-list
    // permission required, so this is the shape that works for a machine
    // token scoped to exactly one project.
    dbPassword, err := client.GetSecretIn(ctx, "my-project", "production", "db-password")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println("DB password:", dbPassword)

    // Already have (or want to cache) project/environment IDs instead of
    // names? Use the *Scoped methods — ProjectByID/EnvironmentByID resolve
    // with no network call at all.
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
for localhost/loopback). `token` can be a machine identity token, a personal
access token (PAT), or a session token — the server accepts all three
identically. For an app running unattended, issue a machine identity token
(`keyorix machine token issue <name|id>`, or the web UI's Project -> Machine
Identities -> Issue Token) and load it from your app's own secret store or
environment — that's the recommended shape, not a user's password.

### `keyorix.Login(ctx, serverURL, username, password string) (string, error)`
Authenticates with a human's username/password and returns a session token.
For interactive use (a developer at a terminal, the CLI's own login flow) —
not for an application's long-running credential.

### `client.GetSecretIn(ctx, project, environment, name string) (string, error)`
Returns the plaintext value of secret `name` in `project`/`environment`
(all by name), via a single server-authorized round trip
(`GET /api/v1/secrets/value?ref=project/environment/name`). Needs no
project/environment-list permission, unlike `GetSecretScoped`.

### `client.GetSecretByRef(ctx, ref string) (string, error)`
Same as `GetSecretIn`, but takes one `"project/environment/name"` string (the
name may itself contain `/`) instead of three arguments — `GetSecretIn` is a
thin wrapper around this.

### `client.GetSecretScoped(ctx, name string, project ProjectRef, environment EnvironmentRef) (string, error)`
Returns the plaintext value of a secret by name, within one project's environment.
`name` is matched exactly among the secrets in that scope: zero matches returns
`*SecretNotFoundError`, more than one returns `*AmbiguousSecretError` (listing every
matching ID) — it never guesses. Prefer `GetSecretIn` unless you already have (or
want to cache) project/environment IDs: `GetSecretScoped` costs up to two extra
round trips to resolve a name-based `ProjectRef`/`EnvironmentRef` the first time,
and needs project/environment-list permission to do so.

### `client.ListSecretsScoped(ctx, project ProjectRef, environment EnvironmentRef) ([]Secret, error)`
Returns every secret within one project's environment, following every page
the server reports.

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
