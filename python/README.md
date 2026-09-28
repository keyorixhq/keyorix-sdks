# Python SDK

Python client for Keyorix — lightweight on-premise secrets manager.

## Install

    pip install keyorix

Zero dependencies — stdlib only. Or just copy keyorix.py into your project.

## Quick start

    import keyorix
    import os

    # Recommended for apps: a machine identity token, not a user password.
    # Issue one via `keyorix machine token issue <name|id>` (or the web
    # UI's Project -> Machine Identities -> Issue Token), then load it from
    # your app's secret store / env var -- never hardcode it.
    client = keyorix.Client("https://your-server:8443", os.environ["KEYORIX_TOKEN"])

    # A personal access token (PAT) works exactly the same way -- pass it
    # as the token above. Password login (below) is for humans at a
    # terminal, not for baking into an application.
    #
    #   token = keyorix.login("https://your-server:8443", "admin", "your-password")
    #   client = keyorix.Client("https://your-server:8443", token)

    # Scoped to a project + environment -- an environment name is only
    # unique within one project, not globally.
    db_password = client.get_secret_scoped("db-password", "my-project", "production")

    secrets = client.list_secrets_scoped("my-project", "production")
    for s in secrets:
        print(s.name, s.type)

## Environment variables pattern

    import os, keyorix
    client = keyorix.Client(os.environ["KEYORIX_SERVER"], os.environ["KEYORIX_TOKEN"])
    db_password = client.get_secret_scoped("db-password", "my-project", "production")

## API

- keyorix.Client(server_url, token, timeout=30) — `token` is a machine
  identity token, a PAT, or a session token; the server accepts all three
  identically. For an app running unattended, prefer a machine identity
  token over a user's password.
- keyorix.login(server_url, username, password) -> str — authenticates
  with a human's username/password. For interactive use, not for an
  application's long-running credential.
- client.get_secret_scoped(name, project, environment) -> str
- client.list_secrets_scoped(project, environment) -> list
- client.health() -> bool

`project`/`environment` each accept either a name (`str`, resolved to an ID via
the server and cached on the `Client` for its lifetime) or a numeric ID (`int`,
no resolution round trip).

`get_secret_scoped` matches `name` exactly among the secrets in that scope:
zero matches raises `SecretNotFoundError`, more than one raises
`AmbiguousSecretError` (with `.ids` listing every match) — it never guesses.

### Deprecated: `get_secret`/`list_secrets` (environment-only)

Removed in v0.3.0. An environment name is only unique within one project, not
globally, so scoping by environment alone could silently resolve to another
project's same-named secret. These now always raise without contacting the
server — use `get_secret_scoped`/`list_secrets_scoped` instead.

## Exceptions

- KeyorixError — base
- AuthError — authentication failure
- SecretNotFoundError — secret not found
- AmbiguousSecretError — secret name matched more than one secret in scope (`.ids`)

## Requirements

Python 3.8+, zero external dependencies, Keyorix server v0.1.0+

## Compatibility

See [`../COMPATIBILITY.md`](../COMPATIBILITY.md) for the current
known-compatible server versions and per-endpoint coverage — verified by
[`../.github/workflows/contract.yml`](../.github/workflows/contract.yml)
against a real keyorix-server, not asserted by hand.

## License

Apache-2.0 — see the [repository root LICENSE](../LICENSE)
