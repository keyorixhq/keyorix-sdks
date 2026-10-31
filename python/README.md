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

    # Get a secret value, identified entirely by name -- one round trip,
    # resolved and authorized server-side. No project/environment-list
    # permission required, so this is the shape that works for a machine
    # token scoped to exactly one project.
    db_password = client.get_secret_in("my-project", "production", "db-password")

    # Already have (or want to cache) project/environment IDs instead of
    # names? Use the *_scoped methods.
    secrets = client.list_secrets_scoped("my-project", "production")
    for s in secrets:
        print(s.name, s.type)

## Environment variables pattern

    import os, keyorix
    client = keyorix.Client(os.environ["KEYORIX_SERVER"], os.environ["KEYORIX_TOKEN"])
    db_password = client.get_secret_in("my-project", "production", "db-password")

## API

- keyorix.Client(server_url, token, timeout=30) — `token` is a machine
  identity token, a PAT, or a session token; the server accepts all three
  identically. For an app running unattended, prefer a machine identity
  token over a user's password.
- keyorix.login(server_url, username, password) -> str — authenticates
  with a human's username/password. For interactive use, not for an
  application's long-running credential. On an account with a second factor
  (MFA, the server default) it raises `MFARequiredError` (an `AuthError`)
  carrying `.challenge` and `.methods` (`"totp"`, `"webauthn"`); complete it
  with `keyorix.verify_mfa(server_url, e.challenge, totp_code) -> str` (TOTP or
  recovery code; a wrong or expired one raises `AuthError`). A passkey needs a
  browser ceremony the SDK does not run.
- client.get_secret_in(project, environment, name) -> str — a single
  server-authorized round trip
  (`GET /api/v1/secrets/value?ref=project/environment/name`). Needs no
  project/environment-list permission, unlike `get_secret_scoped`.
- client.get_secret_by_ref(ref) -> str — same as `get_secret_in`, but takes
  one `"project/environment/name"` string (the name may itself contain `/`)
  instead of three arguments. `get_secret_in` is a thin wrapper around this.
- client.get_secret_scoped(name, project, environment) -> str — prefer
  `get_secret_in` unless you already have (or want to cache)
  project/environment IDs: this costs up to two extra round trips to
  resolve a name-based project/environment the first time, and needs
  project/environment-list permission to do so.
- client.list_secrets_scoped(project, environment) -> list — follows every
  page the server reports.
- client.list_deleted_secrets(project) -> list — the project's soft-deleted
  secrets; `purge_at` is the restore deadline (RFC 3339 UTC; empty on live
  secrets). Needs server v0.96.0+.
- client.update_secret(project, environment, name, value) -> Secret — writes
  `value` as a **new version** of the secret `name` (the rotation call) and
  returns its metadata — never the value. Earlier versions are kept and a read
  returns the new value. The name is resolved as for `get_secret_scoped`
  (`SecretNotFoundError` / `AmbiguousSecretError`; an ambiguous name writes
  nothing). `value` must be a non-empty `str`. Needs `secrets.write` on the
  secret. `client.update_secret_by_id(secret_id, value)` is the same call when
  you already have the ID (a positive `int`).
  ```python
  client.update_secret("my-project", "production", "db-password", new_password)
  ```
  The value is never put in an exception's message, and an echo of it in the
  server's response is replaced with `[REDACTED]` in `e.response_body`. Under
  heavy concurrent writes to the same secret the server answers 409; that is a
  plain `KeyorixError` (`e.status_code == 409`): retry.
- client.delete_secret(project, environment, name) -> Optional[str] —
  soft-deletes the secret: it stops being readable at once but can be restored
  until the returned purge date (RFC 3339 UTC; `list_deleted_secrets` lists it
  with the same date). `None` only if the server sent none (the delete still
  succeeded). Deleting twice raises `NotFoundError` the second time. Needs
  `secrets.delete` on the secret. `client.delete_secret_by_id(secret_id)` is the
  by-ID form. The server asks for no step-up or MFA for a delete; the SDK adds
  none. Both calls raise `ForbiddenError` (403) when the token may not
  write/delete that secret and `NotFoundError` (404) when no live secret has
  that ID. The purge date needs server v0.96.0+; on an older server the delete
  works and the result is `None`.
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
- AuthError — authentication failure (HTTP 401)
- MFARequiredError — `login()` got an MFA challenge (an `AuthError`; `.challenge`, `.methods`)
- ForbiddenError — token authenticated but not permitted (HTTP 403)
- NotFoundError — resource not found (HTTP 404), which is what
  `get_secret_in`/`get_secret_by_ref` raise for a missing secret, project or environment
- SecretNotFoundError — raised by `get_secret_scoped` when no secret in the scope has that name
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
