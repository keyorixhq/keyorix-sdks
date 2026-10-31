# Java SDK

Java SDK for Keyorix — lightweight on-premise secrets manager.

Zero external dependencies. Java 11+.

## Install

Add to your `pom.xml`:

```xml
<dependency>
    <groupId>com.keyorix</groupId>
    <artifactId>keyorix-sdk</artifactId>
    <version>0.3.0</version>
</dependency>
```

## Quick start

```java
import com.keyorix.Keyorix;
import com.keyorix.KeyorixClient;
import com.keyorix.Secret;
import java.util.List;

// Recommended for apps: a machine identity token, not a user password.
// Issue one via `keyorix machine token issue <name|id>` (or the web UI's
// Project -> Machine Identities -> Issue Token), then load it from your
// app's secret store / env var -- never hardcode it.
KeyorixClient client = Keyorix.newClient("https://your-server:8443", System.getenv("KEYORIX_TOKEN"));

// A personal access token (PAT) works exactly the same way -- pass it as
// the token above. Password login (below) is for humans at a terminal,
// not for baking into an application.
//
//   String token = Keyorix.login("https://your-server:8443", "admin", "your-password");
//   KeyorixClient client = Keyorix.newClient("https://your-server:8443", token);

// Get a secret value, identified entirely by name -- one round trip,
// resolved and authorized server-side. No project/environment-list
// permission required, so this is the shape that works for a machine
// token scoped to exactly one project.
String dbPassword = client.getSecretIn("my-project", "production", "db-password");

// Already have (or want to cache) project/environment IDs instead of
// names? Use the *Scoped methods.
List<Secret> secrets = client.listSecretsScoped("my-project", "production");
```

## Environment variables pattern

```java
String token = System.getenv("KEYORIX_TOKEN");
String server = System.getenv("KEYORIX_SERVER");
KeyorixClient client = Keyorix.newClient(server, token);
String dbPassword = client.getSecretIn("my-project", "production", "db-password");
```

## API

- Keyorix.newClient(serverUrl, token) -> KeyorixClient — `token` is a
  machine identity token, a PAT, or a session token; the server accepts
  all three identically. For an app running unattended, prefer a machine
  identity token over a user's password.
- Keyorix.login(serverUrl, username, password) -> String — authenticates
  with a human's username/password. For interactive use, not for an
  application's long-running credential. On an account with a second factor
  (MFA, the server default) it throws `MFARequiredException` (an
  `AuthException`) carrying `getChallenge()` and `getMethods()` ("totp",
  "webauthn"); complete it with
  `Keyorix.verifyMfa(serverUrl, e.getChallenge(), totpCode)` -> String (TOTP or
  recovery code; a wrong or expired one throws `AuthException`). A passkey
  needs a browser ceremony the SDK does not run.
- client.getSecretIn(project, environment, name) -> String — a single
  server-authorized round trip
  (`GET /api/v1/secrets/value?ref=project/environment/name`). Needs no
  project/environment-list permission, unlike `getSecretScoped`.
- client.getSecretByRef(ref) -> String — same as `getSecretIn`, but takes
  one `"project/environment/name"` string (the name may itself contain
  `/`) instead of three arguments. `getSecretIn` is a thin wrapper around this.
- client.getSecretScoped(name, project, environment) -> String — prefer
  `getSecretIn` unless you already have (or want to cache)
  project/environment IDs: this costs up to two extra round trips to
  resolve a name-based project/environment the first time, and needs
  project/environment-list permission to do so.
- client.listSecretsScoped(project, environment) -> List<Secret> —
  follows every page the server reports.
- client.listDeletedSecrets(projectId) -> List<Secret> — the project's
  soft-deleted secrets; `secret.getPurgeAt()` is the restore deadline (RFC 3339
  UTC; empty on live secrets). Needs server v0.96.0+.
- client.updateSecret(project, environment, name, value) -> Secret — writes
  `value` as a **new version** of the secret `name` (the rotation call) and
  returns its metadata — never the value. Earlier versions are kept and a read
  returns the new value. The name is resolved as for `getSecretScoped`
  (`SecretNotFoundException` / `AmbiguousSecretException`; an ambiguous name
  writes nothing). `value` must not be empty. Needs `secrets.write` on the
  secret. `client.updateSecretById(secretId, value)` is the same call when you
  already have the ID.
  ```java
  client.updateSecret("my-project", "production", "db-password", newPassword);
  ```
  The value is never put in an exception's message, and an echo of it in the
  server's response is replaced with `[REDACTED]` in `getResponseBody()`. Under
  heavy concurrent writes to the same secret the server answers 409; that is a
  plain `KeyorixException` (`getStatusCode() == 409`): retry.
- client.deleteSecret(project, environment, name) -> String — soft-deletes the
  secret: it stops being readable at once but can be restored until the
  returned purge date (RFC 3339 UTC; `listDeletedSecrets` lists it with the
  same date). The date is `""` only if the server sent none (the delete still
  succeeded). Deleting twice throws `NotFoundException` the second time. Needs
  `secrets.delete` on the secret. `client.deleteSecretById(secretId)` is the
  by-ID form. The server asks for no step-up or MFA for a delete; the SDK adds
  none. Both calls throw `ForbiddenException` (403) when the token may not
  write/delete that secret and `NotFoundException` (404) when no live secret
  has that ID. The purge date needs server v0.96.0+; on an older server the
  delete works and the date is `""`.
- client.health() -> boolean

`project`/`environment` each have two overloads: by name (`String`, resolved to
an ID via the server and cached on the `KeyorixClient` for its lifetime) or by
numeric ID (`long`, no resolution round trip).

`getSecretScoped` matches `name` exactly among the secrets in that scope: zero
matches throws `SecretNotFoundException`, more than one throws
`AmbiguousSecretException` (with `getIds()` listing every match) — it never
guesses.

### Deprecated: `getSecret`/`listSecrets` (environment-only)

Removed since v0.3.0. An environment name is only unique within one project,
not globally, so scoping by environment alone could silently resolve to
another project's same-named secret. These now always throw without
contacting the server — use `getSecretScoped`/`listSecretsScoped` instead.

## Exceptions

- KeyorixException — base
- AuthException — authentication failure (HTTP 401)
- ForbiddenException — token authenticated but not permitted (HTTP 403)
- NotFoundException — resource not found (HTTP 404), which is what
  `getSecretIn`/`getSecretByRef` throw for a missing secret, project or environment
- SecretNotFoundException — thrown by `getSecretScoped` when no secret in the scope has that name
- AmbiguousSecretException — secret name matched more than one secret in scope (`getIds()`)

## Requirements

Java 11+, zero external dependencies, Keyorix server v0.1.0+

## Compatibility

See [`../COMPATIBILITY.md`](../COMPATIBILITY.md) for the current
known-compatible server versions and per-endpoint coverage — verified by
[`../.github/workflows/contract.yml`](../.github/workflows/contract.yml)
against a real keyorix-server, not asserted by hand. Note: this SDK does not
yet implement `createProject` (unlike the other three languages here).

## License

Apache-2.0 — see the [repository root LICENSE](../LICENSE)
