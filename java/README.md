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
- client.createProject(name, description) -> Project — creates a project
  (`POST /api/v1/projects`) and seeds its default environments; `description`
  may be `null`. Same behaviour as `CreateProject`/`createProject`/`create_project`
  in the Go, Node and Python SDKs.
- client.createSecret(project, environment, name, value) -> Secret — creates a
  secret (`POST /api/v1/secrets`) and returns its metadata, never the value. The
  overload `createSecret(project, environment, name, value, type, description)`
  sets the type (default `generic`) and a free-text note (`null` for none).
  Needs `secrets.write` in the scope. A name already taken in the scope throws
  `SecretAlreadyExistsException`. The value never appears in an exception
  message, and any echo of it by the server is stripped from `getResponseBody()`.
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
- SecretAlreadyExistsException — thrown by `createSecret` when the name is already taken in the scope (HTTP 409)
- AmbiguousSecretException — secret name matched more than one secret in scope (`getIds()`)

## Requirements

Java 11+, zero external dependencies, Keyorix server v0.1.0+

## Compatibility

See [`../COMPATIBILITY.md`](../COMPATIBILITY.md) for the current
known-compatible server versions and per-endpoint coverage — verified by
[`../.github/workflows/contract.yml`](../.github/workflows/contract.yml)
against a real keyorix-server, not asserted by hand.

## License

Apache-2.0 — see the [repository root LICENSE](../LICENSE)
