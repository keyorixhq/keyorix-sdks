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
  application's long-running credential.
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
- AuthException — authentication failure
- SecretNotFoundException — secret not found
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
