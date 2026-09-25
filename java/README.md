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

String token = Keyorix.login("https://your-server:8443", "admin", "password");
KeyorixClient client = Keyorix.newClient("https://your-server:8443", token);

// Scoped to a project + environment -- an environment name is only unique
// within one project, not globally.
String dbPassword = client.getSecretScoped("db-password", "my-project", "production");

List<Secret> secrets = client.listSecretsScoped("my-project", "production");
```

## Environment variables pattern

```java
String token = System.getenv("KEYORIX_TOKEN");
String server = System.getenv("KEYORIX_SERVER");
KeyorixClient client = Keyorix.newClient(server, token);
String dbPassword = client.getSecretScoped("db-password", "my-project", "production");
```

## API

- Keyorix.login(serverUrl, username, password) -> String
- Keyorix.newClient(serverUrl, token) -> KeyorixClient
- client.getSecretScoped(name, project, environment) -> String
- client.listSecretsScoped(project, environment) -> List<Secret>
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
