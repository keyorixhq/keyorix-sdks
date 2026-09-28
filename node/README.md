# Node.js SDK

Node.js SDK for Keyorix — lightweight on-premise secrets manager.

Zero external dependencies. Uses Node.js built-in http/https modules.

## Install

    npm install @keyorixhq/sdk

## Quick start

    const keyorix = require('@keyorixhq/sdk');

    const token = await keyorix.login('https://your-server:8443', 'admin', 'password');
    const client = new keyorix.Client('https://your-server:8443', token);

    // Scoped to a project + environment -- an environment name is only
    // unique within one project, not globally.
    const dbPassword = await client.getSecretScoped('db-password', 'my-project', 'production');

    const secrets = await client.listSecretsScoped('my-project', 'production');
    secrets.forEach(s => console.log(s.name, s.type));

## Environment variables pattern

    const client = new keyorix.Client(
      process.env.KEYORIX_SERVER,
      process.env.KEYORIX_TOKEN
    );
    const dbPassword = await client.getSecretScoped('db-password', 'my-project', 'production');

## API

- keyorix.login(serverUrl, username, password) -> Promise<string>
- new keyorix.Client(serverUrl, token, opts?)
- client.getSecretScoped(name, project, environment) -> Promise<string>
- client.listSecretsScoped(project, environment) -> Promise<Secret[]>
- client.health() -> Promise<boolean>

`project`/`environment` each accept either a name (`string`, resolved to an ID
via the server and cached on the `Client` for its lifetime) or a numeric ID
(`number`, no resolution round trip).

`getSecretScoped` matches `name` exactly among the secrets in that scope: zero
matches throws `SecretNotFoundError`, more than one throws
`AmbiguousSecretError` (with `.ids` listing every match) — it never guesses.

### Deprecated: `getSecret`/`listSecrets` (environment-only)

Removed in v0.3.0. An environment name is only unique within one project, not
globally, so scoping by environment alone could silently resolve to another
project's same-named secret. These now always throw without contacting the
server — use `getSecretScoped`/`listSecretsScoped` instead.

## Errors

- KeyorixError — base
- AuthError — authentication failure
- SecretNotFoundError — secret not found
- AmbiguousSecretError — secret name matched more than one secret in scope (`.ids`)

## Requirements

Node.js 18+, zero external dependencies, Keyorix server v0.1.0+

## Compatibility

See [`../COMPATIBILITY.md`](../COMPATIBILITY.md) for the current
known-compatible server versions and per-endpoint coverage — verified by
[`../.github/workflows/contract.yml`](../.github/workflows/contract.yml)
against a real keyorix-server, not asserted by hand.

## License

Apache-2.0 — see the [repository root LICENSE](../LICENSE)
