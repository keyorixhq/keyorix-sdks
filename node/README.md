# Node.js SDK

Node.js SDK for Keyorix — lightweight on-premise secrets manager.

Zero external dependencies. Uses Node.js built-in http/https modules.

## Install

    npm install @keyorixhq/sdk

## Quick start

    const keyorix = require('@keyorixhq/sdk');

    const token = await keyorix.login('https://your-server:8443', 'admin', 'password');
    const client = new keyorix.Client('https://your-server:8443', token);

    const dbPassword = await client.getSecret('db-password', 'production');

    const secrets = await client.listSecrets('production');
    secrets.forEach(s => console.log(s.name, s.type));

## Environment variables pattern

    const client = new keyorix.Client(
      process.env.KEYORIX_SERVER,
      process.env.KEYORIX_TOKEN
    );
    const dbPassword = await client.getSecret('db-password', 'production');

## API

- keyorix.login(serverUrl, username, password) -> Promise<string>
- new keyorix.Client(serverUrl, token, opts?)
- client.getSecret(name, environment?) -> Promise<string> — matches `environment` by
  name across every project you can read; use `getSecretInProject` if the same
  environment name exists in more than one project
- client.listSecrets(environment?) -> Promise<Secret[]> — same caveat as above; see
  `listSecretsInProject` to scope to one specific project
- client.listSecretsInProject(projectId, environment?) -> Promise<Secret[]> — resolves
  `environment` to its numeric ID within `projectId` before querying
- client.getSecretInProject(projectId, name, environment?) -> Promise<string>
- client.listProjects() -> Promise<Project[]>
- client.listEnvironments(projectId) -> Promise<Environment[]>
- client.health() -> Promise<boolean>

## Errors

- KeyorixError — base
- AuthError — authentication failure
- SecretNotFoundError — secret not found

## Requirements

Node.js 18+, zero external dependencies, Keyorix server v0.1.0+

## License

Apache-2.0 — see the [repository root LICENSE](../LICENSE)
