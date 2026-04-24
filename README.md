# keyorix-node

Node.js SDK for Keyorix — lightweight on-premise secrets manager.

Zero external dependencies. Uses Node.js built-in http/https modules.

## Install

    npm install keyorix

## Quick start

    const keyorix = require('keyorix');

    const token = await keyorix.login('http://your-server:8080', 'admin', 'password');
    const client = new keyorix.Client('http://your-server:8080', token);

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
- client.getSecret(name, environment?) -> Promise<string>
- client.listSecrets(environment?) -> Promise<Secret[]>
- client.health() -> Promise<boolean>

## Errors

- KeyorixError — base
- AuthError — authentication failure
- SecretNotFoundError — secret not found

## Requirements

Node.js 18+, zero external dependencies, Keyorix server v0.1.0+

## License

AGPL-3.0
